;;; org-linear.el --- Org-mode integration for Linear.app  -*- lexical-binding: t; -*-

;;; Commentary:
;; End-to-end Linear <--> Org workflow:
;; - OAuth (authorize, local callback, token exchange)
;; - Insert team issues into Org as headings
;; - Open issue URL from heading
;; - Refresh issues under a parent heading
;; - Create a Linear issue from current Org subtree (writes PROPERTIES, renames heading)
;;
;; Quick start:
;;   (require 'org-linear)
;;   M-x org-linear-oauth-callback-server     ;; http://localhost:8080/callback
;;   M-x org-linear-oauth-authorize
;;   M-x org-linear-insert-issues-for-team
;;   (Optional) Turn on minor mode in Org buffers for keybindings:
;;     (add-hook 'org-mode-hook #'org-linear-mode)

;;; Code:

(require 'json)
(require 'request)
(require 'org)
(require 'cl-lib)        ;; cl-function, cl-reduce
(require 'subr-x)        ;; string-empty-p, string-trim
(require 'simple-httpd)  ;; defservlet / httpd-start
(require 'auth-source)   ;; secure authentication

;; Note: Using request.el struct accessors:
;; - request-response-status-code (public accessor)
;; - request-response--buffer (internal accessor)

(defgroup org-linear nil
  "Integration with Linear."
  :group 'tools)

(defgroup org-linear-auth nil
  "Authentication settings for Linear integration."
  :group 'org-linear)

;;;; Configuration

(defcustom org-linear-graphql-endpoint "https://api.linear.app/graphql"
  "Linear GraphQL endpoint."
  :type 'string
  :group 'org-linear)

(defcustom org-linear-api-key ""
  "API key (OAuth access token) for accessing the Linear API."
  :type 'string
  :group 'org-linear)

(defcustom org-linear-client-id ""
  "Client ID for Linear OAuth2 application."
  :type 'string
  :group 'org-linear)

(defcustom org-linear-client-secret ""
  "Client secret for Linear OAuth2 application."
  :type 'string
  :group 'org-linear)

(defcustom org-linear-oauth-redirect-uri "http://localhost:8080/callback"
  "Redirect URI for Linear OAuth2 authentication (must match app settings)."
  :type 'string
  :group 'org-linear)

(defcustom org-linear-issues-page-size 50
  "How many issues to fetch per GraphQL page."
  :type 'integer
  :group 'org-linear)

(defcustom org-linear-directory ".org-linear"
  "Directory to store Linear team issue files.
Each team's issues will be stored in [TEAM].org within this directory."
  :type 'string
  :group 'org-linear)

(defcustom org-linear-state-alist
  '(("TODO" . "Todo")
    ("IN-PROGRESS" . "In Progress")
    ("IN-REVIEW" . "In Review")
    ("BACKLOG" . "Backlog")
    ("BLOCKED" . "Blocked")
    ("DONE" . "Done"))
  "Alist mapping Org TODO keywords to Linear state names.
Each entry is (ORG-TODO-KEYWORD . LINEAR-STATE-NAME).
The mapping is bidirectional: syncing uses this to convert between Org and Linear states."
  :type '(alist :key-type string :value-type string)
  :group 'org-linear)

(defcustom org-linear-priority-alist
  '((?A . 1)
    (?B . 2)
    (?C . 3)
    (?D . 4))
  "Alist mapping Org priority characters to Linear priority numbers.
Each entry is (ORG-PRIORITY-CHAR . LINEAR-PRIORITY-NUMBER).
Linear priorities: 0=No priority, 1=Urgent, 2=High, 3=Medium, 4=Low.
The mapping is bidirectional: syncing uses this to convert between Org and Linear priorities."
  :type '(alist :key-type character :value-type integer)
  :group 'org-linear)

(defvar org-linear-oauth-state nil
  "CSRF-prevention state used during OAuth flow.")

(defvar org-linear-oauth-pkce-verifier nil
  "PKCE code verifier for OAuth flow.")

(defvar org-linear--cached-token nil
  "Cached access token for performance.")

(defvar org-linear--token-expiry nil
  "Expiry time for cached token.")

;;;; Authentication helpers

(defcustom org-linear-auth-host "api.linear.app"
  "Host for Linear API authentication storage."
  :type 'string
  :group 'org-linear-auth)

(defcustom org-linear-auth-user "access-token"
  "User identifier for Linear API authentication storage."
  :type 'string
  :group 'org-linear-auth)

(defun org-linear-auth--read-token ()
  "Read Linear access token from auth-source with caching.
Returns token string or nil if not found."
  (cl-block nil
    ;; Return cached token if still valid
    (when (and org-linear--cached-token
               org-linear--token-expiry
               (time-less-p (current-time) org-linear--token-expiry))
      (cl-return org-linear--cached-token))

    ;; Look up token from auth-source
    (when-let* ((auth-info (auth-source-search
                           :host org-linear-auth-host
                           :user org-linear-auth-user
                           :port "https"
                           :require '(:secret)
                           :max 1))
                (auth-entry (car auth-info))
                (secret-fn (plist-get auth-entry :secret)))
      (let ((token (if (functionp secret-fn) (funcall secret-fn) secret-fn)))
        (when (and token (stringp token) (> (length (string-trim token)) 0))
          (setq org-linear--cached-token token
                org-linear--token-expiry (time-add (current-time) (* 3600 24))) ; Cache for 24h
          token)))))

(defun org-linear-auth--write-token (token &optional refresh-token expires-in)
  "Write TOKEN to auth-source storage.
REFRESH-TOKEN and EXPIRES-IN are stored for future use."
  (when (and token (stringp token) (> (length (string-trim token)) 0))
    ;; Use auth-source-search with :create t to store credentials
    (condition-case err
        (let ((auth-source-save-behavior t))
          ;; Store access token
          (let ((result (auth-source-search
                         :host org-linear-auth-host
                         :user org-linear-auth-user
                         :port "https"
                         :secret token
                         :create t
                         :max 1)))
            (when result
              (let ((save-function (plist-get (car result) :save-function)))
                (when save-function (funcall save-function)))))

          ;; Store refresh token if provided
          (when (and refresh-token (stringp refresh-token) (> (length (string-trim refresh-token)) 0))
            (let ((result (auth-source-search
                           :host org-linear-auth-host
                           :user (concat org-linear-auth-user "-refresh")
                           :port "https"
                           :secret refresh-token
                           :create t
                           :max 1)))
              (when result
                (let ((save-function (plist-get (car result) :save-function)))
                  (when save-function (funcall save-function))))))

          (message "Tokens saved to auth-source successfully"))
      (error
       ;; Fallback: just cache in memory and show the actual error
       (message "Unable to save tokens to auth-source (%s). Tokens cached in memory only." (error-message-string err))))

    ;; Always cache the token in memory
    (setq org-linear--cached-token token
          org-linear--token-expiry (if expires-in
                                      (time-add (current-time) expires-in)
                                    (time-add (current-time) (* 3600 24))))))

(defun org-linear-auth--read-refresh-token ()
  "Read Linear refresh token from auth-source.
 Returns refresh token string or nil if not found."
  (when-let* ((auth-info (auth-source-search
                         :host org-linear-auth-host
                         :user (concat org-linear-auth-user "-refresh")
                         :port "https"
                         :require '(:secret)
                         :max 1))
              (auth-entry (car auth-info))
              (secret-fn (plist-get auth-entry :secret)))
    (let ((token (if (functionp secret-fn) (funcall secret-fn) secret-fn)))
      (when (and token (stringp token) (> (length (string-trim token)) 0))
        token))))

(defun org-linear-auth--refresh-token ()
  "Refresh the access token using the stored refresh token.
Returns t on success, nil on failure."
  (cl-block nil
    (let ((refresh-token (org-linear-auth--read-refresh-token)))
      (unless refresh-token
        (message "No refresh token available. Please re-authenticate.")
        (cl-return nil))

      (pcase-let* ((`(,client-id . ,client-secret) (condition-case nil
                                                        (org-linear-auth--read-client-credentials)
                                                      (error nil)))
                   (success-flag nil))
        (unless (and client-id client-secret)
          (message "Cannot refresh token: missing client credentials")
          (cl-return nil))

      (request
       "https://api.linear.app/oauth/token"
       :type "POST"
       :sync t
       :headers '(("Content-Type" . "application/x-www-form-urlencoded"))
       :data (format (concat "refresh_token=%s"
                            "&client_id=%s"
                            "&client_secret=%s"
                            "&grant_type=refresh_token")
                     (url-hexify-string refresh-token)
                     (url-hexify-string client-id)
                     (url-hexify-string client-secret))
       :parser 'json-read
       :success (cl-function
                 (lambda (&key data &allow-other-keys)
                   (let ((access-token (alist-get 'access_token data))
                         (new-refresh-token (alist-get 'refresh_token data))
                         (expires-in (alist-get 'expires_in data)))
                     (when access-token
                       (org-linear-auth--write-token access-token
                                                  (or new-refresh-token refresh-token)
                                                  expires-in)
                       (setq success-flag t)
                       (message "Successfully refreshed Linear access token")))))
       :error (cl-function
               (lambda (&key error-thrown response &allow-other-keys)
                 (let ((status (when response (request-response-status-code response))))
                   (message "Failed to refresh token (HTTP %s): %S" status error-thrown)))))
        success-flag))))

(defun org-linear-auth-clear ()
  "Clear stored Linear authentication tokens."
  (interactive)
  (setq org-linear--cached-token nil
        org-linear--token-expiry nil)
  (let ((deleted 0))
    ;; Clear access token
    (condition-case nil
        (when-let* ((auth-info (auth-source-search
                               :host org-linear-auth-host
                               :user org-linear-auth-user
                               :port "https"
                               :max 1)))
          (dolist (entry auth-info)
            (when-let* ((delete-fn (plist-get entry :delete)))
              (funcall delete-fn)
              (cl-incf deleted))))
      (error nil))

    ;; Clear refresh token
    (condition-case nil
        (when-let* ((auth-info (auth-source-search
                               :host org-linear-auth-host
                               :user (concat org-linear-auth-user "-refresh")
                               :port "https"
                               :max 1)))
          (dolist (entry auth-info)
            (when-let* ((delete-fn (plist-get entry :delete)))
              (funcall delete-fn)
              (cl-incf deleted))))
      (error nil))

    (if (> deleted 0)
        (message "Cleared %d Linear auth token(s)" deleted)
      (message "Cleared cached tokens (auth-source entries may need manual removal)"))))

;;;###autoload
(defun org-linear-auth-revoke ()
  "Revoke Linear authentication by deleting stored access and refresh tokens."
  (interactive)
  (org-linear-auth-clear))

(defun org-linear-auth--read-client-credentials ()
  "Read client credentials from environment or auth-source.
Returns (client-id . client-secret) or signals error."
  (let ((id (or (getenv "LINEAR_CLIENT_ID")
                ;; Fallback to deprecated defcustom for backward compatibility
                (unless (string-empty-p (string-trim org-linear-client-id))
                  org-linear-client-id)
                (when-let* ((auth-info (auth-source-search
                                       :host org-linear-auth-host
                                       :user "client-id"
                                       :port "https"
                                       :max 1))
                            (secret-fn (plist-get (car auth-info) :secret)))
                  (if (functionp secret-fn) (funcall secret-fn) secret-fn))))
        (secret (or (getenv "LINEAR_CLIENT_SECRET")
                    ;; Fallback to deprecated defcustom for backward compatibility
                    (unless (string-empty-p (string-trim org-linear-client-secret))
                      org-linear-client-secret)
                    (when-let* ((auth-info (auth-source-search
                                           :host org-linear-auth-host
                                           :user "client-secret"
                                           :port "https"
                                           :max 1))
                                (secret-fn (plist-get (car auth-info) :secret)))
                      (if (functionp secret-fn) (funcall secret-fn) secret-fn)))))
    (unless (and id secret 
                 (> (length (string-trim id)) 0) 
                 (> (length (string-trim secret)) 0))
      (user-error "Linear client credentials not found. Set LINEAR_CLIENT_ID/LINEAR_CLIENT_SECRET environment variables, configure via auth-source, or set org-linear-client-id/org-linear-client-secret"))
    (cons (string-trim id) (string-trim secret))))

(defun org-linear-auth--base64url-encode (data)
  "Encode DATA as base64url (RFC 4648)."
  (let ((b64 (base64-encode-string data t)))
    (setq b64 (replace-regexp-in-string "\\+" "-" b64))
    (setq b64 (replace-regexp-in-string "/" "_" b64))
    (setq b64 (replace-regexp-in-string "=" "" b64))
    b64))

(defun org-linear-auth--generate-pkce-pair ()
  "Generate PKCE code verifier and challenge."
  (let* ((verifier-data (format "%s-%s-%s-%s" 
                               (current-time-string)
                               (emacs-pid)
                               (random 1000000)
                               (random 1000000)))
         (verifier (org-linear-auth--base64url-encode verifier-data))
         (challenge-data (secure-hash 'sha256 verifier nil nil 'binary))
         (challenge (org-linear-auth--base64url-encode challenge-data)))
    (cons verifier challenge)))

(defun org-linear-auth--generate-state ()
  "Generate cryptographically secure OAuth state parameter."
  (let ((state-data (format "%s-%s-%s-%s"
                           (current-time-string)
                           (emacs-pid)
                           (random 1000000)
                           (random 1000000))))
    (org-linear-auth--base64url-encode state-data)))

(defun org-linear-auth-status ()
  "Show current authentication status."
  (interactive)
  (let ((has-token (or (org-linear-auth--read-token)
                       (unless (string-empty-p (string-trim org-linear-api-key))
                         org-linear-api-key)))
        (has-credentials (condition-case nil
                            (org-linear-auth--read-client-credentials)
                          (error nil))))
    (message "Linear auth status: Token: %s, Credentials: %s"
             (if has-token "✓" "✗")
             (if has-credentials "✓" "✗"))))

;;;; OAuth: top-level servlet + helpers

;; Handler at: http://localhost:8080/callback
(defservlet callback text/plain (path query)
  (let ((code  (cadr (assoc "code" query)))
        (state (cadr (assoc "state" query)))
        (error-code (cadr (assoc "error" query))))
    (cond
     (error-code
      (insert (format "Authentication failed: %s" error-code)))
     ((not (and code state))
      (insert "Authentication failed: missing code/state."))
     ((not (string= state org-linear-oauth-state))
      (insert "Authentication failed: invalid state (CSRF protection)."))
     (t
      (condition-case err
          (progn
            (org-linear-oauth-exchange-code code)
            (insert "Authentication successful! You can close this window."))
        (error
         (insert (format "Authentication failed during token exchange: %s" (error-message-string err)))))))))

;;;###autoload
(defun org-linear-oauth-callback-server ()
  "Start a local HTTP server for Linear OAuth at /callback."
  (interactive)
  (setq httpd-port 8080)
  (httpd-start)
  (message "Listening for Linear OAuth callback at http://localhost:%d/callback" httpd-port))

;;;###autoload
(defun org-linear-oauth-callback-server-stop ()
  "Stop the local HTTP server used for Linear OAuth."
  (interactive)
  (httpd-stop)
  (message "Stopped OAuth callback server."))

;;;###autoload
(defun org-linear-oauth-authorize ()
  "Start the OAuth2 authorization process for Linear.
Automatically starts the callback server if it's not already running."
  (interactive)
  (condition-case err
      (progn
        ;; Ensure callback server is running
        (unless (and (boundp 'httpd-port) httpd-port
                     (get-process "httpd"))
          (org-linear-oauth-callback-server))

        (pcase-let* ((`(,client-id . ,client-secret) (org-linear-auth--read-client-credentials))
                     (`(,verifier . ,challenge) (org-linear-auth--generate-pkce-pair))
                     (state (org-linear-auth--generate-state))
                     (url (format (concat "https://linear.app/oauth/authorize"
                                          "?client_id=%s"
                                          "&redirect_uri=%s"
                                          "&response_type=code"
                                          "&scope=read,write"
                                          "&state=%s"
                                          "&code_challenge=%s"
                                          "&code_challenge_method=S256")
                                  (url-hexify-string client-id)
                                  (url-hexify-string org-linear-oauth-redirect-uri)
                                  (url-hexify-string state)
                                  (url-hexify-string challenge))))
          (setq org-linear-oauth-state state
                org-linear-oauth-pkce-verifier verifier)
          (browse-url url)
          (message "Opening browser for Linear OAuth…")))
    (error
     (message "Failed to start OAuth flow: %s" (error-message-string err)))))

(defun org-linear-oauth-exchange-code (code)
  "Exchange authorization CODE for an access token."
  (pcase-let ((`(,client-id . ,client-secret) (org-linear-auth--read-client-credentials)))
    (request
     "https://api.linear.app/oauth/token"
     :type "POST"
     :headers '(("Content-Type" . "application/x-www-form-urlencoded"))
     :data (format (concat "code=%s"
                          "&redirect_uri=%s"
                          "&client_id=%s"
                          "&client_secret=%s"
                          "&grant_type=authorization_code"
                          "&code_verifier=%s")
                   (url-hexify-string code)
                   (url-hexify-string org-linear-oauth-redirect-uri)
                   (url-hexify-string client-id)
                   (url-hexify-string client-secret)
                   (url-hexify-string (or org-linear-oauth-pkce-verifier "")))
     :parser 'json-read
     :success (cl-function
               (lambda (&key data &allow-other-keys)
                 (let ((access-token (alist-get 'access_token data))
                       (refresh-token (alist-get 'refresh_token data))
                       (expires-in (alist-get 'expires_in data)))
                   (org-linear-auth--write-token access-token refresh-token expires-in)
                   (setq org-linear-oauth-state nil
                         org-linear-oauth-pkce-verifier nil)
                   (message "Successfully authenticated with Linear!"))))
     :error (cl-function
             (lambda (&key error-thrown response &allow-other-keys)
               (let ((status (when response (request-response-status-code response)))
                     (data (when response
                            (condition-case nil
                                (let ((buffer (request-response--buffer response)))
                                  (when buffer
                                    (with-current-buffer buffer
                                      (json-read-from-string (buffer-string)))))
                              (error nil)))))
                 (message "Error exchanging code for token (HTTP %s): %S. Data: %S"
                         status error-thrown data)))))))

;;;; GraphQL core

(defun org-linear--assert-auth ()
  "Signal an error if no API key is present, return token if found."
  (let ((token (or (org-linear-auth--read-token)
                   (unless (string-empty-p (string-trim org-linear-api-key))
                     org-linear-api-key))))
    (unless (and token (> (length (string-trim token)) 0))
      (user-error "No Linear API key found. Run `linear-oauth-authorize' or configure via auth-source"))
    token))

(defun org-linear--alist-get-in (keys alist)
  "Return nested value by KEYS from ALIST/hash-tables."
  (cl-reduce (lambda (acc k)
               (cond
                ((hash-table-p acc) (gethash k acc))
                ((listp acc)        (alist-get k acc))
                (t nil)))
             keys :initial-value alist))

(defun org-linear--graphql (query &optional variables)
  "Execute a synchronous GraphQL REQUEST with QUERY and VARIABLES.
Returns parsed JSON as an alist, or signals an error with details.
Automatically refreshes token on 401 and retries once."
  (let ((token (org-linear--assert-auth))
        (retry-count 0)
        resp err resp-buf status-code)
    (while (< retry-count 2)
      (setq resp nil err nil resp-buf nil status-code nil)
      (request
       org-linear-graphql-endpoint
       :type "POST"
       :sync t
       :headers `(("Content-Type" . "application/json")
                  ("Authorization" . ,(concat "Bearer " (string-trim token))))
       :data (json-encode `(("query" . ,query)
                            ("variables" . ,(or variables (make-hash-table :test 'equal)))))
       :parser 'json-read
       :success (cl-function (lambda (&key data &allow-other-keys) (setq resp data)))
       :error   (cl-function
                 (lambda (&key error-thrown response &allow-other-keys)
                   (setq err error-thrown
                         resp-buf (when response (request-response--buffer response))
                         status-code (when response (request-response-status-code response))))))

      ;; Check if we got a 401 and should retry with refreshed token
      (if (and (= retry-count 0)
               (or (and status-code (= status-code 401))
                   (and err (string-match-p "401\\|[Uu]nauthorized" (format "%s" err)))))
          ;; Try to refresh token and retry
          (if (org-linear-auth--refresh-token)
              (progn
                (setq token (org-linear--assert-auth))
                (cl-incf retry-count)
                (message "Retrying request with refreshed token..."))
            ;; Refresh failed, break out of loop
            (setq retry-count 2))
        ;; Not a 401 or already retried, break out of loop
        (setq retry-count 2)))

    (when err
      (let ((raw (and resp-buf (with-current-buffer resp-buf (buffer-string)))))
        (error "Linear GraphQL request failed: %S\nRaw: %s" err (or raw ""))))
    (let* ((errors (alist-get 'errors resp))
           (first-error (and (vectorp errors) (> (length errors) 0) (aref errors 0)))
           (msg (and (consp first-error) (alist-get 'message first-error))))
      (when msg
        (error "Linear GraphQL error: %s" msg)))
    (alist-get 'data resp)))

;;;; Common helpers

(defun org-linear--string-or (s fallback)
  "Trim S to a string, else FALLBACK."
  (let ((v (and s (stringp s) (string-trim s))))
    (if (and v (> (length v) 0)) v fallback)))

(defun org-linear--truthy (x)
  "Return non-nil iff JSON boolean X is true."
  (and x (not (eq x json-false))))

;;;; Teams

(defun org-linear--teams ()
  "Return a list of teams as ((DISPLAY . ID) ...)."
  (let* ((q "query { teams(first: 100) { nodes { id name key } } }")
         (data  (org-linear--graphql q))
         (nodes (alist-get 'nodes (alist-get 'teams data))))
    (mapcar (lambda (node)
              (let ((id   (alist-get 'id node))
                    (name (alist-get 'name node))
                    (key  (alist-get 'key node)))
                (cons (format "%s (%s)" name key) id)))
            (append nodes nil))))

(defun org-linear--team-states (team-id)
  "Return ((DISPLAY . ID) ...) for workflow states of TEAM-ID."
  (let* ((q "query($id: ID!) { team(id:$id){ states(first:100){ nodes { id name type } } } }")
         (vars (let ((h (make-hash-table :test 'equal))) (puthash "id" team-id h) h))
         (data (org-linear--graphql q vars))
         (nodes (org-linear--alist-get-in '(team states nodes) data)))
    (mapcar (lambda (node)
              (let ((id (alist-get 'id node))
                    (nm (alist-get 'name node))
                    (tp (alist-get 'type node)))
                (cons (format "%s (%s)" nm tp) id)))
            (append nodes nil))))

(defun org-linear--team-labels (team-id)
  "Return ((NAME . ID) ...) for labels of TEAM-ID."
  (let* ((q "query($id: ID!) { team(id:$id){ labels(first:100){ nodes { id name } } } }")
         (vars (let ((h (make-hash-table :test 'equal))) (puthash "id" team-id h) h))
         (data (org-linear--graphql q vars))
         (nodes (org-linear--alist-get-in '(team labels nodes) data)))
    (mapcar (lambda (node)
              (cons (alist-get 'name node) (alist-get 'id node)))
            (append nodes nil))))

;;;; Team file management

(defun org-linear--ensure-directory ()
  "Ensure the org-linear directory exists. Return the absolute path."
  (let ((dir (expand-file-name org-linear-directory)))
    (unless (file-exists-p dir)
      (make-directory dir t))
    dir))

(defun org-linear--team-file-path (team-name team-key)
  "Return the file path for TEAM-NAME with TEAM-KEY.
The filename will be sanitized to remove special characters."
  (let* ((dir (org-linear--ensure-directory))
         ;; Use team key as filename, sanitize it
         (filename (format "%s.org" (replace-regexp-in-string "[^a-zA-Z0-9-]" "_" team-key))))
    (expand-file-name filename dir)))

;;;; Workspace users (assignees)

(defun org-linear--users (&optional n)
  "Return ((DISPLAY . ID) ...) for workspace users (active first). N defaults to 200."
  (let* ((q "query($first:Int!){
               users(first:$first){
                 nodes{ id name displayName active }
               }
             }")
         (vars (let ((h (make-hash-table :test 'equal)))
                 (puthash "first" (or n 200) h) h))
         (data  (org-linear--graphql q vars))
         (nodes (alist-get 'nodes (alist-get 'users data))))
    (let* ((vec (append nodes nil))
           (active (seq-filter (lambda (u) (org-linear--truthy (alist-get 'active u))) vec))
           (inactive (seq-remove (lambda (u) (org-linear--truthy (alist-get 'active u))) vec))
           (ordered (append active inactive)))
      (mapcar (lambda (u)
                (let* ((id (alist-get 'id u))
                       (nm (or (alist-get 'displayName u)
                               (alist-get 'name u)
                               id)))
                  (cons nm id)))
              ordered))))

;;;; Issues → Org

(defun org-linear--issues-for-team (team-id)
  "Return a list of issue nodes for TEAM-ID (handles pagination)."
  (let ((query
         "query($teamId: ID!, $first: Int!, $after: String) {
            issues(
              filter: { team: { id: { eq: $teamId } }, state: { type: { neq: \"canceled\" } } }
              orderBy: updatedAt
              first: $first
              after: $after
            ) {
              pageInfo { hasNextPage endCursor }
              nodes {
                id identifier title url
                state { id name type }
                priority
                assignee { id name displayName }
                labels { nodes { id name color } }
                createdAt updatedAt
              }
            }
          }"))
    (let ((results nil)
          (after   nil)
          (guard   0)
          has-next prev-cursor)
      (setq has-next t)
      (while (and has-next (< guard 500))
        (cl-incf guard)
        (let* ((vars (let ((ht (make-hash-table :test 'equal)))
                       (puthash "teamId" team-id ht)
                       (puthash "first" (or org-linear-issues-page-size 50) ht)
                       (when after (puthash "after" after ht))
                       ht))
               (data   (org-linear--graphql query vars))
               (issues (alist-get 'issues data))
               (page   (alist-get 'pageInfo issues))
               (nodes  (alist-get 'nodes issues)))
          (setq results (nconc results (append nodes nil)))
          (setq prev-cursor after
                after    (alist-get 'endCursor page)
                has-next (org-linear--truthy (alist-get 'hasNextPage page)))
          (when (and (not has-next) (equal after prev-cursor))
            (setq has-next nil))))
      results)))

(defun org-linear--map-state-to-todo (state-name)
  "Map Linear STATE-NAME to Org TODO keyword using `org-linear-state-alist'.
Returns TODO keyword or nil if no mapping found."
  (when state-name
    ;; First try exact match
    (or (car (rassoc state-name org-linear-state-alist))
        ;; Then try case-insensitive fuzzy match
        (car (cl-find-if (lambda (pair)
                          (string-equal-ignore-case (cdr pair) state-name))
                        org-linear-state-alist))
        ;; Fallback to TODO
        "TODO")))

(defun org-linear--map-priority-to-org (linear-priority)
  "Map Linear priority number to Org priority character using `org-linear-priority-alist'.
Returns Org priority character or nil if no mapping found."
  (when linear-priority
    (car (rassoc linear-priority org-linear-priority-alist))))

(defun org-linear--map-org-to-priority (org-priority-char)
  "Map Org priority character to Linear priority number using `org-linear-priority-alist'.
Returns Linear priority number or nil if no mapping found."
  (when org-priority-char
    (cdr (assoc org-priority-char org-linear-priority-alist))))

(defun org-linear--labels-to-tags (labels-data)
  "Convert Linear LABELS-DATA to list of Org tag strings.
LABELS-DATA is the labels field from Linear API: { nodes: [...] }"
  (when labels-data
    (let* ((nodes (alist-get 'nodes labels-data))
           (label-names (mapcar (lambda (label)
                                 (alist-get 'name label))
                               nodes)))
      ;; Convert label names to valid Org tags (replace spaces/special chars with underscores)
      (mapcar (lambda (name)
               (replace-regexp-in-string "[^[:alnum:]_@#%]+" "_" name))
             label-names))))

(defun org-linear--issue->org-heading (issue)
  "Return (TODO-KEYWORD ORG-PRIORITY TAGS HEADLINE . PROPERTIES) derived from ISSUE node."
  (let* ((id          (alist-get 'id issue))
         (identifier  (alist-get 'identifier issue))
         (title       (org-linear--string-or (alist-get 'title issue) "(no title)"))
         (url         (alist-get 'url issue))
         (state-name  (org-linear--alist-get-in '(state name) issue))
         (todo-kw     (org-linear--map-state-to-todo state-name))
         (assignee    (or (org-linear--alist-get-in '(assignee displayName) issue)
                          (org-linear--alist-get-in '(assignee name) issue)
                          "—"))
         (linear-priority (alist-get 'priority issue))
         (org-priority    (org-linear--map-priority-to-org linear-priority))
         (labels      (alist-get 'labels issue))
         (tags        (org-linear--labels-to-tags labels))
         ;; Store labels as comma-separated list of label names
         (labels-str  (when labels
                       (let ((nodes (alist-get 'nodes labels)))
                         (mapconcat (lambda (label) (alist-get 'name label))
                                   nodes
                                   ", "))))
         (headline    (format "[%s] %s" identifier title))
         (props `(("LINEAR_ID"  . ,id)
                  ("STATE"      . ,(or state-name ""))
                  ("ASSIGNEE"   . ,assignee)
                  ("PRIORITY"   . ,(if linear-priority (number-to-string linear-priority) ""))
                  ("LABELS"     . ,(or labels-str ""))
                  ("URL"        . ,(or url ""))
                  ("UPDATED"    . ,(format-time-string "%Y-%m-%d %H:%M")) )))
    (list todo-kw org-priority tags headline props)))

(defun org-linear--insert-org-heading (todo-kw org-priority tags headline props)
  "Insert an Org subtree for HEADLINE with TODO-KW, ORG-PRIORITY, TAGS and PROPS alist."
  (let* ((priority-str (if org-priority (format " [#%c]" org-priority) ""))
         (all-tags (if tags
                      (append tags '("linear"))
                    '("linear"))))
    ;; Insert heading without tags first
    (insert (format "* %s%s %s\n" (or todo-kw "TODO") priority-str headline))
    ;; Move to the heading and set tags properly (this will align them)
    (forward-line -1)
    (org-set-tags all-tags)
    (forward-line 1)
    ;; Insert properties
    (insert ":PROPERTIES:\n")
    (dolist (kv props)
      (insert (format ":%s: %s\n" (car kv) (cdr kv))))
    (insert ":END:\n")))

;;;###autoload
(defun org-linear-insert-issues-for-team (&optional team-id)
  "Prompt for a Linear TEAM-ID (or use TEAM-ID) and insert its open issues as Org headings.
Each issue becomes a `**` heading with useful PROPERTIES and a clickable URL."
  (interactive)
  (org-linear--assert-auth)
  (let* ((choice (or team-id
                     (let* ((pairs (org-linear--teams))
                            (name (completing-read "Linear team: " (mapcar #'car pairs) nil t)))
                       (cdr (assoc name pairs)))))
         (issues (org-linear--issues-for-team choice))
         (team-label (car (rassoc choice (org-linear--teams)))))
    (unless issues
      (user-error "No issues returned for that team"))
    (save-excursion
      (unless (org-before-first-heading-p)
        (org-back-to-heading t)
        (org-end-of-subtree t t)
        (unless (bolp) (insert "\n")))
      (insert (format "* Linear Issues for %s\n"
                      (or team-label choice)))
      (org-set-property "TEAM_ID" choice)
      (dolist (iss issues)
        (pcase-let* ((`(,todo-kw ,org-priority ,tags ,headline ,props) (org-linear--issue->org-heading iss)))
          (org-linear--insert-org-heading todo-kw org-priority tags headline props)))
      (message "Inserted %d issues for team %s" (length issues) (or team-label choice)))))

;;;###autoload
(defun org-linear-open-at-point ()
  "Open the Linear issue URL for the Org heading at point."
  (interactive)
  (let ((url (org-entry-get (point) "URL")))
    (if (and url (string-match-p "^https?://" url))
        (browse-url url)
      (user-error "No URL property on this heading"))))

;;;###autoload
(defun org-linear-refresh-under-heading ()
  "Re-sync issues for the team of the current parent heading, replacing `**` entries.
Relies on a TEAM_ID property at the parent level."
  (interactive)
  (save-excursion
    (org-back-to-heading t)
    (let* ((parent (point))
           (team-id (org-entry-get parent "TEAM_ID")))
      (unless team-id
        (user-error "No TEAM_ID on this heading; re-run `org-linear-insert-issues-for-team`"))
      (org-map-entries
       (lambda ()
         (when (= (org-current-level) 2)
           (org-cut-subtree)))
       nil 'children)
      (let ((issues (org-linear--issues-for-team team-id)))
        (dolist (iss issues)
          (pcase-let* ((`(,todo-kw ,org-priority ,tags ,headline ,props) (org-linear--issue->org-heading iss)))
            (org-linear--insert-org-heading todo-kw org-priority tags headline props)))
        (message "Refreshed %d issues" (length issues))))))

;;;###autoload
(defun org-linear-refresh-file ()
  "Re-sync issues for the team file, replacing all `*` level entries.
Relies on file-level #+PROPERTY: TEAM_ID."
  (interactive)
  (org-linear--assert-auth)
  (let ((team-id (org-entry-get-with-inheritance "TEAM_ID")))
    (unless team-id
      (user-error "No TEAM_ID file property found"))
    ;; Delete all top-level headings
    (save-excursion
      (goto-char (point-min))
      (while (re-search-forward "^\\* " nil t)
        (org-back-to-heading t)
        (org-cut-subtree)))
    ;; Re-insert all issues
    (let ((issues (org-linear--issues-for-team team-id)))
      (goto-char (point-max))
      (dolist (iss issues)
        (pcase-let* ((`(,todo-kw ,org-priority ,tags ,headline ,props) (org-linear--issue->org-heading iss)))
          (org-linear--insert-org-heading todo-kw org-priority tags headline props)))
      (message "Refreshed %d issues" (length issues)))))

;;;; Property validation and conversion for bidirectional sync

(defun org-linear--validate-assignee (assignee-name team-id)
  "Convert ASSIGNEE-NAME to user ID, return nil if invalid/unassigned."
  (when (and assignee-name
             (not (string-empty-p (string-trim assignee-name)))
             (not (string-prefix-p "—" assignee-name)))
    (let* ((users (org-linear--users 200))
           (match (cl-find-if (lambda (pair)
                               (string= (car pair) (string-trim assignee-name)))
                             users)))
      (when match (cdr match)))))

(defun org-linear--validate-state (state-name team-id)
  "Convert STATE-NAME to state ID, return nil if invalid."
  (when (and state-name
             (not (string-empty-p (string-trim state-name)))
             (not (string-prefix-p "—" state-name)))
    (let* ((states (org-linear--team-states team-id))
           (match (cl-find-if (lambda (pair)
                               (let ((display (car pair)))
                                 (or (string= display (string-trim state-name))
                                     (string= (replace-regexp-in-string " (.*)" "" display)
                                             (string-trim state-name)))))
                             states)))
      (when match (cdr match)))))

(defun org-linear--validate-priority (priority-str)
  "Convert PRIORITY-STR to integer priority, return nil if invalid."
  (when (and priority-str
             (not (string-empty-p (string-trim priority-str)))
             (string-match-p "^[0-4]$" (string-trim priority-str)))
    (string-to-number (string-trim priority-str))))

(defun org-linear--validate-labels (labels-str team-id)
  "Convert comma-separated LABELS-STR to list of label IDs for TEAM-ID.
Returns list of label IDs that exist in the team, ignoring unknown labels."
  (when (and labels-str (not (string-empty-p (string-trim labels-str))))
    (let* ((label-names (mapcar #'string-trim
                               (split-string labels-str "," t)))
           (team-labels (org-linear--team-labels team-id)))
      (delq nil
            (mapcar (lambda (name)
                     (cdr (assoc name team-labels)))
                   label-names)))))

(defun org-linear--extract-title-from-heading (heading)
  "Extract clean title from Org HEADING, removing [IDENTIFIER] prefix if present."
  (let ((clean (string-trim heading)))
    (if (string-match "^\\[\\([A-Z]+-[0-9]+\\)\\] \\(.*\\)" clean)
        (match-string 2 clean)
      clean)))

(defun org-linear--get-team-id-for-issue (linear-id)
  "Get team ID for an issue by querying Linear API with LINEAR-ID."
  (let* ((q "query($id: String!) {
               issue(id: $id) {
                 team { id }
               }
             }")
         (vars (let ((h (make-hash-table :test 'equal)))
                 (puthash "id" linear-id h) h))
         (data (org-linear--graphql q vars)))
    (org-linear--alist-get-in '(issue team id) data)))

;;;; Create issue from Org subtree

(defun org-linear--org-subtree-title ()
  "Return the current Org heading text, stripped of TODO/priority/tags."
  (save-excursion
    (org-back-to-heading t)
    (let ((raw (org-get-heading t t t t)))
      (string-trim raw))))

(defun org-linear--org-subtree-body ()
  "Return body text of the current Org subtree (excluding the heading line)."
  (save-excursion
    (org-back-to-heading t)
    (let ((beg (progn (forward-line 1) (point)))
          (end (progn (org-end-of-subtree t t) (point))))
      (string-trim (buffer-substring-no-properties beg end)))))

(defun org-linear--read-team (&optional default-id)
  "Prompt for a team; if DEFAULT-ID provided, preselect it."
  (let* ((pairs (org-linear--teams))
         (default-name (car (rassoc default-id pairs)))
         (name (completing-read
                (if default-name
                    (format "Team (default %s): " default-name)
                  "Team: ")
                (mapcar #'car pairs) nil t nil nil default-name)))
    (cdr (assoc name pairs))))

(defun org-linear--read-assignee (&optional _team-id)
  "Prompt for an assignee from workspace users; return user ID or nil."
  (let* ((pairs (org-linear--users 200))
         (names (cons "— Unassigned —" (mapcar #'car pairs)))
         (choice (completing-read "Assignee: " names nil t nil nil "— Unassigned —")))
    (if (string-prefix-p "—" choice) nil (cdr (assoc choice pairs)))))

(defun org-linear--read-state (team-id)
  "Prompt for a workflow state in TEAM-ID; return state ID or nil."
  (let* ((pairs (org-linear--team-states team-id))
         (names (cons "— Default —" (mapcar #'car pairs)))
         (choice (completing-read "State: " names nil t nil nil "— Default —")))
    (if (string-prefix-p "—" choice)
        nil
      (cdr (assoc choice pairs)))))

(defun org-linear--read-priority ()
  "Prompt for priority 0–4; returns integer or nil."
  (let* ((opts '("0 (None)" "1 (Low)" "2 (Medium)" "3 (High)" "4 (Urgent)" "— leave unset —"))
         (choice (completing-read "Priority: " opts nil t nil nil "— leave unset —")))
    (pcase choice
      ((pred (string-prefix-p "0")) 0)
      ((pred (string-prefix-p "1")) 1)
      ((pred (string-prefix-p "2")) 2)
      ((pred (string-prefix-p "3")) 3)
      ((pred (string-prefix-p "4")) 4)
      (_ nil))))

(defun org-linear--issue-create (team-id title description &optional assignee-id state-id priority)
  "Create a Linear issue; return alist with id/identifier/url (or signal error)."
  (let* ((q "mutation($input: IssueCreateInput!){
               issueCreate(input:$input){
                 success
                 issue{ id identifier url
                        state{ id name }
                        assignee{ id name displayName }
                        priority
                        labels { nodes { id name color } } }
               }
             }")
         (in (let ((h (make-hash-table :test 'equal)))
               (puthash "teamId" team-id h)
               (puthash "title" title h)
               (when (and description (> (length (string-trim description)) 0))
                 (puthash "description" description h))
               (when assignee-id (puthash "assigneeId" assignee-id h))
               (when state-id    (puthash "stateId" state-id h))
               (when priority    (puthash "priority" priority h))
               h))
         (vars (let ((h (make-hash-table :test 'equal))) (puthash "input" in h) h))
         (data (org-linear--graphql q vars))
         (node (org-linear--alist-get-in '(issueCreate issue) data)))
    (unless node (error "Linear returned no issue node"))
    node))

(defun org-linear--issue-update (issue-id &optional title description assignee-id state-id priority label-ids)
  "Update a Linear issue; return alist with updated issue data (or signal error)."
  (let* ((q "mutation($id: String!, $input: IssueUpdateInput!){
               issueUpdate(id: $id, input: $input){
                 success
                 issue{ id identifier url title
                        state{ id name type }
                        assignee{ id name displayName }
                        priority priorityLabel
                        labels { nodes { id name color } } }
               }
             }")
         (in (let ((h (make-hash-table :test 'equal)))
               (when (and title (> (length (string-trim title)) 0))
                 (puthash "title" title h))
               (when (and description (> (length (string-trim description)) 0))
                 (puthash "description" description h))
               (when assignee-id (puthash "assigneeId" assignee-id h))
               (when state-id    (puthash "stateId" state-id h))
               (when priority    (puthash "priority" priority h))
               (when label-ids   (puthash "labelIds" (vconcat label-ids) h))
               h))
         (vars (let ((h (make-hash-table :test 'equal)))
                 (puthash "id" issue-id h)
                 (puthash "input" in h)
                 h))
         (data (org-linear--graphql q vars))
         (success (org-linear--alist-get-in '(issueUpdate success) data))
         (node (org-linear--alist-get-in '(issueUpdate issue) data)))
    (unless success (error "Linear issue update failed"))
    (unless node (error "Linear returned no issue node after update"))
    node))

;;;###autoload
(defun org-linear-create-issue-from-subtree (&optional team-id)
  "Create a Linear issue using the current Org subtree.
Prompts for Team/State/Assignee/Priority, uses heading as title and body as description.
Writes LINEAR_ID/URL/STATE/ASSIGNEE/PRIORITY back to PROPERTIES and prefixes heading with [KEY-###]."
  (interactive)
  (org-linear--assert-auth)
  (save-excursion
    (org-back-to-heading t)
    (let* ((default-team (or team-id
                             (save-excursion
                               (catch 'found
                                 (let ((here (point)))
                                   (while (ignore-errors (outline-up-heading 1 t))
                                     (let ((id (org-entry-get (point) "TEAM_ID")))
                                       (when id (throw 'found id))))
                                   (goto-char here))
                                 nil))))
           (team   (org-linear--read-team default-team))
           (title  (org-linear--org-subtree-title))
           (body   (org-linear--org-subtree-body))
           (state  (org-linear--read-state team))
           (assn   (org-linear--read-assignee team))
           (prio   (org-linear--read-priority))
           (issue  (org-linear--issue-create team title body assn state prio))
           (identifier (alist-get 'identifier issue))
           (url        (alist-get 'url issue))
           (state-name (org-linear--alist-get-in '(state name) issue))
           (assignee   (or (org-linear--alist-get-in '(assignee name) issue)
                           (org-linear--alist-get-in '(assignee displayName) issue)
                           "—"))
           (priority   (alist-get 'priority issue)))
      ;; Update PROPERTIES
      (org-set-property "LINEAR_ID" (alist-get 'id issue))
      (org-set-property "URL"       (or url ""))
      (org-set-property "STATE"     (or state-name ""))
      (org-set-property "ASSIGNEE"  assignee)
      (org-set-property "PRIORITY"  (if priority (number-to-string priority) ""))
      ;; Update heading to include identifier prefix
      (let* ((current (org-get-heading t t t t))
             (new     (if (string-match-p (rx bol "[" (+ (not ?\])) "] ") current)
                          current
                        (format "[%s] %s" identifier current))))
        (org-edit-headline new))
      (message "Created Linear issue %s → %s" identifier url))))

;;;; Configuration for bidirectional sync

(defcustom org-linear-auto-sync t
  "Whether to automatically sync Org property changes to Linear.
When enabled, changes to STATE, ASSIGNEE, and PRIORITY properties
will automatically sync to Linear."
  :type 'boolean
  :group 'org-linear)

(defcustom org-linear-auto-sync-properties '("STATE" "ASSIGNEE" "PRIORITY")
  "List of properties that trigger automatic sync when changed."
  :type '(repeat string)
  :group 'org-linear)

(defcustom org-linear-conflict-resolution 'prompt
  "How to handle sync conflicts.
'prompt - Ask user what to do
'linear-wins - Always use Linear values
'org-wins - Always use Org values"
  :type '(choice (const :tag "Prompt user" prompt)
                 (const :tag "Linear wins" linear-wins)
                 (const :tag "Org wins" org-wins))
  :group 'org-linear)

;;;; Conflict detection and resolution

(defun org-linear--fetch-current-issue-state (linear-id)
  "Fetch current state of issue from Linear API."
  (let* ((q "query($id: String!) {
               issue(id: $id) {
                 id identifier title updatedAt
                 state { id name }
                 assignee { id name displayName }
                 priority
                 labels { nodes { id name color } }
               }
             }")
         (vars (let ((h (make-hash-table :test 'equal)))
                 (puthash "id" linear-id h) h))
         (data (org-linear--graphql q vars)))
    (alist-get 'issue data)))

(defun org-linear--detect-conflicts (linear-id org-state org-assignee org-priority)
  "Detect if Linear issue has changed since last sync.
Returns alist of conflicts or nil if no conflicts."
  (let* ((current-issue (org-linear--fetch-current-issue-state linear-id))
         (linear-state (org-linear--alist-get-in '(state name) current-issue))
         (linear-assignee (or (org-linear--alist-get-in '(assignee displayName) current-issue)
                             (org-linear--alist-get-in '(assignee name) current-issue)
                             "—"))
         (linear-priority (alist-get 'priority current-issue))
         (linear-priority-str (when linear-priority (number-to-string linear-priority)))
         (conflicts nil))

    ;; Check for conflicts (both sides have non-empty values that differ)
    (when (and org-state linear-state
               (not (string= (string-trim org-state) (string-trim linear-state))))
      (push `(state . ((org . ,org-state) (linear . ,linear-state))) conflicts))

    (when (and org-assignee linear-assignee
               (not (string= (string-trim org-assignee) (string-trim linear-assignee))))
      (push `(assignee . ((org . ,org-assignee) (linear . ,linear-assignee))) conflicts))

    (when (and org-priority linear-priority-str
               (not (string= (string-trim org-priority) (string-trim linear-priority-str))))
      (push `(priority . ((org . ,org-priority) (linear . ,linear-priority-str))) conflicts))

    conflicts))

(defun org-linear--resolve-conflicts (conflicts)
  "Resolve conflicts based on user configuration.
Returns alist of (property . resolved-value) pairs."
  (let ((resolutions nil))
    (dolist (conflict conflicts)
      (let* ((property (car conflict))
             (values (cdr conflict))
             (org-val (alist-get 'org values))
             (linear-val (alist-get 'linear values))
             (resolved-val
              (pcase org-linear-conflict-resolution
                ('linear-wins linear-val)
                ('org-wins org-val)
                ('prompt
                 (let ((choice (completing-read
                               (format "Conflict in %s. Choose value: " property)
                               `(,(format "Org: %s" org-val)
                                 ,(format "Linear: %s" linear-val))
                               nil t)))
                   (if (string-prefix-p "Org:" choice) org-val linear-val))))))
        (push `(,property . ,resolved-val) resolutions)))
    resolutions))

;;;; Automatic sync hooks

(defvar org-linear--sync-in-progress nil
  "Flag to prevent recursive sync calls.")

(defun org-linear--property-changed-hook (property new-value)
  "Hook function called when an Org property changes.
PROPERTY is the name of the property, NEW-VALUE is the new value."
  (when (and org-linear-auto-sync
             (not org-linear--sync-in-progress)
             (member property org-linear-auto-sync-properties))
    ;; Check if we're in a heading with a LINEAR_ID
    (when (org-entry-get (point) "LINEAR_ID")
      (condition-case err
          (progn
            (setq org-linear--sync-in-progress t)
            (org-linear-sync-to-linear)
            (setq org-linear--sync-in-progress nil))
        (error
         (setq org-linear--sync-in-progress nil)
         (message "Auto-sync failed: %s" (error-message-string err)))))))

;; Add our hook to org-property-changed-functions
(add-hook 'org-property-changed-functions #'org-linear--property-changed-hook)

;;;; Bidirectional sync commands

;;;###autoload
(defun org-linear--map-todo-to-state (todo-kw team-id)
  "Map Org TODO-KW to Linear state name using `org-linear-state-alist'.
TEAM-ID is used to verify the state exists in the team.
Returns the Linear state name or nil if no mapping found."
  (when todo-kw
    (let* ((linear-state (cdr (assoc todo-kw org-linear-state-alist)))
           (states (org-linear--team-states team-id)))
      ;; Verify the mapped state exists in the team's available states
      (when linear-state
        (or (car (cl-find-if (lambda (pair)
                              (string-equal-ignore-case (car pair) linear-state))
                            states))
            ;; If exact match not found, return the mapped value anyway
            linear-state)))))

(defun org-linear-sync-to-linear ()
  "Sync current Org heading's properties to Linear.
Updates Linear issue with current STATE, ASSIGNEE, PRIORITY, TODO keyword, and title from Org."
  (interactive)
  (org-linear--assert-auth)
  (save-excursion
    (org-back-to-heading t)
    (let* ((linear-id (org-entry-get (point) "LINEAR_ID"))
           (org-title (org-linear--extract-title-from-heading
                       (org-linear--org-subtree-title)))
           (todo-kw (org-get-todo-state))
           (org-priority-char (nth 3 (org-heading-components)))  ; Get priority character from heading
           (org-state (org-entry-get (point) "STATE"))
           (org-assignee (org-entry-get (point) "ASSIGNEE"))
           (org-priority-prop (org-entry-get (point) "PRIORITY"))
           (org-labels (org-entry-get (point) "LABELS")))

      (unless linear-id
        (user-error "No LINEAR_ID property on this heading"))

      ;; Check for conflicts before syncing
      (let* ((conflicts (org-linear--detect-conflicts linear-id org-state org-assignee org-priority-prop)))
        (when conflicts
          (let ((resolutions (org-linear--resolve-conflicts conflicts)))
            ;; Apply resolved values back to Org properties
            (dolist (resolution resolutions)
              (let ((property (car resolution))
                    (value (cdr resolution)))
                (pcase property
                  ('state (setq org-state value))
                  ('assignee (setq org-assignee value))
                  ('priority (setq org-priority-prop value)))))))

        ;; Get team ID for validation
        (let* ((team-id (org-linear--get-team-id-for-issue linear-id))
               ;; If TODO keyword exists and differs from STATE property, prefer TODO
               (effective-state (if todo-kw
                                   (org-linear--map-todo-to-state todo-kw team-id)
                                 org-state))
               ;; If org priority character exists, map it to Linear priority
               (effective-priority (if org-priority-char
                                      (number-to-string (org-linear--map-org-to-priority org-priority-char))
                                    org-priority-prop))
               (assignee-id (org-linear--validate-assignee org-assignee team-id))
               (state-id (org-linear--validate-state effective-state team-id))
               (priority (org-linear--validate-priority effective-priority))
               (label-ids (org-linear--validate-labels org-labels team-id))
               (has-changes (or org-title effective-state org-assignee effective-priority org-labels)))

          (unless team-id
            (user-error "Could not determine team for Linear issue %s" linear-id))

          (if has-changes
              (let* ((updated-issue (org-linear--issue-update
                                    linear-id
                                    org-title
                                    nil ; description - not syncing body for now
                                    assignee-id
                                    state-id
                                    priority
                                    label-ids))
                     (new-state (org-linear--alist-get-in '(state name) updated-issue))
                     (new-assignee (or (org-linear--alist-get-in '(assignee displayName) updated-issue)
                                      (org-linear--alist-get-in '(assignee name) updated-issue)
                                      "—"))
                     (new-priority (alist-get 'priority updated-issue))
                     (new-labels (alist-get 'labels updated-issue))
                     (new-labels-str (when new-labels
                                      (let ((nodes (alist-get 'nodes new-labels)))
                                        (mapconcat (lambda (label) (alist-get 'name label))
                                                  nodes
                                                  ", "))))
                     (identifier (alist-get 'identifier updated-issue)))

                ;; Update Org properties with confirmed Linear values
                (when new-state
                  (org-set-property "STATE" new-state)
                  ;; Update TODO keyword
                  (let ((todo-kw (org-linear--map-state-to-todo new-state)))
                    (when todo-kw
                      (org-todo todo-kw))))
                (org-set-property "ASSIGNEE" new-assignee)
                (when new-priority
                  (org-set-property "PRIORITY" (number-to-string new-priority))
                  ;; Update Org priority in heading
                  (let ((org-priority-char (org-linear--map-priority-to-org new-priority)))
                    (when org-priority-char
                      (org-priority org-priority-char))))
                (when new-labels-str
                  (org-set-property "LABELS" new-labels-str))

                ;; Add sync timestamp
                (org-set-property "LINEAR_LAST_SYNC"
                                 (format-time-string "%Y-%m-%d %H:%M:%S"))

                (message "Synced %s to Linear successfully" identifier))
            (message "No changes to sync to Linear")))))))

;;;###autoload
(defun org-linear-sync-from-linear ()
  "Pull latest changes from Linear for current issue and update Org properties."
  (interactive)
  (org-linear--assert-auth)
  (save-excursion
    (org-back-to-heading t)
    (let* ((linear-id (org-entry-get (point) "LINEAR_ID")))
      (unless linear-id
        (user-error "No LINEAR_ID property on this heading"))

      (let* ((current-issue (org-linear--fetch-current-issue-state linear-id))
             (linear-state (org-linear--alist-get-in '(state name) current-issue))
             (linear-assignee (or (org-linear--alist-get-in '(assignee displayName) current-issue)
                                 (org-linear--alist-get-in '(assignee name) current-issue)
                                 "—"))
             (linear-priority (alist-get 'priority current-issue))
             (linear-labels (alist-get 'labels current-issue))
             (linear-labels-str (when linear-labels
                                 (let ((nodes (alist-get 'nodes linear-labels)))
                                   (mapconcat (lambda (label) (alist-get 'name label))
                                             nodes
                                             ", "))))
             (identifier (alist-get 'identifier current-issue)))

        ;; Update Org properties with Linear values
        (when linear-state
          (org-set-property "STATE" linear-state)
          ;; Update TODO keyword
          (let ((todo-kw (org-linear--map-state-to-todo linear-state)))
            (when todo-kw
              (org-todo todo-kw))))
        (org-set-property "ASSIGNEE" linear-assignee)
        (when linear-priority
          (org-set-property "PRIORITY" (number-to-string linear-priority))
          ;; Update Org priority in heading
          (let ((org-priority-char (org-linear--map-priority-to-org linear-priority)))
            (when org-priority-char
              (org-priority org-priority-char))))
        (when linear-labels-str
          (org-set-property "LABELS" linear-labels-str))
        (org-set-property "LINEAR_LAST_SYNC"
                         (format-time-string "%Y-%m-%d %H:%M:%S"))

        (message "Updated %s from Linear" identifier)))))

;;;###autoload
(defun org-linear-sync-status ()
  "Show sync status for current Linear issue."
  (interactive)
  (save-excursion
    (org-back-to-heading t)
    (let* ((linear-id (org-entry-get (point) "LINEAR_ID"))
           (last-sync (org-entry-get (point) "LINEAR_LAST_SYNC"))
           (org-state (org-entry-get (point) "STATE"))
           (org-assignee (org-entry-get (point) "ASSIGNEE"))
           (org-priority (org-entry-get (point) "PRIORITY")))

      (unless linear-id
        (user-error "No LINEAR_ID property on this heading"))

      (let* ((current-issue (org-linear--fetch-current-issue-state linear-id))
             (linear-state (org-linear--alist-get-in '(state name) current-issue))
             (linear-assignee (or (org-linear--alist-get-in '(assignee displayName) current-issue)
                                 (org-linear--alist-get-in '(assignee name) current-issue)
                                 "—"))
             (linear-priority (alist-get 'priority current-issue))
             (linear-priority-str (when linear-priority (number-to-string linear-priority)))
             (identifier (alist-get 'identifier current-issue))
             (conflicts (org-linear--detect-conflicts linear-id org-state org-assignee org-priority)))

        (message "%s | Last sync: %s | %s"
                identifier
                (or last-sync "Never")
                (if conflicts
                    (format "CONFLICTS: %s" (mapconcat (lambda (c) (symbol-name (car c))) conflicts ", "))
                  "In sync"))))))

;;;###autoload
(defun org-linear-sync-subtree-to-linear ()
  "Sync all Linear issues under current heading to Linear.
Processes all child headings with LINEAR_ID properties."
  (interactive)
  (org-linear--assert-auth)
  (save-excursion
    (org-back-to-heading t)
    (let ((synced-count 0)
          (error-count 0))
      (org-map-entries
       (lambda ()
         (let ((linear-id (org-entry-get (point) "LINEAR_ID")))
           (when linear-id
             (condition-case err
                 (progn
                   (org-linear-sync-to-linear)
                   (cl-incf synced-count))
               (error
                (cl-incf error-count)
                (message "Error syncing %s: %s" linear-id (error-message-string err)))))))
       nil 'tree)
      (message "Synced %d issues to Linear (%d errors)" synced-count error-count))))

;;;###autoload
(defun org-linear-sync-subtree-from-linear ()
  "Sync all Linear issues under current heading from Linear.
Processes all child headings with LINEAR_ID properties."
  (interactive)
  (org-linear--assert-auth)
  (save-excursion
    (org-back-to-heading t)
    (let ((synced-count 0)
          (error-count 0))
      (org-map-entries
       (lambda ()
         (let ((linear-id (org-entry-get (point) "LINEAR_ID")))
           (when linear-id
             (condition-case err
                 (progn
                   (org-linear-sync-from-linear)
                   (cl-incf synced-count))
               (error
                (cl-incf error-count)
                (message "Error syncing %s: %s" linear-id (error-message-string err)))))))
       nil 'tree)
      (message "Synced %d issues from Linear (%d errors)" synced-count error-count))))

;;;; Minor mode & keymap

(defvar org-linear-mode-map
  (let ((m (make-sparse-keymap)))
    ;; Original commands
    (define-key m (kbd "C-c l i") #'org-linear-insert-issues-for-team)
    (define-key m (kbd "C-c l o") #'org-linear-open-at-point)
    (define-key m (kbd "C-c l r") #'org-linear-refresh-under-heading)
    (define-key m (kbd "C-c l c") #'org-linear-create-issue-from-subtree)
    ;; Bidirectional sync commands
    (define-key m (kbd "C-c l s") #'org-linear-sync-to-linear)
    (define-key m (kbd "C-c l p") #'org-linear-sync-from-linear)
    (define-key m (kbd "C-c l S") #'org-linear-sync-subtree-to-linear)
    (define-key m (kbd "C-c l ?") #'org-linear-sync-status)
    ;; User issues
    (define-key m (kbd "C-c l u") #'org-linear-insert-issues-for-current-user)
    m)
  "Keymap for `org-linear-mode`.")

;;;###autoload
(define-minor-mode org-linear-mode
  "Minor mode with keybindings for Linear ↔ Org workflows."
  :init-value nil
  :lighter " LinearOrg"
  :keymap org-linear-mode-map)

;;; Fetch issues assigned to current user

(defun org-linear--current-user-id ()
  "Return the current authenticated user's Linear ID."
  (let* ((q "query { viewer { id } }")
         (data (org-linear--graphql q)))
    (org-linear--alist-get-in '(viewer id) data)))

(defun org-linear--issues-for-current-user ()
  "Return a list of open issues assigned to the current user."
  (let* ((user-id (org-linear--current-user-id))
         (query
          "query($assigneeId: ID!, $first: Int!, $after: String) {
             issues(
               filter: { assignee: { id: { eq: $assigneeId } }, state: { type: { neq: \"canceled\" } } }
               orderBy: updatedAt
               first: $first
               after: $after
             ) {
               pageInfo { hasNextPage endCursor }
               nodes {
                 id identifier title url
                 state { id name type }
                 priority
                 assignee { id name displayName }
                 labels { nodes { id name color } }
                 createdAt updatedAt
               }
             }
           }")
         (results nil)
         (after nil)
         (guard 0)
         has-next prev-cursor)
    (setq has-next t)
    (while (and has-next (< guard 500))
      (cl-incf guard)
      (let* ((vars (let ((ht (make-hash-table :test 'equal)))
                     (puthash "assigneeId" user-id ht)
                     (puthash "first" (or org-linear-issues-page-size 50) ht)
                     (when after (puthash "after" after ht))
                     ht))
             (data (org-linear--graphql query vars))
             (issues (alist-get 'issues data))
             (page (alist-get 'pageInfo issues))
             (nodes (alist-get 'nodes issues)))
        (setq results (nconc results (append nodes nil)))
        (setq prev-cursor after
              after (alist-get 'endCursor page)
              has-next (org-linear--truthy (alist-get 'hasNextPage page)))
        (when (and (not has-next) (equal after prev-cursor))
          (setq has-next nil))))
    results))

;;;###autoload
(defun org-linear-download-all-teams ()
  "Download all team issues to separate files in `org-linear-directory'.
Each team's issues are saved to [TEAM_KEY].org in the directory.
Files are overwritten if they already exist."
  (interactive)
  (org-linear--assert-auth)
  (let* ((teams (org-linear--teams))
         (total-teams (length teams))
         (team-count 0))
    (unless teams
      (user-error "No teams found"))

    (message "Downloading issues for %d team(s)..." total-teams)

    (dolist (team-pair teams)
      (cl-incf team-count)
      (let* ((display (car team-pair))
             (team-id (cdr team-pair))
             ;; Extract name and key from display string "Name (KEY)"
             (name-key (if (string-match "\\(.*\\) (\\([^)]+\\))" display)
                          (cons (match-string 1 display) (match-string 2 display))
                        (cons display display)))
             (team-name (car name-key))
             (team-key (cdr name-key))
             (file-path (org-linear--team-file-path team-name team-key))
             (issues (org-linear--issues-for-team team-id)))

        (message "[%d/%d] Downloading %s (%d issues)..."
                 team-count total-teams team-name (length issues))

        (with-temp-file file-path
          (insert (format "#+TITLE: %s Linear Issues\n" team-name))
          (insert (format "#+AUTHOR: Linear\n"))
          (insert (format "#+DATE: %s\n" (format-time-string "%Y-%m-%d %H:%M:%S")))
          (insert (format "#+PROPERTY: TEAM_ID %s\n" team-id))
          (insert (format "#+PROPERTY: TEAM_NAME %s\n" team-name))
          (insert (format "#+PROPERTY: TEAM_KEY %s\n\n" team-key))

          (if issues
              (dolist (iss issues)
                (pcase-let* ((`(,todo-kw ,org-priority ,tags ,headline ,props)
                             (org-linear--issue->org-heading iss)))
                  (org-linear--insert-org-heading todo-kw org-priority tags headline props)))
            (insert "No issues found.\n")))

        (message "[%d/%d] Saved %s to %s"
                 team-count total-teams team-name (file-name-nondirectory file-path))))

    (message "Downloaded issues for %d team(s) to %s"
             total-teams (expand-file-name org-linear-directory))))

;;;###autoload
(defun org-linear-insert-issues-for-current-user ()
  "Insert open Linear issues assigned to the current user as Org headings."
  (interactive)
  (org-linear--assert-auth)
  (let* ((issues (org-linear--issues-for-current-user)))
    (unless issues
      (user-error "No issues assigned to current user"))
    (save-excursion
      (unless (org-before-first-heading-p)
        (org-back-to-heading t)
        (org-end-of-subtree t t)
        (unless (bolp) (insert "\n")))
      (insert (format "* Linear Issues assigned to me\n"))
      (dolist (iss issues)
        (pcase-let* ((`(,todo-kw ,org-priority ,tags ,headline ,props) (org-linear--issue->org-heading iss)))
          (org-linear--insert-org-heading todo-kw org-priority tags headline props)))
      (message "Inserted %d issues assigned to current user" (length issues)))))

(provide 'org-linear)
;;; org-linear.el ends here
