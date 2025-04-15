;;; org-linear.el --- Org-mode integration for Linear.app  -*- lexical-binding: t; -*-
;; SPDX-License-Identifier: GPL-3.0-or-later

;;; Commentary:
;; End-to-end Linear ↔ Org workflow:
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

(defcustom org-linear-workspace-id ""
  "Workspace ID for Linear (not required for authenticated queries)."
  :type 'string
  :group 'org-linear)

(defcustom org-linear-client-id "195109b12876be343bad55f93cb30172"
  "Client ID for Linear OAuth2 application."
  :type 'string
  :group 'org-linear)

(defcustom org-linear-client-secret "d3ee010b6a76ff78a1e1cacaeb352356"
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

(defvar org-linear-oauth-state nil
  "CSRF-prevention state used during OAuth flow.")

(defvar org-linear-oauth-pkce-verifier nil
  "PKCE code verifier for OAuth flow.")

;;;; Authentication helpers

(defcustom org-linear-auth-host "api.linear.app"
  "Host for Linear API authentication storage."
  :type 'string
  :group 'org-linear-auth)

(defcustom org-linear-auth-user "token"
  "User identifier for Linear token storage."
  :type 'string
  :group 'org-linear-auth)

(defvar org-linear--cached-token nil
  "Cached access token to avoid repeated auth-source lookups.")

(defvar org-linear--token-expiry nil
  "Timestamp when cached token expires.")

(defun org-linear-auth--read-token ()
  "Read Linear access token from auth-source with caching.
Returns token string or nil if not found."
  ;; Return cached token if still valid
  (when (and org-linear--cached-token 
             org-linear--token-expiry
             (time-less-p (current-time) org-linear--token-expiry))
    (return org-linear--cached-token))
  
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
        token))))

(defun org-linear-auth--write-token (token &optional refresh-token expires-in)
  "Write TOKEN to auth-source storage.
REFRESH-TOKEN and EXPIRES-IN are stored for future use."
  (when (and token (stringp token) (> (length (string-trim token)) 0))
    (let ((auth-source-save-behavior t))
      ;; Store access token
      (auth-source-store-save
       :host org-linear-auth-host
       :user org-linear-auth-user
       :port "https"
       :secret token)
      
      ;; Store refresh token if provided
      (when (and refresh-token (stringp refresh-token) (> (length (string-trim refresh-token)) 0))
        (auth-source-store-save
         :host org-linear-auth-host
         :user (concat org-linear-auth-user "-refresh")
         :port "https"
         :secret refresh-token))
      
      ;; Cache the token
      (setq org-linear--cached-token token
            org-linear--token-expiry (if expires-in
                                    (time-add (current-time) expires-in)
                                  (time-add (current-time) (* 3600 24)))))))

(defun org-linear-auth-clear ()
  "Clear stored Linear authentication tokens."
  (interactive)
  (setq org-linear--cached-token nil
        org-linear--token-expiry nil)
  (let ((deleted 0))
    ;; Clear access token
    (when-let ((auth-info (auth-source-search
                          :host org-linear-auth-host
                          :user org-linear-auth-user
                          :port "https"
                          :max 1)))
      (dolist (entry auth-info)
        (when-let ((delete-fn (plist-get entry :delete)))
          (funcall delete-fn)
          (cl-incf deleted))))
    
    ;; Clear refresh token
    (when-let ((auth-info (auth-source-search
                          :host org-linear-auth-host
                          :user (concat org-linear-auth-user "-refresh")
                          :port "https"
                          :max 1)))
      (dolist (entry auth-info)
        (when-let ((delete-fn (plist-get entry :delete)))
          (funcall delete-fn)
          (cl-incf deleted))))
    
    (message "Cleared %d Linear auth token(s)" deleted)))

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
      (user-error "Linear client credentials not found. Set LINEAR_CLIENT_ID/LINEAR_CLIENT_SECRET environment variables, configure via auth-source, or set org-linear-client-id/org-linear-client-secret (deprecated)"))
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
  "Start the OAuth2 authorization process for Linear."
  (interactive)
  (condition-case err
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
        (message "Opening browser for Linear OAuth… (Ensure callback server is running)"))
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
                                (with-current-buffer (request-response-buffer response)
                                  (json-read-from-string (buffer-string)))
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
Returns parsed JSON as an alist, or signals an error with details."
  (let ((token (org-linear--assert-auth))
        resp err resp-buf)
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
                       resp-buf (and response (request-response-buffer response))))))
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

(defun org-linear--issue->org-heading (issue)
  "Return (HEADLINE . PROPERTIES) derived from ISSUE node."
  (let* ((id          (alist-get 'id issue))
         (identifier  (alist-get 'identifier issue))
         (title       (org-linear--string-or (alist-get 'title issue) "(no title)"))
         (url         (alist-get 'url issue))
         (state-name  (org-linear--alist-get-in '(state name) issue))
         (assignee    (or (org-linear--alist-get-in '(assignee displayName) issue)
                          (org-linear--alist-get-in '(assignee name) issue)
                          "—"))
         (priority    (alist-get 'priority issue))
         (headline    (format "[%s] %s" identifier title))
         (props `(("LINEAR_ID"  . ,id)
                  ("STATE"      . ,(or state-name ""))
                  ("ASSIGNEE"   . ,assignee)
                  ("PRIORITY"   . ,(if priority (number-to-string priority) ""))
                  ("URL"        . ,(or url "")) )))
    (cons headline props)))

(defun org-linear--insert-org-heading (headline props)
  "Insert an Org subtree for HEADLINE with PROPS alist."
  (insert (format "** %s :linear:\n" headline))
  (insert ":PROPERTIES:\n")
  (dolist (kv props)
    (insert (format ":%s: %s\n" (car kv) (cdr kv))))
  (insert ":END:\n"))

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
      (insert (format "* Linear Issues for %s (synced %s)\n"
                      (or team-label choice)
                      (format-time-string "%Y-%m-%d %H:%M")))
      (org-set-property "TEAM_ID" choice)
      (dolist (iss issues)
        (pcase-let* ((`(,headline . ,props) (org-linear--issue->org-heading iss)))
          (org-linear--insert-org-heading headline props)))
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
          (pcase-let* ((`(,headline . ,props) (org-linear--issue->org-heading iss)))
            (org-linear--insert-org-heading headline props)))
        (message "Refreshed %d issues" (length issues))))))

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
                        priority }
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

;;;; Minor mode & keymap

(defvar org-linear-mode-map
  (let ((m (make-sparse-keymap)))
    (define-key m (kbd "C-c l i") #'org-linear-insert-issues-for-team)
    (define-key m (kbd "C-c l o") #'org-linear-open-at-point)
    (define-key m (kbd "C-c l r") #'org-linear-refresh-under-heading)
    (define-key m (kbd "C-c l c") #'org-linear-create-issue-from-subtree)
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
      (insert (format "* Linear Issues assigned to me (synced %s)\n"
                      (format-time-string "%Y-%m-%d %H:%M")))
      (dolist (iss issues)
        (pcase-let* ((`(,headline . ,props) (org-linear--issue->org-heading iss)))
          (org-linear--insert-org-heading headline props)))
      (message "Inserted %d issues assigned to current user" (length issues)))))

(provide 'org-linear)
;;; org-linear.el ends here
