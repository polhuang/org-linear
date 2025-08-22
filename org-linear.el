(require 'json)
(require 'request)
(require 'org)

(defgroup linear-org nil
  "Integration with Linear"
  :group 'tools)

(defcustom linear-api-key ""
  "API key for accessing the Linear API."
  :type 'string
  :group 'linear-org)

(defcustom linear-workspace-id ""
  "Workspace ID for Linear (used for fetching public issues)."
  :type 'string
  :group 'linear-org)

(defcustom linear-client-id "195109b12876be343bad55f93cb30172"
  "Client ID for Linear OAuth2 application."
  :type 'string
  :group 'linear-org)

(defcustom linear-client-secret "d3ee010b6a76ff78a1e1cacaeb352356"
  "Client secret for Linear OAuth2 application."
  :type 'string
  :group 'linear-org)

(defcustom linear-oauth-redirect-uri "http://localhost"
  "Redirect URI for Linear OAuth2 authentication."
  :type 'string
  :group 'linear-org)

(defcustom linear-graphql-endpoint "https://api.linear.app/graphql"
  "Linear GraphQL endpoint."
  :type 'string
  :group 'linear-org)


;;;###autoload
(defun linear-oauth-authorize ()
  "Start the OAuth2 authorization process for Linear."
  (interactive)
  (if (or (string-empty-p linear-client-id)
          (string-empty-p linear-client-secret))
      (message "linear-client-id and linear-client-secret must be set")
    (let* ((state (format "%06x" (random (expt 16 6))))
           (url (format (concat "https://linear.app/oauth/authorize"
                              "?client_id=%s"
                              "&redirect_uri=%s"
                              "&response_type=code"
                              "&scope=read,write"
                              "&state=%s")
                       linear-client-id
                       (url-hexify-string linear-oauth-redirect-uri)
                       state)))
      ;; Store state for later verification
      (setq linear-oauth-state state)
      (browse-url url))))

(defun linear-oauth-exchange-code (code)
  "Exchange authorization CODE for an access token."
  (request
   "https://api.linear.app/oauth/token"
   :type "POST"
   :headers '(("Content-Type" . "application/x-www-form-urlencoded"))
   :data (format (concat "code=%s"
                        "&redirect_uri=%s"
                        "&client_id=%s"
                        "&client_secret=%s"
                        "&grant_type=authorization_code")
                 code
                 (url-hexify-string linear-oauth-redirect-uri)
                 linear-client-id
                 linear-client-secret)
   :parser 'json-read
   :success (cl-function
             (lambda (&key data &allow-other-keys)
               (let ((access-token (alist-get 'access_token data)))
                 (setq linear-api-key access-token)
                 (message "Successfully authenticated with Linear!"))))
   :error (cl-function
           (lambda (&key error-thrown &allow-other-keys)
             (message "Error exchanging code for token: %S" error-thrown)))))

;;;###autoload
(defun linear-oauth-callback-server ()
  "Start a local server to handle the OAuth callback."
  (interactive)
  (require 'simple-httpd)
  (setq httpd-port 8080)
  (httpd-start)
  (defservlet callback text/plain (path query)
    (let ((code (cadr (assoc "code" query)))
          (state (cadr (assoc "state" query))))
      (if (and code state (string= state linear-oauth-state))
          (progn
            (linear-oauth-exchange-code code)
            (insert "Authentication successful! You can close this window."))
        (insert "Authentication failed. Invalid state parameter.")))))

(defun linear--assert-auth ()
  "Signal an error if no API key is present."
  (when (string-empty-p (string-trim (or linear-api-key "")))
    (user-error "No Linear API key found. Run `linear-oauth-authorize' or set `linear-api-key'")))

(defun linear--graphql (query &optional variables)
  "Execute a synchronous GraphQL REQUEST with QUERY and VARIABLES.
Returns parsed JSON as an alist, or signals an error."
  (linear--assert-auth)
  (let (resp err)
    (request
     linear-graphql-endpoint
     :type "POST"
     :sync t
     :headers `(("Content-Type" . "application/json")
                ("Authorization" . ,(concat "Bearer " linear-api-key)))
     :data (json-encode `(("query" . ,query)
                          ("variables" . ,(or variables (make-hash-table :test 'equal)))))
     :parser 'json-read
     :success (cl-function (lambda (&key data &allow-other-keys) (setq resp data)))
     :error   (cl-function (lambda (&key error-thrown &allow-other-keys) (setq err error-thrown))))
    (when err
      (error "Linear GraphQL request failed: %S" err))
    (let* ((errors (alist-get 'errors resp))
           (first-error (and (vectorp errors) (> (length errors) 0) (aref errors 0)))
           (message (and (consp first-error) (alist-get 'message first-error))))
      (when message
        (error "Linear GraphQL error: %s" message)))
    (alist-get 'data resp)))

(defun linear--teams ()
  "Return a list of teams as ((display . id) ...)."
  (let* ((q "query { teams(first: 100) { nodes { id name key } } }")
         (data (linear--graphql q))
         (nodes (alist-get 'nodes (alist-get 'teams data))))
    (mapcar (lambda (node)
              (let ((id (alist-get 'id node))
                    (name (alist-get 'name node))
                    (key (alist-get 'key node)))
                (cons (format "%s (%s)" name key) id)))
            (append nodes nil))))

(provide 'linear-org)
;;; linear-org.el ends here
