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

;;;; Teams

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


;;;; Issues -> Org

(defun linear--string-or (s fallback)
  "Trim S to a string, else FALLBACK."
  (let ((v (and s (stringp s) (string-trim s))))
    (if (and v (> (length v) 0)) v fallback)))

(defun linear--issues-for-team (team-id)
  "Return a list of issue nodes for TEAM-ID (handles pagination)."
  (let ((query
         "query($teamId: String!, $first: Int!, $after: String) {
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
    (let (results after has-next)
      (setq has-next t)
      (while has-next
        (let* ((vars (let ((ht (make-hash-table :test 'equal)))
                       (puthash "teamId" team-id ht)
                       (puthash "first" (or linear-issues-page-size 50) ht)
                       (when after (puthash "after" after ht))
                       ht))
               (data (linear--graphql query vars))
               (issues (linear--alist-get-in '(issues nodes) data))
               (page   (linear--alist-get-in '(issues pageInfo) data)))
          (setq results (nconc results (append issues nil)))
          (setq has-next (alist-get 'hasNextPage page))
          (setq after    (alist-get 'endCursor page))))
      results)))

(defun linear--issue->org-heading (issue)
  "Return (HEADLINE . PROPERTIES) derived from ISSUE node."
  (let* ((id          (alist-get 'id issue))
         (identifier  (alist-get 'identifier issue))
         (title       (linear--string-or (alist-get 'title issue) "(no title)"))
         (url         (alist-get 'url issue))
         (state-name  (linear--alist-get-in '(state name) issue))
         (assignee    (or (linear--alist-get-in '(assignee displayName) issue)
                          (linear--alist-get-in '(assignee name) issue)
                          "—"))
         (priority    (alist-get 'priority issue))
         (headline    (format "[%s] %s" identifier title))
         (props `(("LINEAR_ID"  . ,id)
                  ("STATE"      . ,(or state-name ""))
                  ("ASSIGNEE"   . ,assignee)
                  ("PRIORITY"   . ,(if priority (number-to-string priority) ""))
                  ("URL"        . ,(or url "")) )))
    (cons headline props)))

(defun linear--insert-org-heading (headline props)
  "Insert an Org subtree for HEADLINE with PROPS alist."
  (insert (format "** %s :linear:\n" headline))
  (insert ":PROPERTIES:\n")
  (dolist (kv props)
    (insert (format ":%s: %s\n" (car kv) (cdr kv))))
  (insert ":END:\n"))


;;;###autoload
(defun linear-org-insert-issues-for-team (&optional team-id)
  "Prompt for a Linear TEAM-ID (or use TEAM-ID) and insert its open issues as Org headings.
Each issue becomes a `**` heading with useful PROPERTIES and a clickable URL."
  (interactive)
  (linear--assert-auth)
  (let* ((choice (or team-id
                     (let* ((pairs (linear--teams))
                            (name (completing-read "Linear team: " (mapcar #'car pairs) nil t)))
                       (cdr (assoc name pairs)))))
         (issues (linear--issues-for-team choice))
         (team-label (car (rassoc choice (linear--teams)))))
    (unless issues
      (user-error "No issues returned for that team"))
    (save-excursion
      ;; Insert a parent heading; user can move it as desired.
      (unless (org-before-first-heading-p)
        (org-back-to-heading t)
        (org-end-of-subtree t t)
        (unless (bolp) (insert "\n")))
      (insert (format "* Linear Issues for %s (synced %s)\n"
                      (or team-label choice)
                      (format-time-string "%Y-%m-%d %H:%M")))
      ;; Store TEAM_ID so refresh can work later.
      (org-set-property "TEAM_ID" choice)
      (dolist (iss issues)
        (pcase-let* ((`(,headline . ,props) (linear--issue->org-heading iss)))
          (linear--insert-org-heading headline props)))
      (message "Inserted %d issues for team %s" (length issues) (or team-label choice)))))

;;;###autoload
(defun linear-org-open-at-point ()
  "Open the Linear issue URL for the Org heading at point."
  (interactive)
  (let ((url (org-entry-get (point) "URL")))
    (if (and url (string-match-p "^https?://" url))
        (browse-url url)
      (user-error "No URL property on this heading"))))

;;;###autoload
(defun linear-org-refresh-under-heading ()
  "Re-sync issues for the team of the current parent heading, replacing `**` entries.
Relies on a TEAM_ID property at the parent level."
  (interactive)
  (save-excursion
    (org-back-to-heading t)
    (let* ((parent (point))
           (team-id (org-entry-get parent "TEAM_ID")))
      (unless team-id
        (user-error "No TEAM_ID on this heading; re-run `linear-org-insert-issues-for-team`"))
      ;; Remove existing level-2 children beneath this parent:
      (org-map-entries
       (lambda ()
         (when (= (org-current-level) 2)
           (org-cut-subtree)))
       nil 'children)
      ;; Reinsert fresh data:
      (let ((issues (linear--issues-for-team team-id)))
        (dolist (iss issues)
          (pcase-let* ((`(,headline . ,props) (linear--issue->org-heading iss)))
            (linear--insert-org-heading headline props)))
        (message "Refreshed %d issues" (length issues))))))

;;;; Minor mode & keymap

(defvar linear-org-mode-map
  (let ((m (make-sparse-keymap)))
    (define-key m (kbd "C-c l i") #'linear-org-insert-issues-for-team)
    (define-key m (kbd "C-c l o") #'linear-org-open-at-point)
    (define-key m (kbd "C-c l r") #'linear-org-refresh-under-heading)
    m)
  "Keymap for `linear-org-mode`.")

;;;###autoload
(define-minor-mode linear-org-mode
  "Minor mode with keybindings for Linear ↔ Org workflows."
  :init-value nil
  :lighter " LinearOrg"
  :keymap linear-org-mode-map)


(provide 'linear-org)
;;; linear-org.el ends here
