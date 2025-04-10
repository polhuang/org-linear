;;; linear-org.el --- Org-mode integration for Linear.app  -*- lexical-binding: t; -*-
;; SPDX-License-Identifier: GPL-3.0-or-later

;;; Commentary:
;; End-to-end Linear ↔ Org workflow:
;; - OAuth (authorize, local callback, token exchange)
;; - GraphQL helper (error details, sane encoding)
;; - Insert team issues into Org as headings
;; - Open issue URL from heading
;; - Refresh issues under a parent heading
;; - Create a Linear issue from current Org subtree (writes PROPERTIES, renames heading)
;;
;; Quick start:
;;   (require 'linear-org)
;;   M-x linear-oauth-callback-server     ;; http://localhost:8080/linear-callback
;;   M-x linear-oauth-authorize
;;   M-x linear-org-insert-issues-for-team
;;   (Optional) Turn on minor mode in Org buffers for keybindings:
;;     (add-hook 'org-mode-hook #'linear-org-mode)

;;; Code:

(require 'json)
(require 'request)
(require 'org)
(require 'cl-lib)        ;; cl-function, cl-reduce
(require 'subr-x)        ;; string-empty-p, string-trim
(require 'simple-httpd)  ;; defservlet / httpd-start

(defgroup linear-org nil
  "Integration with Linear."
  :group 'tools)

;;;; Configuration

(defcustom linear-graphql-endpoint "https://api.linear.app/graphql"
  "Linear GraphQL endpoint."
  :type 'string
  :group 'linear-org)

(defcustom linear-api-key ""
  "API key (OAuth access token) for accessing the Linear API."
  :type 'string
  :group 'linear-org)

(defcustom linear-workspace-id ""
  "Workspace ID for Linear (not required for authenticated queries)."
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

(defcustom linear-oauth-redirect-uri "http://localhost:8080/linear-callback"
  "Redirect URI for Linear OAuth2 authentication (must match app settings)."
  :type 'string
  :group 'linear-org)

(defcustom linear-issues-page-size 50
  "How many issues to fetch per GraphQL page."
  :type 'integer
  :group 'linear-org)

(defvar linear-oauth-state nil
  "CSRF-prevention state used during OAuth flow.")

;;;; OAuth: top-level servlet + helpers

;; Handler at: http://localhost:8080/linear-callback
(defservlet linear-callback text/plain (path query)
  (let ((code  (cadr (assoc "code" query)))
        (state (cadr (assoc "state" query))))
    (cond
     ((not (and code state))
      (insert "Authentication failed: missing code/state."))
     ((not (string= state linear-oauth-state))
      (insert "Authentication failed: invalid state."))
     (t
      (linear-oauth-exchange-code code)
      (insert "Authentication successful! You can close this window.")))))

;;;###autoload
(defun linear-oauth-callback-server ()
  "Start a local HTTP server for Linear OAuth at /linear-callback."
  (interactive)
  (setq httpd-port 8080)
  (httpd-start)
  (message "Listening for Linear OAuth callback at http://localhost:%d/linear-callback" httpd-port))

;;;###autoload
(defun linear-oauth-callback-server-stop ()
  "Stop the local HTTP server used for Linear OAuth."
  (interactive)
  (httpd-stop)
  (message "Stopped OAuth callback server."))

;;;###autoload
(defun linear-oauth-authorize ()
  "Start the OAuth2 authorization process for Linear."
  (interactive)
  (if (or (string-empty-p (string-trim (or linear-client-id "")))
          (string-empty-p (string-trim (or linear-client-secret ""))))
      (message "linear-client-id and linear-client-secret must be set")
    (let* ((state (format "%06x" (random (expt 16 6))))
           (url (format (concat "https://linear.app/oauth/authorize"
                                "?client_id=%s"
                                "&redirect_uri=%s"
                                "&response_type=code"
                                "&scope=read,write"
                                "&state=%s")
                        (url-hexify-string linear-client-id)
                        (url-hexify-string linear-oauth-redirect-uri)
                        (url-hexify-string state))))
      (setq linear-oauth-state state)
      (browse-url url)
      (message "Opening browser for Linear OAuth… (Ensure callback server is running)"))))

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
                 (url-hexify-string code)
                 (url-hexify-string linear-oauth-redirect-uri)
                 (url-hexify-string linear-client-id)
                 (url-hexify-string linear-client-secret))
   :parser 'json-read
   :success (cl-function
             (lambda (&key data &allow-other-keys)
               (let ((access-token (alist-get 'access_token data)))
                 (setq linear-api-key (string-trim (or access-token "")))
                 (message "Successfully authenticated with Linear!"))))
   :error (cl-function
           (lambda (&key error-thrown &allow-other-keys)
             (message "Error exchanging code for token: %S" error-thrown)))))

;;;; GraphQL core

(defun linear--assert-auth ()
  "Signal an error if no API key is present."
  (when (string-empty-p (string-trim (or linear-api-key "")))
    (user-error "No Linear API key found. Run `linear-oauth-authorize' or set `linear-api-key'")))

(defun linear--alist-get-in (keys alist)
  "Return nested value by KEYS from ALIST/hash-tables."
  (cl-reduce (lambda (acc k)
               (cond
                ((hash-table-p acc) (gethash k acc))
                ((listp acc)        (alist-get k acc))
                (t nil)))
             keys :initial-value alist))

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
                ("Authorization" . ,(concat "Bearer " (string-trim linear-api-key))))
     :data (json-encode `(("query" . ,query)
                          ("variables" . ,(or variables (make-hash-table :test 'equal)))))
     :parser 'json-read
     :success (cl-function (lambda (&key data &allow-other-keys) (setq resp data)))
     :error   (cl-function (lambda (&key error-thrown &allow-other-keys) (setq err error-thrown))))
    (when err
      (error "Linear GraphQL request failed: %S" err))
    (let* ((errors (alist-get 'errors resp))
           (first-error (and (vectorp errors) (> (length errors) 0) (aref errors 0)))
           (msg (and (consp first-error) (alist-get 'message first-error))))
      (when msg
        (error "Linear GraphQL error: %s" msg)))
    (alist-get 'data resp)))

;;;; Common helpers

(defun linear--string-or (s fallback)
  "Trim S to a string, else FALLBACK."
  (let ((v (and s (stringp s) (string-trim s))))
    (if (and v (> (length v) 0)) v fallback)))

(defun linear--truthy (x)
  "Return non-nil iff JSON boolean X is true."
  (and x (not (eq x json-false))))

;;;; Teams

(defun linear--teams ()
  "Return a list of teams as ((DISPLAY . ID) ...)."
  (let* ((q "query { teams(first: 100) { nodes { id name key } } }")
         (data  (linear--graphql q))
         (nodes (alist-get 'nodes (alist-get 'teams data))))
    (mapcar (lambda (node)
              (let ((id   (alist-get 'id node))
                    (name (alist-get 'name node))
                    (key  (alist-get 'key node)))
                (cons (format "%s (%s)" name key) id)))
            (append nodes nil))))

(defun linear--team-states (team-id)
  "Return ((DISPLAY . ID) ...) for workflow states of TEAM-ID."
  ;; NB: team(id: …) expects String!, not ID!
  (let* ((q "query($id: String!) {
               team(id:$id){
                 states(first:100){ nodes { id name type } }
               }
             }")
         (vars (let ((h (make-hash-table :test 'equal))) (puthash "id" team-id h) h))
         (data (linear--graphql q vars))
         (nodes (linear--alist-get-in '(team states nodes) data)))
    (mapcar (lambda (node)
              (let ((id (alist-get 'id node))
                    (nm (alist-get 'name node))
                    (tp (alist-get 'type node)))
                (cons (format "%s (%s)" nm tp) id)))
            (append nodes nil))))

;;;; Workspace users (assignees)

(defun linear--users (&optional n)
  "Return ((DISPLAY . ID) ...) for workspace users (active first). N defaults to 200."
  (let* ((q "query($first:Int!){
               users(first:$first){
                 nodes{ id name displayName active }
               }
             }")
         (vars (let ((h (make-hash-table :test 'equal)))
                 (puthash "first" (or n 200) h) h))
         (data  (linear--graphql q vars))
         (nodes (alist-get 'nodes (alist-get 'users data))))
    (let* ((vec (append nodes nil))
           (active (seq-filter (lambda (u) (linear--truthy (alist-get 'active u))) vec))
           (inactive (seq-remove (lambda (u) (linear--truthy (alist-get 'active u))) vec))
           (ordered (append active inactive)))
      (mapcar (lambda (u)
                (let* ((id (alist-get 'id u))
                       (nm (or (alist-get 'displayName u)
                               (alist-get 'name u)
                               id)))
                  (cons nm id)))
              ordered))))

;;;; Issues → Org

(defun linear--issues-for-team (team-id)
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
                       (puthash "first" (or linear-issues-page-size 50) ht)
                       (when after (puthash "after" after ht))
                       ht))
               (data   (linear--graphql query vars))
               (issues (alist-get 'issues data))
               (page   (alist-get 'pageInfo issues))
               (nodes  (alist-get 'nodes issues)))
          (setq results (nconc results (append nodes nil)))
          (setq prev-cursor after
                after    (alist-get 'endCursor page)
                has-next (linear--truthy (alist-get 'hasNextPage page)))
          (when (and (not has-next) (equal after prev-cursor))
            (setq has-next nil))))
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
         (props `(("LINEAR_ID"    . ,id)
                  ("STATE"        . ,(or state-name ""))
                  ("ASSIGNEE"     . ,assignee)
                  ("LNR_PRIORITY" . ,(if priority (number-to-string priority) ""))
                  ("URL"          . ,(or url "")) )))
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
      (unless (org-before-first-heading-p)
        (org-back-to-heading t)
        (org-end-of-subtree t t)
        (unless (bolp) (insert "\n")))
      (insert (format "* Linear Issues for %s (synced %s)\n"
                      (or team-label choice)
                      (format-time-string "%Y-%m-%d %H:%M")))
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
      (org-map-entries
       (lambda ()
         (when (= (org-current-level) 2)
           (org-cut-subtree)))
       nil 'children)
      (let ((issues (linear--issues-for-team team-id)))
        (dolist (iss issues)
          (pcase-let* ((`(,headline . ,props) (linear--issue->org-heading iss)))
            (linear--insert-org-heading headline props)))
        (message "Refreshed %d issues" (length issues))))))

;;;; Create issue from Org subtree

(defun linear--org-subtree-title ()
  "Return the current Org heading text, stripped of TODO/priority/tags."
  (save-excursion
    (org-back-to-heading t)
    (let ((raw (org-get-heading t t t t)))
      (string-trim raw))))

(defun linear--org-subtree-body ()
  "Return body text of the current Org subtree (excluding the heading line)."
  (save-excursion
    (org-back-to-heading t)
    (let ((beg (progn (forward-line 1) (point)))
          (end (progn (org-end-of-subtree t t) (point))))
      (string-trim (buffer-substring-no-properties beg end)))))

(defun linear--read-team (&optional default-id)
  "Prompt for a team; if DEFAULT-ID provided, preselect it."
  (let* ((pairs (linear--teams))
         (default-name (car (rassoc default-id pairs)))
         (name (completing-read
                (if default-name
                    (format "Team (default %s): " default-name)
                  "Team: ")
                (mapcar #'car pairs) nil t nil nil default-name)))
    (cdr (assoc name pairs))))

(defun linear--read-assignee (&optional _team-id)
  "Prompt for an assignee from workspace users; return user ID or nil."
  (let* ((pairs (linear--users 200))
         (names (cons "— Unassigned —" (mapcar #'car pairs)))
         (choice (completing-read "Assignee: " names nil t nil nil "— Unassigned —")))
    (if (string-prefix-p "—" choice) nil (cdr (assoc choice pairs)))))

(defun linear--read-state (team-id)
  "Prompt for a workflow state in TEAM-ID; return state ID or nil."
  (let* ((pairs (linear--team-states team-id))
         (names (cons "— Default —" (mapcar #'car pairs)))
         (choice (completing-read "State: " names nil t nil nil "— Default —")))
    (if (string-prefix-p "—" choice)
        nil
      (cdr (assoc choice pairs)))))

(defun linear--read-priority ()
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

;; Safe helper: only remove the Org priority cookie if one exists
(defun linear--org-heading-has-priority-p ()
  "Return non-nil if the current heading already has an Org priority cookie."
  (save-excursion
    (org-back-to-heading t)
    (let ((h (org-get-heading t t t t)))
      (string-match-p "\\[#[A-Z]\\]" h))))

(defun linear--apply-org-priority-from-linear (lin-prio)
  "Map Linear priority 0..4 to Org priority cookie A..C (or clear if present)."
  (when (org-at-heading-p)
    (pcase lin-prio
      ((or 4 3) (org-priority ?A))
      (2        (org-priority ?B))
      (1        (org-priority ?C))
      (_        (when (linear--org-heading-has-priority-p)
                  (org-priority 'remove))))))

(defun linear--issue-create (team-id title description &optional assignee-id state-id priority)
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
         (data (linear--graphql q vars))
         (node (linear--alist-get-in '(issueCreate issue) data)))
    (unless node (error "Linear returned no issue node"))
    node))

;;;###autoload
(defun linear-org-create-issue-from-subtree (&optional team-id)
  "Create a Linear issue using the current Org subtree.
Prompts for Team/State/Assignee/Priority, uses heading as title and body as description.
Writes LINEAR_ID/URL/STATE/ASSIGNEE/LNR_PRIORITY back to PROPERTIES and prefixes heading with [KEY-###]."
  (interactive)
  (linear--assert-auth)
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
           (team   (linear--read-team default-team))
           (title  (linear--org-subtree-title))
           (body   (linear--org-subtree-body))
           (state  (linear--read-state team))
           (assn   (linear--read-assignee team))
           (prio   (linear--read-priority))
           (issue  (linear--issue-create team title body assn state prio))
           (identifier (alist-get 'identifier issue))
           (url        (alist-get 'url issue))
           (state-name (linear--alist-get-in '(state name) issue))
           (assignee   (or (linear--alist-get-in '(assignee name) issue)
                           (linear--alist-get-in '(assignee displayName) issue)
                           "—"))
           (priority   (alist-get 'priority issue)))
      ;; Update PROPERTIES
      (org-set-property "LINEAR_ID"    (alist-get 'id issue))
      (org-set-property "URL"          (or url ""))
      (org-set-property "STATE"        (or state-name ""))
      (org-set-property "ASSIGNEE"     assignee)
      (org-set-property "LNR_PRIORITY" (if priority (number-to-string priority) ""))
      ;; Optional: set Org A..C cookie based on Linear priority (safe remove)
      (linear--apply-org-priority-from-linear priority)
      ;; Update heading to include identifier prefix
      (let* ((current (org-get-heading t t t t))
             (new     (if (string-match-p "^\\[[^]]+] " current)
                          current
                        (format "[%s] %s" identifier current))))
        (org-edit-headline new))
      (message "Created Linear issue %s → %s" identifier url))))

;;;; Minor mode & keymap

(defvar linear-org-mode-map
  (let ((m (make-sparse-keymap)))
    (define-key m (kbd "C-c l i") #'linear-org-insert-issues-for-team)
    (define-key m (kbd "C-c l o") #'linear-org-open-at-point)
    (define-key m (kbd "C-c l r") #'linear-org-refresh-under-heading)
    (define-key m (kbd "C-c l c") #'linear-org-create-issue-from-subtree)
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
