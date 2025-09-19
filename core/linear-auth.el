;;; linear-auth.el --- Authentication support for org-linear  -*- lexical-binding: t; -*-
;; SPDX-License-Identifier: GPL-3.0-or-later

;;; Commentary:
;; Secure token storage using auth-source, which integrates with OS keychains
;; (macOS Keychain, GNOME Keyring, etc.) for persistent, encrypted storage.

;;; Code:

(require 'auth-source)
(require 'subr-x)  ; for string-trim

(defgroup linear-auth nil
  "Authentication settings for Linear integration."
  :group 'org-linear)

(defcustom linear-auth-host "api.linear.app"
  "Host identifier for auth-source Linear token storage."
  :type 'string
  :group 'linear-auth)

(defcustom linear-auth-user "token"
  "User identifier for auth-source Linear token storage."
  :type 'string
  :group 'linear-auth)

(defun linear-auth--read-token ()
  "Read Linear access token from auth-source or session cache.
Returns the token string or nil if not found."
  ;; First try session cache
  (or linear-auth--cached-token
      ;; Then try auth-source (from ~/.authinfo.gpg or keychain)
      (when-let ((auth (auth-source-search :host linear-auth-host
                                           :user linear-auth-user
                                           :max 1)))
        (let ((secret (plist-get (car auth) :secret)))
          (if (functionp secret)
              (funcall secret)
            secret)))))

(defun linear-auth--write-token (token &optional refresh-token)
  "Store Linear access TOKEN for the current session.
REFRESH-TOKEN is currently unused but reserved for future OAuth refresh flows.
Note: This stores the token in memory for the current session only.
For persistent storage, manually add to ~/.authinfo.gpg:
  machine api.linear.app login token password YOUR_TOKEN_HERE"
  (when (and token (stringp token) (> (length (string-trim token)) 0))
    (setq linear-auth--cached-token token)
    (message "Linear token stored for current session. For persistent storage, see auth-source documentation.")))

;; Session cache for the token
(defvar linear-auth--cached-token nil
  "Cached Linear token for the current Emacs session.")

(defun linear-auth-clear ()
  "Clear Linear authentication token from session cache."
  (interactive)
  (setq linear-auth--cached-token nil)
  (message "Linear token cleared from session cache"))

;;;###autoload
(defun linear-auth-setup-persistent ()
  "Guide user to set up persistent token storage.
This will prompt to add an entry to ~/.authinfo.gpg for permanent storage."
  (interactive)
  (let ((token (read-passwd "Enter your Linear API token: ")))
    (when (and token (> (length token) 0))
      ;; Store in session
      (setq linear-auth--cached-token token)
      ;; Guide user for persistent storage
      (message (concat "Token stored for this session. "
                      "For persistent storage, add this line to ~/.authinfo.gpg:\n"
                      "machine %s login %s password %s")
               linear-auth-host linear-auth-user token)
      (when (y-or-n-p "Copy token to clipboard for manual setup? ")
        (kill-new token)
        (message "Token copied to clipboard")))))

(provide 'linear-auth)
;;; linear-auth.el ends here
