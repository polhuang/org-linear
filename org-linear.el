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

(provide 'linear-org)
;;; linear-org.el ends here
