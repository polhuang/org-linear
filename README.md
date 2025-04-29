# org-linear

Bidirectional synchronization between [Linear](https://linear.app) and [Org mode](https://orgmode.org) for Emacs.

## Features

- **OAuth2 Authentication**: Secure authentication with Linear using OAuth2
- **Issue Import**: Download Linear issues as Org headings with properties
- **Issue Creation**: Create Linear issues from Org subtrees
- **Bidirectional Sync**
  - Sync TODO states, priorities, assignees, and labels
  - Conflict detection and resolution
  - Bulk sync for files, subtrees, or individual issues
- **Team Management**: Download all teams' issues to separate files
- **User Issues**: View and manage issues assigned to you

## Installation

### Setup

1. Clone this repository or download `org-linear.el`
2. Add to your Emacs configuration:
   ```elisp
   (add-to-list 'load-path "/path/to/org-linear")
   (require 'org-linear)

   
   (add-hook 'org-mode-hook #'org-linear-mode)
   ```

### Linear OAuth Application

1. Create an OAuth application in Linear:
   - Go to Settings � API � OAuth applications
   - Create new application
   - Set redirect URI to: `http://localhost:8080/callback`
   - Copy your Client ID and Client Secret

2. Configure credentials (choose one method):

   **Option 1: Environment variables (recommended)**
   ```bash
   export LINEAR_CLIENT_ID="your-client-id"
   export LINEAR_CLIENT_SECRET="your-client-secret"
   ```

   **Option 2: auth-source (most secure)**

   Add to `~/.authinfo.gpg` (encrypted) or `~/.authinfo`:
   ```
   machine api.linear.app login client-id password your-client-id
   machine api.linear.app login client-secret password your-client-secret
   ```

   **Option 3: Emacs variables**
   ```elisp
   (setq org-linear-client-id "your-client-id"
         org-linear-client-secret "your-client-secret")
   ```

## Quick Start

1. **Authenticate with Linear**:
   ```
   M-x org-linear-oauth-authorize
   ```
   This will open your browser for OAuth authentication. The callback server starts automatically.

2. **Import team issues**:
   ```
   M-x org-linear-insert-issues-for-team
   ```
   Select a team and issues will be inserted as Org headings.

3. **Create a Linear issue from Org**:
   - Create an Org heading with your task details
   - Run: `M-x org-linear-create-issue-from-subtree`
   - The heading will be updated with Linear properties

4. **Sync changes**:
   - Sync to Linear: `M-x org-linear-sync-to-linear`
   - Sync from Linear: `M-x org-linear-sync-from-linear`

## Key Bindings

When `org-linear-mode` is enabled:

| Key | Command | Description |
|-----|---------|-------------|
| `C-c l i` | `org-linear-insert-issues-for-team` | Import team issues |
| `C-c l u` | `org-linear-insert-issues-for-current-user` | Import your issues |
| `C-c l o` | `org-linear-open-at-point` | Open issue in browser |
| `C-c l c` | `org-linear-create-issue-from-subtree` | Create Linear issue |
| `C-c l d` | `org-linear-delete-issue` | Delete Linear issue |
| `C-c l s` | `org-linear-sync-to-linear` | Sync current issue to Linear |
| `C-c l p` | `org-linear-sync-from-linear` | Sync current issue from Linear |
| `C-c l S` | `org-linear-sync-subtree-to-linear` | Sync subtree to Linear |
| `C-c l P` | `org-linear-sync-subtree-from-linear` | Sync subtree from Linear |
| `C-c l f` | `org-linear-sync-file-to-linear` | Sync entire file to Linear |
| `C-c l F` | `org-linear-sync-file-from-linear` | Sync entire file from Linear |
| `C-c l ?` | `org-linear-sync-status` | Show sync status |

## Configuration

### TODO State Mapping

Map Org TODO keywords to Linear states:

```elisp
(setq org-linear-state-alist
  '(("TODO" . "Todo")
    ("IN-PROGRESS" . "In Progress")
    ("IN-REVIEW" . "In Review")
    ("BACKLOG" . "Backlog")
    ("BLOCKED" . "Blocked")
    ("DONE" . "Done")))
```

### Priority Mapping

Map Org priorities to Linear priorities:

```elisp
(setq org-linear-priority-alist
  '((?A . 1)  ; Urgent
    (?B . 2)  ; High
    (?C . 3)  ; Medium
    (?D . 4))) ; Low
```

### Conflict Resolution

Configure how to handle sync conflicts:

```elisp
(setq org-linear-conflict-resolution 'prompt)  ; Ask user (default)
;; (setq org-linear-conflict-resolution 'linear-wins)  ; Use Linear values
;; (setq org-linear-conflict-resolution 'org-wins)     ; Use Org values
```

### Storage Directory

Set where team files are stored:

```elisp
(setq org-linear-directory "~/.org-linear")
```

## Workflow Examples

### Track Team Issues

```elisp
;; Download all team issues to separate files
M-x org-linear-download-all-teams

;; Files are created in .org-linear/[TEAM_KEY].org
```

### Bidirectional Sync

```elisp
;; Make changes in Org, push to Linear
M-x org-linear-sync-to-linear

;; Pull latest changes from Linear
M-x org-linear-sync-from-linear

;; Destructive sync: delete all and re-import from Linear
C-u M-x org-linear-sync-file-from-linear
```

### Issue Properties

Each Linear issue is stored with properties:

```org
* TODO [PRJ-123] Fix authentication bug          :linear:bug:
:PROPERTIES:
:LINEAR_ID: issue-uuid-here
:STATE: Todo
:ASSIGNEE: John Doe
:PRIORITY: 1
:LABELS: bug, auth
:URL: https://linear.app/team/issue/PRJ-123
:UPDATED: 2025-09-30 14:30
:END:
```

## Authentication

### Token Storage

The package uses `auth-source` to securely store OAuth tokens. After authenticating via `org-linear-oauth-authorize`, access and refresh tokens are automatically saved.

**Default storage locations:**
- `~/.authinfo.gpg` (encrypted, recommended)
- `~/.authinfo` (plaintext)

Tokens are cached for 24 hours and automatically refreshed when expired.

### Auth Commands

**Revoke authentication:**
```elisp
M-x org-linear-auth-revoke
```

**Check authentication status:**
```elisp
M-x org-linear-auth-status
```

**Clear cached tokens:**
```elisp
M-x org-linear-auth-clear
```
