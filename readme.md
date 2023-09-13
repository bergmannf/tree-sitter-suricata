# Suricata tree-sitter

This is a (very basic) tree-sitter grammer for [suricata](https://suricata.io/
"suricata") rules.

# Usage

## Emacs

Build the shared library file for your operating system.

If using [tree-sitter](https://github.com/emacs-tree-sitter/elisp-tree-sitter)
library (emacs < 29), the tree-sitter-cli in use must be version 0.19.x instead
of the newest 0.20.x.

Once the right library is build, setup Emacs to load it:

```elisp
(tree-sitter-require 'suricata)

(setq tree-sitter-major-mode-language-alist
      (cons (cons 'suricata-mode 'suricata)
            (cdr tree-sitter-major-mode-language-alist)))

(define-derived-mode suricata-mode
  prog-mode
  "suricata"
  "Edit suricata rule files")
(add-hook 'suricata-mode-hook 'tree-sitter-mode)
(add-hook 'suricata-mode-hook 'tree-sitter-hl-mode)
(add-to-list 'auto-mode-alist '("\\.rules" . suricata-mode))
```

Alternatively in doom-emacs:

```elisp
(define-derived-mode suricata-mode
  prog-mode
  "suricata"
  "Edit suricata rule files")

(after! tree-sitter
  (tree-sitter-require 'suricata))
(add-to-list 'auto-mode-alist '("\\.rules" . suricata-mode))
(add-hook! suricata-mode 'tree-sitter-mode 'tree-sitter-hl-mode)
(set-tree-sitter-lang! 'suricata-mode 'suricata)
```

Now the queries file for the language has to be copied to the right place, so it
will be picked up:

```elisp
;; Find the right location
(tree-sitter-langs--hl-query-path 'suricata)
```

Copy the file from this repository to this location:

```sh
cp queries/highlights.scm <path_from_previous_command>
```

Activating `suricata-mode` should now use the correct syntax highlighting.
