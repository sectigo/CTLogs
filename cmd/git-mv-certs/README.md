# git-mv-certs

A Go tool that turns matching certificate deletions and additions in the local git working tree into `git mv` operations, so that certificates moved between directories keep their history.

## Overview

The update scripts regenerate certificate directories by deleting every `.crt` file and writing new ones, so a certificate that moves from one directory to another (e.g. from `crt/common/trusted/tls` to `crt/common/non_production/trusted_but_not_for_serverauth`) shows up as a deletion plus an unrelated addition.

This tool reads `git status` and, for each certificate filename (`<SHA-256 of the DER certificate>.crt`) that has been deleted in one place and added in another, replaces the deletion and addition with a `git mv`. It handles both staged and unstaged deletions, and both staged and untracked additions. The newly added file's content is kept, and the result is staged.

A pair is skipped (and reported) when:

- The same filename was deleted or added in more than one place, so the pairing is ambiguous.
- The added file's SHA-256 fingerprint doesn't match its filename (run `check-certs` first to fix filenames).

Deletions and additions that are already staged as a rename are left alone.

## Usage

Run from anywhere inside the repository:

```bash
go run ./cmd/git-mv-certs/main.go
```

Preview the moves without changing anything:

```bash
go run ./cmd/git-mv-certs/main.go -dry-run
```

## Flags

- `-dry-run`: Show what would be moved without changing anything

## Notes

Git doesn't record renames; it detects them by comparing content. If the added file contains the same certificate as the deleted one but encoded differently (e.g. different PEM line wrapping), the tool still does the `git mv` but warns that git may not show it as a rename.

The tool exits with a non-zero status if any move fails. If a move fails, the newly added file's content is left in place.
