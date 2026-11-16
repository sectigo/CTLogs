# check-certs

A Go tool that validates certificate filenames against their SHA-256 fingerprints.

## Overview

This tool scans all certificate files (`.crt`) in a directory tree, calculates the SHA-256 fingerprint of each DER-encoded certificate, and verifies that the filename (excluding the `.crt` extension) matches the fingerprint. Files with mismatched names are automatically renamed to their correct fingerprint-based names using `git mv` to preserve version control history.

## Usage

### Build

```bash
go build -o check-certs ./cmd/check-certs/main.go
```

### Run

Verify certificates and rename mismatched files (using `git mv`):

```bash
./check-certs -dir crt
```

### Dry-run

Preview what would be renamed without making actual changes:

```bash
./check-certs -dry-run -dir crt
```

## Flags

- `-dir <path>`: Path to the certificate directory (default: `crt`)
- `-dry-run`: Show what would be renamed without actually renaming files

## Output

The tool produces a detailed report including:

- **Mismatches**: Files whose names don't match their SHA-256 fingerprints
- **Errors**: Files that couldn't be parsed (e.g., malformed certificates) or renamed
- **Summary**: Total files checked, matched, mismatched, errors, and number of renames

Example:

```
================================================================================
Certificate Filename Verification Report
================================================================================

⚠️  MISMATCH: DigiCertVerifiedMarkRootCA.crt
   Expected: DigiCertVerifiedMarkRootCA.crt
   Actual:   504386C9EE8932FECC95FADE427F69C3E2534B7310489E300FEE448E33C46B42.crt
   ✓ RENAMED to: 504386C9EE8932FECC95FADE427F69C3E2534B7310489E300FEE448E33C46B42.crt

--------------------------------------------------------------------------------
Summary:
  Total files checked:     1160
  Filenames matched:       1158
  Filenames mismatched:    2
  Errors:                  0
  Renamed:                 2
================================================================================
```

## Certificate Format

The tool supports PEM-encoded certificates (`.crt` files). It extracts the certificate data, parses it, and computes the SHA-256 fingerprint of the DER-encoded form.

## Git Integration

When renaming files, the tool uses `git mv` instead of direct filesystem operations. This ensures that:
- The rename operation is tracked in version control
- Git history is properly preserved
- The changes can be easily committed

## Edge Cases

Some edge cases may produce errors:

- **Malformed certificates**: Certificates that don't conform to X.509 standards
- **Unusual string types**: Non-standard attributes in the certificate's DN
- **Negative serial numbers**: Certificates with invalid serial number fields
- **Git errors**: Issues with running `git mv` (e.g., not in a git repository)

These errors are reported in the summary and do not prevent the tool from processing other files.

