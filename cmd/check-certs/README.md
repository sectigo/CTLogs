# check-certs

A Go tool that validates certificate filenames against their SHA-256 fingerprints and removes certificates with ML-DSA keys.

## Overview

This tool scans all certificate files (`.crt`) in a directory tree and performs two key operations:

1. **Filename Validation**: Calculates the SHA-256 fingerprint of each DER-encoded certificate and verifies that the filename (excluding the `.crt` extension) matches the fingerprint. Files with mismatched names are automatically renamed to their correct fingerprint-based names using `git mv`.

2. **ML-DSA Removal**: Detects certificates that use ML-DSA (Module-Lattice-Based Digital Signature Algorithm) keys and deletes them using `git rm` to preserve version control history.

## Usage

### Build

```bash
go build -o check-certs ./cmd/check-certs/main.go
```

### Run

Verify certificates, rename mismatched files, and delete ML-DSA certificates:

```bash
./check-certs -dir crt
```

### Dry-run

Preview what would be renamed and deleted without making actual changes:

```bash
./check-certs -dry-run -dir crt
```

## Flags

- `-dir <path>`: Path to the certificate directory (default: `crt`)
- `-dry-run`: Show what would be renamed/deleted without actually making changes

## Output

The tool produces a detailed report including:

- **ML-DSA Certificates**: Certificates using ML-DSA keys that will be deleted
- **Mismatches**: Files whose names don't match their SHA-256 fingerprints
- **Errors**: Files that couldn't be parsed (e.g., malformed certificates) or processed
- **Summary**: Total files checked, matched, mismatched, ML-DSA deletions, errors, and renames

Example:

```
================================================================================
Certificate Filename Verification Report
================================================================================

🗑️  ML-DSA KEY DETECTED: EXAMPLE1234567890ABCDEF.crt
   Path: crt/common/trusted/tls/EXAMPLE1234567890ABCDEF.crt
   ✓ DELETED with git rm

⚠️  MISMATCH: DigiCertVerifiedMarkRootCA.crt
   Expected: DigiCertVerifiedMarkRootCA.crt
   Actual:   504386C9EE8932FECC95FADE427F69C3E2534B7310489E300FEE448E33C46B42.crt
   ✓ RENAMED to: 504386C9EE8932FECC95FADE427F69C3E2534B7310489E300FEE448E33C46B42.crt

--------------------------------------------------------------------------------
Summary:
  Total files checked:     1160
  Filenames matched:       1156
  Filenames mismatched:    2
  ML-DSA certificates:     1
  Errors:                  1
  Renamed:                 2
  Deleted ML-DSA:          1
================================================================================
```

## Certificate Format

The tool supports PEM-encoded certificates (`.crt` files). It extracts the certificate data, parses it, and computes the SHA-256 fingerprint of the DER-encoded form.

## ML-DSA Detection

The tool detects ML-DSA keys by reading the algorithm OID from the certificate's SubjectPublicKeyInfo (FIPS 204, RFC 9881):

- `2.16.840.1.101.3.4.3.17` (ML-DSA-44)
- `2.16.840.1.101.3.4.3.18` (ML-DSA-65)
- `2.16.840.1.101.3.4.3.19` (ML-DSA-87)
- `2.16.840.1.101.3.4.3.32` - `.34` (HashML-DSA-44/65/87 with SHA-512)

Any certificate whose public key uses one of these algorithms will be detected and deleted.

## Git Integration

Operations use git commands when possible to maintain version control:

- **Renames**: Uses `git mv` to track filename changes in git history
- **ML-DSA Deletions**: 
  - Attempts `git rm` for tracked files to record deletion in git history
  - Falls back to plain `rm` for untracked files
  - Both operations properly remove the certificates

Changes from renames are automatically staged in git's index and ready to commit. Deletions of tracked files are also staged. Deletions of untracked files are simply removed from the filesystem.

## Edge Cases

Some edge cases may produce errors:

- **Malformed certificates**: Certificates that don't conform to X.509 standards
- **Unusual string types**: Non-standard attributes in the certificate's DN
- **Negative serial numbers**: Certificates with invalid serial number fields
- **Git errors**: Issues with running `git mv` or `git rm` (e.g., not in a git repository)

These errors are reported in the summary and do not prevent the tool from processing other files.


