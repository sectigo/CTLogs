package main

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type CheckResult struct {
	Path         string
	Filename     string
	Expected     string
	Actual       string
	Renamed      bool
	OldPath      string
	Error        string
	MLDSAFound   bool
	Deleted      bool
	DeleteMethod string
}

func main() {
	crtDir := flag.String("dir", "crt", "Path to the certificate directory")
	dryRun := flag.Bool("dry-run", false, "Show what would be renamed without actually renaming")
	flag.Parse()

	if _, err := os.Stat(*crtDir); os.IsNotExist(err) {
		log.Fatalf("Certificate directory does not exist: %s", *crtDir)
	}

	results := checkCertificates(*crtDir, *dryRun)
	reportFindings(results, *dryRun)
}

func checkCertificates(crtDir string, dryRun bool) []CheckResult {
	var results []CheckResult

	err := filepath.Walk(crtDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !strings.HasSuffix(info.Name(), ".crt") {
			return nil
		}

		result := checkCertificate(path, dryRun)
		results = append(results, result)

		return nil
	})

	if err != nil {
		log.Fatalf("Error walking certificate directory: %v", err)
	}

	return results
}

func checkCertificate(certPath string, dryRun bool) CheckResult {
	result := CheckResult{
		Path:     certPath,
		Filename: filepath.Base(certPath),
	}

	// Read certificate file
	certData, err := os.ReadFile(certPath)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read file: %v", err)
		return result
	}

	// Parse PEM format
	block, _ := pem.Decode(certData)
	if block == nil {
		result.Error = "failed to decode PEM data"
		return result
	}

	// Parse the DER encoded certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		result.Error = fmt.Sprintf("failed to parse certificate: %v", err)
		return result
	}

	// Check for ML-DSA keys and delete if found
	if hasMLDSAKey(cert) {
		result.MLDSAFound = true
		if !dryRun {
			// Try git rm first (for tracked files), fall back to plain rm for untracked files
			cmd := exec.Command("git", "rm", "--quiet", certPath)
			result.DeleteMethod = "git rm"
			if err := cmd.Run(); err != nil {
				// If git rm fails, try plain rm (file might be untracked)
				if err := os.Remove(certPath); err != nil {
					result.Error = fmt.Sprintf("failed to delete certificate with ML-DSA key: %v", err)
					return result
				}
				result.DeleteMethod = "rm"
			}
			result.Deleted = true
		}
		return result
	}

	// Calculate SHA-256 fingerprint of the DER-encoded certificate
	hash := sha256.Sum256(cert.Raw)
	fingerprint := fmt.Sprintf("%X", hash)
	result.Actual = fingerprint

	// Extract expected filename (without .crt extension)
	expectedFilename := strings.TrimSuffix(result.Filename, ".crt")
	result.Expected = expectedFilename

	// Check if filename matches the fingerprint
	if fingerprint == expectedFilename {
		return result
	}

	// Filename doesn't match - rename it using git mv
	dir := filepath.Dir(certPath)
	newFilename := fingerprint + ".crt"
	newPath := filepath.Join(dir, newFilename)

	if dryRun {
		result.Renamed = false
		result.OldPath = certPath
	} else {
		// Use git mv to rename the file
		cmd := exec.Command("git", "mv", certPath, newPath)
		if err := cmd.Run(); err != nil {
			result.Error = fmt.Sprintf("failed to rename with git mv: %v", err)
			return result
		}
		result.Renamed = true
		result.OldPath = certPath
		result.Path = newPath
	}

	return result
}

// ML-DSA public key algorithm OIDs (FIPS 204, RFC 9881).
var mlDSAOIDs = []asn1.ObjectIdentifier{
	{2, 16, 840, 1, 101, 3, 4, 3, 17}, // id-ml-dsa-44
	{2, 16, 840, 1, 101, 3, 4, 3, 18}, // id-ml-dsa-65
	{2, 16, 840, 1, 101, 3, 4, 3, 19}, // id-ml-dsa-87
	{2, 16, 840, 1, 101, 3, 4, 3, 32}, // id-hash-ml-dsa-44-with-sha512
	{2, 16, 840, 1, 101, 3, 4, 3, 33}, // id-hash-ml-dsa-65-with-sha512
	{2, 16, 840, 1, 101, 3, 4, 3, 34}, // id-hash-ml-dsa-87-with-sha512
}

// hasMLDSAKey reports whether the certificate's subject public key is an ML-DSA key.
// crypto/x509 reports unrecognized key algorithms only as UnknownPublicKeyAlgorithm, so
// the algorithm OID is read from the raw SubjectPublicKeyInfo.
func hasMLDSAKey(cert *x509.Certificate) bool {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return false
	}
	for _, oid := range mlDSAOIDs {
		if spki.Algorithm.Algorithm.Equal(oid) {
			return true
		}
	}
	return false
}

func reportFindings(results []CheckResult, dryRun bool) {
	var mismatched int
	var errors int
	var mldsaCount int
	var mldsaDeleted int
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("Certificate Filename Verification Report")
	fmt.Println(strings.Repeat("=", 80))

	// First, report ML-DSA deletions
	for _, result := range results {
		if result.MLDSAFound {
			mldsaCount++
			fmt.Printf("\n🗑️  ML-DSA KEY DETECTED: %s\n", result.Filename)
			fmt.Printf("   Path: %s\n", result.Path)
			if result.Deleted {
				mldsaDeleted++
				fmt.Printf("   ✓ DELETED with %s\n", result.DeleteMethod)
			} else if result.Error != "" {
				fmt.Printf("   Error: %s\n", result.Error)
			} else if dryRun {
				fmt.Printf("   [DRY-RUN] Would delete\n")
			}
		}
	}

	// Then report other findings
	for _, result := range results {
		if result.MLDSAFound {
			continue
		}

		if result.Error != "" {
			errors++
			fmt.Printf("\n❌ ERROR: %s\n", result.Filename)
			fmt.Printf("   Path: %s\n", result.Path)
			fmt.Printf("   Error: %s\n", result.Error)
			continue
		}

		if result.Actual != result.Expected {
			mismatched++
			fmt.Printf("\n⚠️  MISMATCH: %s\n", result.Filename)
			fmt.Printf("   Expected: %s.crt\n", result.Expected)
			fmt.Printf("   Actual:   %s.crt\n", result.Actual)
			if result.Renamed {
				fmt.Printf("   ✓ RENAMED to: %s\n", filepath.Base(result.Path))
			} else if dryRun {
				fmt.Printf("   [DRY-RUN] Would rename to: %s.crt\n", result.Actual)
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("-", 80))
	fmt.Printf("Summary:\n")
	validCount := len(results) - mldsaCount - errors
	fmt.Printf("  Total files checked:     %d\n", len(results))
	fmt.Printf("  Filenames matched:       %d\n", validCount-mismatched)
	fmt.Printf("  Filenames mismatched:    %d\n", mismatched)
	fmt.Printf("  ML-DSA certificates:     %d\n", mldsaCount)
	fmt.Printf("  Errors:                  %d\n", errors)
	if dryRun {
		fmt.Printf("  Renamed (dry-run):       %d\n", mismatched)
		fmt.Printf("  Deleted ML-DSA (dry-run):%d\n", mldsaCount)
	} else {
		fmt.Printf("  Renamed:                 %d\n", mismatched)
		fmt.Printf("  Deleted ML-DSA:          %d\n", mldsaDeleted)
	}
	fmt.Println(strings.Repeat("=", 80))
}
