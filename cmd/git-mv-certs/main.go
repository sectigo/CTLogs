package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var certFilename = regexp.MustCompile(`^[0-9A-F]{64}\.crt$`)

type change struct {
	path   string
	staged bool // the deletion/addition is staged in the index
}

type move struct {
	from, to       change
	err            error
	contentChanged bool
}

type skipped struct {
	name   string
	reason string
}

func main() {
	dryRun := flag.Bool("dry-run", false, "Show what would be moved without changing anything")
	flag.Parse()

	root, err := git("", "rev-parse", "--show-toplevel")
	if err != nil {
		log.Fatalf("Not in a git repository: %v", err)
	}
	root = strings.TrimSpace(root)

	deleted, added, err := localChanges(root)
	if err != nil {
		log.Fatalf("Failed to read git status: %v", err)
	}

	moves, skips := pairChanges(root, deleted, added)
	if !*dryRun {
		for i := range moves {
			moves[i].err = gitMove(root, &moves[i])
		}
	}

	if failed := report(moves, skips, *dryRun); failed > 0 {
		os.Exit(1)
	}
}

// localChanges returns the deleted and added certificate files (staged or not), keyed by filename.
func localChanges(root string) (map[string][]change, map[string][]change, error) {
	out, err := git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
	if err != nil {
		return nil, nil, err
	}

	deleted := map[string][]change{}
	added := map[string][]change{}
	entries := strings.Split(out, "\x00")
	for i := 0; i < len(entries); i++ {
		entry := entries[i]
		if len(entry) < 4 {
			continue
		}
		x, y, p := entry[0], entry[1], entry[3:]
		if x == 'R' || x == 'C' || y == 'R' || y == 'C' {
			// Already a rename/copy; the next entry is its source path.
			i++
			continue
		}
		name := path.Base(p)
		if !certFilename.MatchString(name) {
			continue
		}
		switch {
		case x == 'D':
			deleted[name] = append(deleted[name], change{p, true})
		case x == ' ' && y == 'D':
			deleted[name] = append(deleted[name], change{p, false})
		case x == 'A' && y == ' ':
			added[name] = append(added[name], change{p, true})
		case x == '?' && y == '?':
			added[name] = append(added[name], change{p, false})
		}
	}
	return deleted, added, nil
}

// pairChanges pairs each deletion with an addition of the same filename, where the pairing is unambiguous
// and the added file's content matches its filename.
func pairChanges(root string, deleted, added map[string][]change) ([]move, []skipped) {
	var moves []move
	var skips []skipped

	var names []string
	for name := range deleted {
		if len(added[name]) > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		dels, adds := deleted[name], added[name]
		if len(dels) != 1 || len(adds) != 1 {
			skips = append(skips, skipped{name, fmt.Sprintf("ambiguous: deleted from %s; added to %s", paths(dels), paths(adds))})
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, adds[0].path))
		if err != nil {
			skips = append(skips, skipped{name, err.Error()})
			continue
		}
		if fp := fingerprint(data); fp+".crt" != name {
			skips = append(skips, skipped{name, fmt.Sprintf("%s has SHA-256 fingerprint %s", adds[0].path, fp)})
			continue
		}
		moves = append(moves, move{from: dels[0], to: adds[0]})
	}
	return moves, skips
}

// fingerprint returns the uppercase hex SHA-256 of the DER certificate in data (PEM or DER).
func fingerprint(data []byte) string {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}
	return fmt.Sprintf("%X", sha256.Sum256(der))
}

// gitMove replaces the deletion of m.from and the addition of m.to with "git mv", keeping m.to's current content.
func gitMove(root string, m *move) (err error) {
	toAbs := filepath.Join(root, m.to.path)
	info, err := os.Stat(toAbs)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(toAbs)
	if err != nil {
		return err
	}
	// Whatever happens, leave the newly added file's content in place.
	defer func() {
		if werr := os.WriteFile(toAbs, data, info.Mode().Perm()); werr != nil && err == nil {
			err = werr
		}
	}()

	if m.to.staged {
		if _, err := git(root, "rm", "--cached", "--quiet", "--", m.to.path); err != nil {
			return err
		}
	}
	if err := os.Remove(toAbs); err != nil {
		return err
	}
	if _, err := git(root, "restore", "--source=HEAD", "--staged", "--worktree", "--", m.from.path); err != nil {
		return err
	}
	if _, err := git(root, "mv", "--", m.from.path, m.to.path); err != nil {
		// Put the deletion back as it was.
		os.Remove(filepath.Join(root, m.from.path))
		if m.from.staged {
			git(root, "rm", "--cached", "--quiet", "--", m.from.path)
		}
		return err
	}
	if err := os.WriteFile(toAbs, data, info.Mode().Perm()); err != nil {
		return err
	}
	if old, err := git(root, "show", "HEAD:"+m.from.path); err == nil && old != string(data) {
		m.contentChanged = true
	}
	// Stage the new content too, in case it differs from the old file's (e.g. PEM formatting).
	_, err = git(root, "add", "--", m.to.path)
	return err
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func paths(changes []change) string {
	p := make([]string, len(changes))
	for i, c := range changes {
		p[i] = c.path
	}
	return strings.Join(p, ", ")
}

// report prints the findings and returns the number of failed moves.
func report(moves []move, skips []skipped, dryRun bool) int {
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("Certificate Move Report")
	fmt.Println(strings.Repeat("=", 80))

	moved, failed := 0, 0
	for _, m := range moves {
		switch {
		case dryRun:
			fmt.Printf("\n[DRY-RUN] Would git mv %s\n                     -> %s\n", m.from.path, m.to.path)
		case m.err != nil:
			failed++
			fmt.Printf("\n❌ FAILED git mv %s\n              -> %s\n   %v\n", m.from.path, m.to.path, m.err)
		default:
			moved++
			fmt.Printf("\n✓ git mv %s\n      -> %s\n", m.from.path, m.to.path)
			if m.contentChanged {
				fmt.Printf("   Note: file content differs (same certificate, different encoding), so git may not show this as a rename\n")
			}
		}
	}
	for _, s := range skips {
		fmt.Printf("\n⚠️  SKIPPED %s\n   %s\n", s.name, s.reason)
	}

	fmt.Println("\n" + strings.Repeat("-", 80))
	fmt.Println("Summary:")
	if dryRun {
		fmt.Printf("  Moves (dry-run): %d\n", len(moves))
	} else {
		fmt.Printf("  Moved:           %d\n", moved)
		fmt.Printf("  Failed:          %d\n", failed)
	}
	fmt.Printf("  Skipped:         %d\n", len(skips))
	fmt.Println(strings.Repeat("=", 80))
	return failed
}
