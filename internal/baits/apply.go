package baits

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/paths"
	"github.com/xak1234/sentient1/internal/winsec"
)

// legacyMarkers identify baits planted by the original PowerShell honeypot
// script, so we adopt (and later clean up) them as our own.
var legacyMarkers = []string{"j.marsh.1987@outlook.com"}

// Create plants a bait and returns its state. Existing files are adopted, not
// overwritten (the user may have customised them). Requires admin for audit rules.
func Create(s Spec, u config.UserInfo, g *Gen) (*config.BaitState, error) {
	bs := &config.BaitState{ID: s.ID, Name: s.Name, Kind: s.Kind, Status: "ok", CreatedAt: time.Now()}
	created := map[string]bool{}
	for _, f := range s.Files(u) {
		dir := filepath.Dir(f.Path)
		if top := topMissingDir(dir); top != "" && !created[top] {
			created[top] = true
			bs.CreatedDirs = append(bs.CreatedDirs, top)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return bs, fmt.Errorf("%s: %w", dir, err)
		}
		bf := config.BaitFile{Path: f.Path, Audit: f.Audit}
		if b, err := os.ReadFile(f.Path); err == nil {
			// Adopt an existing file (e.g. from the original honeypot script).
			if f.Text {
				bf.Text = string(b)
			}
			for _, m := range legacyMarkers {
				if strings.Contains(string(b), m) {
					bf.Created = true
				}
			}
		} else {
			data := f.Gen(g)
			if err := os.WriteFile(f.Path, data, 0o644); err != nil {
				return bs, fmt.Errorf("%s: %w", f.Path, err)
			}
			bf.Created = true
			if f.Text {
				bf.Text = string(data)
			}
			ageFile(f.Path)
		}
		setNotIndexed(f.Path)
		if f.Audit {
			if err := winsec.SetBaitAudit(f.Path); err != nil {
				return bs, fmt.Errorf("audit rule on %s: %w", f.Path, err)
			}
		}
		if fi, err := os.Stat(f.Path); err == nil {
			bf.Size, bf.ModTime = fi.Size(), fi.ModTime()
		}
		bs.Files = append(bs.Files, bf)
	}
	return bs, nil
}

// topMissingDir returns the highest ancestor of dir that doesn't exist yet.
func topMissingDir(dir string) string {
	top := ""
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(d); err == nil {
			return top
		}
		top = d
		if filepath.Dir(d) == d {
			return top
		}
	}
}

// ageFile backdates timestamps by 1–14 months so the bait doesn't look brand new.
func ageFile(path string) {
	t := time.Now().Add(-time.Duration(30+rint(400)) * 24 * time.Hour).Add(-time.Duration(rint(86400)) * time.Second)
	ft := windows.NsecToFiletime(t.UnixNano())
	p, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(p, windows.FILE_WRITE_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	windows.SetFileTime(h, &ft, &ft, &ft)
}

// setNotIndexed keeps Windows Search from reading (and tripping) the bait.
func setNotIndexed(path string) {
	p, _ := windows.UTF16PtrFromString(path)
	a, err := windows.GetFileAttributes(p)
	if err != nil {
		return
	}
	windows.SetFileAttributes(p, a|windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
}

// Problem found by Check.
type Problem struct {
	File   string
	Kind   string // missing | no-audit | modified
	Detail string
}

// Check inspects a bait without reading its contents (reading would trip it).
func Check(bs *config.BaitState) []Problem {
	var out []Problem
	for _, f := range bs.Files {
		fi, err := os.Stat(f.Path)
		if errors.Is(err, os.ErrNotExist) {
			out = append(out, Problem{File: f.Path, Kind: "missing"})
			continue
		}
		if err != nil {
			continue
		}
		if f.Audit {
			if ok, err := winsec.HasBaitAudit(f.Path); err == nil && !ok {
				out = append(out, Problem{File: f.Path, Kind: "no-audit", Detail: "audit rule was stripped (an editor rewrote the file?)"})
			}
		}
		if f.Size != 0 && (fi.Size() != f.Size || !fi.ModTime().Equal(f.ModTime)) {
			out = append(out, Problem{File: f.Path, Kind: "modified", Detail: "contents changed"})
		}
	}
	return out
}

// Repair fixes problems: recreates missing files and re-applies audit rules.
func Repair(bs *config.BaitState, s Spec, u config.UserInfo, g *Gen, probs []Problem) error {
	specs := map[string]FileSpec{}
	for _, f := range s.Files(u) {
		specs[strings.ToLower(f.Path)] = f
	}
	var firstErr error
	for _, p := range probs {
		idx := -1
		for i := range bs.Files {
			if strings.EqualFold(bs.Files[i].Path, p.File) {
				idx = i
			}
		}
		if idx < 0 {
			continue
		}
		bf := &bs.Files[idx]
		switch p.Kind {
		case "missing":
			fs, ok := specs[strings.ToLower(p.File)]
			if !ok {
				continue
			}
			os.MkdirAll(filepath.Dir(p.File), 0o755)
			data := []byte(bf.Text)
			if data == nil || !fs.Text {
				data = fs.Gen(g)
			}
			if err := os.WriteFile(p.File, data, 0o644); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			ageFile(p.File)
			setNotIndexed(p.File)
			bf.Created = true
			if fs.Text {
				bf.Text = string(data)
			}
			fallthrough
		case "no-audit":
			if bf.Audit {
				if err := winsec.SetBaitAudit(p.File); err != nil && firstErr == nil {
					firstErr = err
				}
			}
			if fi, err := os.Stat(p.File); err == nil {
				bf.Size, bf.ModTime = fi.Size(), fi.ModTime()
			}
		case "modified":
			// Something (you, or a real app) wrote to it: from now on we never
			// delete it, we only take our audit rule off when removing.
			bf.Created = false
			if fi, err := os.Stat(p.File); err == nil {
				bf.Size, bf.ModTime = fi.Size(), fi.ModTime()
			}
		}
	}
	return firstErr
}

// Remove takes a bait away: audit rules first (so deleting doesn't alert),
// then files SENTIENT1 created, then folders it created if they're now empty.
// Adopted files the user made themselves are kept.
func Remove(bs *config.BaitState) error {
	var firstErr error
	for _, f := range bs.Files {
		if f.Audit {
			winsec.ClearAudit(f.Path)
		}
		// Only delete a file if it's still exactly what we planted. If anything
		// rewrote it (e.g. the real app moved in and saved its own data there),
		// it's no longer ours: keep it.
		if f.Created && unchanged(f) {
			if err := os.Remove(f.Path); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
				firstErr = err
			} else if err == nil {
				// The name stays visible until every handle closes (the service's
				// instant-freeze guard lets go a moment after the delete), so wait
				// for it: callers report "removed" right after this returns.
				for try := 0; try < 20; try++ {
					if _, err := os.Lstat(f.Path); errors.Is(err, os.ErrNotExist) {
						break
					}
					time.Sleep(50 * time.Millisecond)
				}
			}
		}
	}
	// A just-deleted file can linger for a moment while another handle on it
	// closes (e.g. SENTIENT1's own instant-freeze guard letting go), so retry briefly.
	for i := len(bs.CreatedDirs) - 1; i >= 0; i-- {
		for try := 0; try < 5; try++ {
			if removeEmptyTree(bs.CreatedDirs[i]) {
				break
			}
			if _, err := os.Stat(bs.CreatedDirs[i]); err != nil || !onlyPendingDeletes(bs.CreatedDirs[i], bs) {
				break
			}
			time.Sleep(150 * time.Millisecond)
		}
	}
	return firstErr
}

// removeEmptyTree deletes dir and empty subdirectories, keeping anything with
// files in it (e.g. if the real app has since moved in).
func removeEmptyTree(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	// Our own files (including fake leveldb LOCK files) were already deleted by
	// Remove; anything left belongs to someone else (e.g. the real app) and
	// keeps the folder.
	empty := true
	for _, e := range entries {
		if e.IsDir() && removeEmptyTree(filepath.Join(dir, e.Name())) {
			continue
		}
		empty = false
	}
	if empty {
		return os.Remove(dir) == nil
	}
	return false
}

// Index maps lowercase file paths to bait IDs, for event lookup.
func Index(st *config.State) map[string]string {
	m := map[string]string{}
	for id, bs := range st.Baits {
		if bs.Status == "retired" {
			continue
		}
		for _, f := range bs.Files {
			if f.Audit {
				m[paths.Key(f.Path)] = id
			}
		}
	}
	return m
}

// unchanged reports whether a bait file still has the size and timestamp we recorded.
func unchanged(f config.BaitFile) bool {
	fi, err := os.Stat(f.Path)
	if err != nil {
		return true // already gone; nothing to protect
	}
	return fi.Size() == f.Size && fi.ModTime().Equal(f.ModTime)
}

// Retire removes a decoy whose real app is now installed, plus any baits
// living inside it (e.g. fake MetaMask inside a fake browser the user now
// really uses). Returns the IDs retired.
func Retire(st *config.State, u config.UserInfo, id, why string) []string {
	bs := st.Baits[id]
	if bs == nil || bs.Status == "retired" {
		return nil
	}
	var out []string
	if spec, ok := ByID(id); ok && spec.Root != nil {
		root := spec.Root(u)
		for otherID, other := range st.Baits {
			if otherID == id || other.Status == "retired" || len(other.Files) == 0 {
				continue
			}
			if paths.Under(other.Files[0].Path, root) {
				Remove(other)
				other.Status, other.StatusNote = "retired", "its host decoy was retired: "+why
				out = append(out, otherID)
			}
		}
	}
	Remove(bs)
	bs.Status, bs.StatusNote = "retired", why
	return append(out, id)
}

// onlyPendingDeletes reports whether everything left under dir is one of our
// own bait files (i.e. waiting to vanish), so it's worth retrying.
func onlyPendingDeletes(dir string, bs *config.BaitState) bool {
	ours := map[string]bool{}
	for _, f := range bs.Files {
		if f.Created {
			ours[paths.Key(f.Path)] = true
		}
	}
	only := true
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && !ours[paths.Key(p)] {
			only = false
		}
		return nil
	})
	return only
}
