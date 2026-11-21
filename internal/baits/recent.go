package baits

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"github.com/xak1234/sentient1/internal/paths"
)

// CleanRecent deletes Recent-files shortcuts (.lnk) that point at baits.
// Windows adds a shortcut when you open a file, and apps like Copilot read
// "recent files": that's exactly how the Copilot false alarm happened.
func CleanRecent(roamingAppData string, baitPaths map[string]string) (removed []string) {
	want := map[string]bool{}
	for p := range baitPaths {
		want[paths.Key(p)] = true
	}
	dir := filepath.Join(roamingAppData, `Microsoft\Windows\Recent`)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".lnk") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		t := LnkTarget(b)
		if t == "" {
			continue
		}
		if want[paths.Key(t)] {
			if os.Remove(p) == nil {
				removed = append(removed, p)
			}
		}
	}
	return removed
}

// LnkTarget extracts the local target path from a Shell Link (.lnk) file.
// See [MS-SHLLINK]. Returns "" if it can't be determined.
func LnkTarget(b []byte) string {
	le := binary.LittleEndian
	if len(b) < 0x4C || le.Uint32(b) != 0x4C {
		return ""
	}
	flags := le.Uint32(b[20:])
	const hasIDList, hasLinkInfo = 1 << 0, 1 << 1
	off := 0x4C
	if flags&hasIDList != 0 {
		if len(b) < off+2 {
			return ""
		}
		off += 2 + int(le.Uint16(b[off:]))
	}
	if flags&hasLinkInfo == 0 || len(b) < off+28 {
		return ""
	}
	li := b[off:]
	size := int(le.Uint32(li))
	hdr := le.Uint32(li[4:])
	liFlags := le.Uint32(li[8:])
	if size > len(li) || liFlags&1 == 0 { // VolumeIDAndLocalBasePath
		return ""
	}
	li = li[:size]
	baseOff, suffixOff := int(le.Uint32(li[16:])), int(le.Uint32(li[24:]))
	if hdr >= 0x24 && len(li) >= 36 {
		if uBase := int(le.Uint32(li[28:])); uBase > 0 && uBase < len(li) {
			s := utf16z(li[uBase:])
			if uSuf := int(le.Uint32(li[32:])); uSuf > 0 && uSuf < len(li) {
				s = joinSuffix(s, utf16z(li[uSuf:]))
			}
			return s
		}
	}
	if baseOff <= 0 || baseOff >= len(li) {
		return ""
	}
	s := cstr(li[baseOff:])
	if suffixOff > 0 && suffixOff < len(li) {
		s = joinSuffix(s, cstr(li[suffixOff:]))
	}
	return s
}

func joinSuffix(base, suffix string) string {
	if suffix == "" {
		return base
	}
	if strings.HasSuffix(base, `\`) {
		return base + suffix
	}
	return base + `\` + suffix
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func utf16z(b []byte) string {
	var u []uint16
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}
