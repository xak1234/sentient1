package procinfo

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unsafe"

	"github.com/xak1234/sentient1/internal/authenticode"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// HostedComponent identifies code hosted by an executable. Registry names and
// version resources are labels, not proof of trust or of which function read a file.
type HostedComponent struct {
	Name       string               `json:"name"`
	Identifier string               `json:"identifier,omitempty"`
	Module     string               `json:"module,omitempty"`
	Source     string               `json:"source"`
	Loaded     bool                 `json:"loaded"`
	Signature  *authenticode.Result `json:"signature,omitempty"`
}

type HostedInfo struct {
	Kind       string            `json:"kind"`
	Identifier string            `json:"identifier,omitempty"`
	Status     string            `json:"status"`
	Components []HostedComponent `json:"components,omitempty"`
	Note       string            `json:"note"`
	CheckedAt  time.Time         `json:"checkedAt"`
	Historical bool              `json:"historical,omitempty"`
}

// SharedHost describes common executable hosts; it never classifies them as safe.
func SharedHost(image string) bool {
	switch strings.ToLower(BaseName(image)) {
	case "dllhost.exe", "rundll32.exe", "svchost.exe":
		return true
	}
	return false
}

// Label keeps registration-only attribution visibly separate from observed code.
func (h *HostedInfo) Label() string {
	if h == nil || len(h.Components) == 0 {
		return "hosted component unknown"
	}
	if len(h.Components) > 1 {
		return fmt.Sprintf("%d hosted components", len(h.Components))
	}
	name := h.Components[0].Name
	if h.Status != "observed" {
		name += " (registered)"
	}
	return name
}

// Details is shared by desktop, terminal and notification renderers.
func (h *HostedInfo) Details() string { return h.details(0) }

// BriefDetails keeps a shared-service host from producing a screen-sized popup.
func (h *HostedInfo) BriefDetails() string { return h.details(3) }

func (h *HostedInfo) details(limit int) string {
	if h == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Hosted component: %s\n", h.Label())
	for i, c := range h.Components {
		if limit > 0 && i >= limit {
			fmt.Fprintf(&b, "%d more components recorded; open Detections for the full evidence.\n", len(h.Components)-i)
			break
		}
		fmt.Fprintf(&b, "%s\n", c.Name)
		if c.Module != "" {
			fmt.Fprintf(&b, "Component file: %s\n", c.Module)
		}
		if c.Identifier != "" {
			fmt.Fprintf(&b, "Component ID: %s\n", c.Identifier)
		}
		fmt.Fprintf(&b, "Evidence: %s\n", c.Source)
		if c.Signature != nil {
			fmt.Fprintf(&b, "Component signature: %s\n", c.Signature.String())
		}
	}
	fmt.Fprintln(&b, h.Note)
	return b.String()
}

var comGUID = regexp.MustCompile(`(?i)^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$`)

func surrogateID(command string) string {
	args, err := windows.DecomposeCommandLine(command)
	if err != nil {
		return ""
	}
	var id string
	for _, arg := range args[min(1, len(args)):] {
		if !strings.HasPrefix(strings.ToLower(arg), "/processid:") {
			continue
		}
		value := strings.ToUpper(arg[len("/processid:"):])
		if !comGUID.MatchString(value) || (id != "" && id != value) {
			return ""
		}
		id = value
	}
	return id
}

func rundllModule(command string) string {
	args, err := windows.DecomposeCommandLine(command)
	if err != nil || len(args) < 2 {
		return ""
	}
	path, _, _ := strings.Cut(args[1], ",")
	if !strings.EqualFold(filepath.Ext(path), ".dll") || strings.ContainsAny(path, "\r\n\x00") {
		return ""
	}
	return path
}

// ResolveHosted reads registry/module/service metadata only. expectedCreation
// must be the reader's captured creation time; PID reuse never supplies evidence.
// A zero PID performs registration-only enrichment for older saved alerts.
func ResolveHosted(pid uint32, image, command string, expectedCreation int64) *HostedInfo {
	if !SharedHost(image) {
		return nil
	}
	h := &HostedInfo{Kind: strings.TrimSuffix(strings.ToLower(BaseName(image)), ".exe"),
		Status: "unknown", CheckedAt: time.Now().UTC(), Historical: pid == 0,
		Note: "The hosted component could not be identified. The host name alone does not identify the code that accessed the file."}
	var modules []string
	view := uint32(registry.WOW64_64KEY)
	var sid string
	live := pid != 0 && expectedCreation != 0 && Alive(pid, expectedCreation)
	if live {
		actual, err := ImagePath(pid)
		live = err == nil && strings.EqualFold(actual, image)
	}
	if live {
		modules, _ = loadedModules(pid)
		sid, view = processRegistryContext(pid)
	}
	switch h.Kind {
	case "dllhost":
		h.Identifier = surrogateID(command)
		if h.Identifier != "" {
			h.Components = comComponents(h.Identifier, sid, view)
		}
	case "rundll32":
		if path := rundllModule(command); path != "" {
			h.Components = []HostedComponent{{Name: BaseName(path), Module: path, Source: "DLL named in the recorded command line"}}
		}
	case "svchost":
		if live {
			h.Components, _ = hostedServices(pid)
		}
	}
	for i := range h.Components {
		c := &h.Components[i]
		if module := matchModule(c.Module, modules); module != "" {
			c.Module, c.Loaded = module, true
			c.Source += "; matching module observed in the process"
			if localModule(module) {
				sig := authenticode.Verify(module)
				c.Signature = &sig
				if c.Name == "" || strings.EqualFold(c.Name, BaseName(module)) {
					if product := fileProduct(module); product != "" {
						c.Name = product
					}
				}
			}
		}
		c.Name = displayText(c.Name)
		if c.Name == "" {
			c.Name = displayText(BaseName(c.Module))
		}
		if c.Name == "" {
			c.Name = "Unnamed component"
		}
	}
	// Discard all live evidence if the process disappeared or changed identity
	// during collection. Do not substitute another process with the same PID.
	if live && !Alive(pid, expectedCreation) {
		h.Components = nil
		h.Note = "The process exited or its PID changed during inspection; hosted-component evidence is unavailable."
		return h
	}
	if len(h.Components) > 0 {
		h.Status = "registered"
		h.Note = "Current registration or command-line metadata only; the component was not confirmed loaded. Names do not establish trust."
		observed := true
		for _, c := range h.Components {
			observed = observed && (c.Loaded || (live && h.Kind == "svchost"))
		}
		if observed {
			h.Status = "observed"
			h.Note = "Hosted components observed during inspection. This does not establish which component or function performed the file access."
		}
		if h.Historical {
			h.Note = "Resolved now from the saved command line and current machine registration; this identity was not captured at the time of the alert."
		}
		if len(h.Components) > 1 {
			h.Note += " More than one component is listed; no single reader is attributed."
		}
	}
	return h
}

func loadedModules(pid uint32) ([]string, error) {
	var handle windows.Handle
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		handle, err = windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
		if !errors.Is(err, windows.ERROR_BAD_LENGTH) {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)
	var m windows.ModuleEntry32
	m.Size = uint32(unsafe.Sizeof(m))
	var out []string
	for err = windows.Module32First(handle, &m); err == nil && len(out) < 4096; err = windows.Module32Next(handle, &m) {
		out = append(out, windows.UTF16ToString(m.ExePath[:]))
	}
	return out, nil
}

func matchModule(registered string, modules []string) string {
	registered = strings.Trim(strings.TrimSpace(registered), `"`)
	if expanded, err := registry.ExpandString(registered); err == nil {
		registered = expanded
	}
	if registered == "" {
		return ""
	}
	var matched string
	for _, path := range modules {
		match := strings.EqualFold(filepath.Clean(path), filepath.Clean(registered))
		if !filepath.IsAbs(registered) && filepath.Base(registered) == registered {
			match = strings.EqualFold(filepath.Base(path), registered)
		}
		if match {
			if matched != "" && !strings.EqualFold(matched, path) {
				return "" // ambiguous basename; never choose the first loaded DLL
			}
			matched = path
		}
	}
	return matched
}

func processRegistryContext(pid uint32) (string, uint32) {
	view := uint32(registry.WOW64_64KEY)
	h, err := open(pid, windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err != nil {
		return "", view
	}
	defer windows.CloseHandle(h)
	var wow bool
	if windows.IsWow64Process(h, &wow) == nil && wow {
		view = registry.WOW64_32KEY
	}
	var token windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token) != nil {
		return "", view
	}
	defer token.Close()
	u, err := token.GetTokenUser()
	if err != nil {
		return "", view
	}
	return u.User.Sid.String(), view
}

type classRoot struct {
	key  registry.Key
	path string
	view uint32
}

func (r classRoot) open(path string) (registry.Key, error) {
	return registry.OpenKey(r.key, r.path+`\`+path, registry.READ|r.view)
}

func regString(key registry.Key, name string) string {
	v, _, _ := key.GetStringValue(name)
	return v
}

func subkeys(key registry.Key, limit int) []string {
	names, _ := key.ReadSubKeyNames(limit)
	return names
}

// Registration lookup is bounded and observes per-user overrides before machine
// registration. It never loads a DLL or runs a command from the registry.
func comComponents(id, sid string, view uint32) []HostedComponent {
	roots := []classRoot{{registry.LOCAL_MACHINE, `SOFTWARE\Classes`, view}}
	if sid != "" {
		roots = append([]classRoot{{registry.USERS, sid + `_Classes`, view}}, roots...)
	}
	deadline := time.Now().Add(750 * time.Millisecond)
	seen := map[string]bool{}
	var out []HostedComponent
	for _, root := range roots {
		// Packaged COM classes (including modern Explorer context-menu apps).
		if index, err := root.open(`PackagedCom\ClassIndex\` + id); err == nil {
			packages := subkeys(index, 64)
			index.Close()
			for _, pkg := range packages {
				out = append(out, packagedComponents(root, pkg, id)...)
			}
		}
		if len(out) == 0 {
			out = append(out, packagedAppIDComponents(root, id, deadline)...)
		}
		if len(out) > 0 {
			break
		}
		// A surrogate AppID can differ from every hosted CLSID. Search the
		// registered classes for that AppID rather than assuming they are equal.
		classes, err := root.open(`CLSID`)
		if err != nil {
			continue
		}
		names := append([]string{id}, subkeys(classes, 16384)...)
		classes.Close()
		for _, clsid := range names {
			if len(out) >= 8 || time.Now().After(deadline) {
				break
			}
			keyID := strings.ToUpper(clsid)
			if seen[keyID] {
				continue
			}
			key, err := root.open(`CLSID\` + clsid)
			if err != nil {
				continue
			}
			seen[keyID] = true
			name, appID := regString(key, ""), regString(key, "AppID")
			key.Close()
			if !strings.EqualFold(id, clsid) && !strings.EqualFold(id, appID) {
				continue
			}
			server, err := root.open(`CLSID\` + clsid + `\InprocServer32`)
			if err != nil {
				continue
			}
			module := regString(server, "")
			server.Close()
			if module != "" {
				out = append(out, HostedComponent{Name: name, Identifier: clsid, Module: module, Source: "COM class registration"})
			}
		}
	}
	return uniqueComponents(out)
}

func packagedComponents(root classRoot, pkg, id string) []HostedComponent {
	base := `PackagedCom\Package\` + pkg
	class, err := root.open(base + `\Class\` + id)
	if err != nil {
		return nil
	}
	module := regString(class, "DllPath")
	serverID, _, serverErr := class.GetIntegerValue("ServerId")
	class.Close()
	if serverErr != nil || module == "" {
		return nil
	}
	server, err := root.open(fmt.Sprintf(`%s\Server\%d`, base, serverID))
	if err != nil {
		return nil
	}
	defer server.Close()
	name := regString(server, "ApplicationDisplayName")
	if name == "" || strings.HasPrefix(name, "@") || strings.HasPrefix(name, "ms-resource:") {
		name = strings.SplitN(pkg, "_", 2)[0]
	}
	return []HostedComponent{{Name: name, Identifier: id, Module: module, Source: "Packaged COM registration: " + displayText(regString(server, "DisplayName"))}}
}

// Packaged COM also permits an AppID shared by classes with different CLSIDs.
func packagedAppIDComponents(root classRoot, id string, deadline time.Time) []HostedComponent {
	packages, err := root.open(`PackagedCom\Package`)
	if err != nil {
		return nil
	}
	names := subkeys(packages, 512)
	packages.Close()
	var out []HostedComponent
	for _, pkg := range names {
		if time.Now().After(deadline) || len(out) >= 8 {
			break
		}
		base := `PackagedCom\Package\` + pkg
		servers, err := root.open(base + `\Server`)
		if err != nil {
			continue
		}
		serverNames := subkeys(servers, 256)
		servers.Close()
		matching := map[uint64]bool{}
		for _, serverName := range serverNames {
			server, err := root.open(base + `\Server\` + serverName)
			if err != nil {
				continue
			}
			appID := regString(server, "SurrogateAppId")
			server.Close()
			if strings.EqualFold(appID, id) {
				number, err := strconv.ParseUint(serverName, 10, 32)
				if err == nil {
					matching[number] = true
				}
			}
		}
		if len(matching) == 0 {
			continue
		}
		classes, err := root.open(base + `\Class`)
		if err != nil {
			continue
		}
		classNames := subkeys(classes, 4096)
		classes.Close()
		for _, clsid := range classNames {
			if time.Now().After(deadline) || len(out) >= 8 {
				break
			}
			class, err := root.open(base + `\Class\` + clsid)
			if err != nil {
				continue
			}
			serverID, _, err := class.GetIntegerValue("ServerId")
			class.Close()
			if err == nil && matching[serverID] {
				out = append(out, packagedComponents(root, pkg, clsid)...)
			}
		}
	}
	return out
}

func uniqueComponents(in []HostedComponent) []HostedComponent {
	var out []HostedComponent
	seen := map[string]bool{}
	for _, c := range in {
		key := strings.ToLower(c.Module + "|" + c.Name)
		if !seen[key] && len(out) < 8 {
			seen[key] = true
			out = append(out, c)
		}
	}
	return out
}

func hostedServices(pid uint32) ([]HostedComponent, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, err
	}
	defer windows.CloseServiceHandle(h)
	buffer := make([]byte, 256*1024)
	var needed, count, resume uint32
	var out []HostedComponent
	for page := 0; page < 8; page++ {
		err = windows.EnumServicesStatusEx(h, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32, windows.SERVICE_ACTIVE,
			&buffer[0], uint32(len(buffer)), &needed, &count, &resume, nil)
		if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
			return out, err
		}
		if count > uint32(len(buffer))/uint32(unsafe.Sizeof(windows.ENUM_SERVICE_STATUS_PROCESS{})) {
			return out, fmt.Errorf("invalid service enumeration size")
		}
		entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buffer[0])), int(count))
		for _, s := range entries {
			if s.ServiceStatusProcess.ProcessId != pid {
				continue
			}
			name := windows.UTF16PtrToString(s.ServiceName)
			component := HostedComponent{Name: windows.UTF16PtrToString(s.DisplayName), Identifier: name, Source: "Service Control Manager matched the running PID"}
			if key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name+`\Parameters`, registry.QUERY_VALUE); err == nil {
				component.Module = regString(key, "ServiceDll")
				key.Close()
			}
			out = append(out, component)
		}
		if err == nil || resume == 0 {
			break
		}
	}
	return out, nil
}

func localModule(path string) bool {
	return len(path) > 3 && path[1] == ':' && path[2] == '\\' && strings.EqualFold(filepath.Ext(path), ".dll")
}

func displayText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	r := []rune(strings.TrimSpace(s))
	if len(r) > 160 {
		r = append(r[:157], '.', '.', '.')
	}
	return string(r)
}

func fileProduct(path string) string {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 || size > 4<<20 {
		return ""
	}
	data := make([]byte, size)
	if windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&data[0])) != nil {
		return ""
	}
	defer runtime.KeepAlive(data)
	var translation *uint16
	var bytes uint32
	if windows.VerQueryValue(unsafe.Pointer(&data[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&translation), &bytes) != nil || translation == nil || bytes < 4 {
		return ""
	}
	lang := unsafe.Slice(translation, 2)
	var value *uint16
	var chars uint32
	key := fmt.Sprintf(`\StringFileInfo\%04x%04x\ProductName`, lang[0], lang[1])
	if windows.VerQueryValue(unsafe.Pointer(&data[0]), key, unsafe.Pointer(&value), &chars) != nil || value == nil || chars == 0 || chars > 4096 {
		return ""
	}
	return displayText(windows.UTF16ToString(unsafe.Slice(value, chars)))
}
