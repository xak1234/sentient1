package procinfo

import (
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

// Exercise the real Windows registry API in an isolated test subtree. Nothing
// is registered with COM and no test DLL is loaded or executed.
func TestPackagedCOMAppIDDifferentFromCLSID(t *testing.T) {
	base := fmt.Sprintf(`Software\sentient1-host-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	var created []string
	t.Cleanup(func() {
		for i := len(created) - 1; i >= 0; i-- {
			if err := registry.DeleteKey(registry.CURRENT_USER, created[i]); err != nil {
				t.Errorf("remove test registry key: %v", err)
			}
		}
	})
	const appID = "{11111111-2222-3333-4444-555555555555}"
	const clsID = "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
	const pkg = "Example.Editor_1.0.0.0_neutral__test"
	paths := []string{base, base + `\PackagedCom`, base + `\PackagedCom\Package`,
		base + `\PackagedCom\Package\` + pkg, base + `\PackagedCom\Package\` + pkg + `\Server`,
		base + `\PackagedCom\Package\` + pkg + `\Server\0`, base + `\PackagedCom\Package\` + pkg + `\Class`,
		base + `\PackagedCom\Package\` + pkg + `\Class\` + clsID}
	for _, path := range paths {
		key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, path)
		if path == paths[5] {
			for name, value := range map[string]string{"SurrogateAppId": appID, "ApplicationDisplayName": "Example Editor", "DisplayName": "Document handler"} {
				if err := key.SetStringValue(name, value); err != nil {
					key.Close()
					t.Fatal(err)
				}
			}
		}
		if path == paths[7] {
			if err := key.SetStringValue("DllPath", "editor-handler.dll"); err != nil {
				key.Close()
				t.Fatal(err)
			}
			if err := key.SetDWordValue("ServerId", 0); err != nil {
				key.Close()
				t.Fatal(err)
			}
		}
		key.Close()
	}
	components := packagedAppIDComponents(classRoot{key: registry.CURRENT_USER, path: base}, appID, time.Now().Add(time.Second))
	if len(components) != 1 || components[0].Name != "Example Editor" || components[0].Identifier != clsID || components[0].Loaded {
		t.Fatalf("shared AppID registration: %+v", components)
	}
}
