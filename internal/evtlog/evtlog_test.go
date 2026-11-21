package evtlog

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc/eventlog"
)

const sample4663 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4663</EventID><Version>1</Version><Level>0</Level><Task>12800</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-11-16T22:12:53.5145880Z'/><EventRecordID>482913</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='9480'/><Channel>Security</Channel><Computer>DESKTOP-7Q2M1</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1-2-3-1001</Data><Data Name='SubjectUserName'>bob</Data><Data Name='SubjectDomainName'>DESKTOP-7Q2M1</Data><Data Name='SubjectLogonId'>0x3c8a1</Data><Data Name='ObjectServer'>Security</Data><Data Name='ObjectType'>File</Data><Data Name='ObjectName'>C:\Users\bob\Desktop\passwords.txt</Data><Data Name='HandleId'>0x1f84</Data><Data Name='AccessList'>%%4416
				</Data><Data Name='AccessMask'>0x1</Data><Data Name='ProcessId'>0x9eb8</Data><Data Name='ProcessName'>C:\Program Files (x86)\Microsoft\Copilot\Application\copilotapp.exe</Data><Data Name='ResourceAttributes'>S:AI</Data></EventData></Event>`

func TestParse4663(t *testing.T) {
	e, err := Parse(sample4663)
	if err != nil {
		t.Fatal(err)
	}
	oa, ok := e.AsObjectAccess()
	if !ok {
		t.Fatal("not 4663")
	}
	if oa.ProcessID != 40632 || oa.AccessMask != 1 || oa.RecordID != 482913 ||
		oa.ObjectName != `C:\Users\bob\Desktop\passwords.txt` || oa.User != `DESKTOP-7Q2M1\bob` ||
		!strings.HasSuffix(oa.ProcessName, "copilotapp.exe") || oa.Time.Year() != 2026 {
		t.Fatalf("bad decode: %+v", oa)
	}
}

// Exercises the real subscription + bookmark path on the Application log,
// which non-admin users can write to.
func TestSubscribeApplicationLog(t *testing.T) {
	src := "SENTIENT1Test"
	l, err := eventlog.Open(src)
	if err != nil {
		t.Skip("cannot open event source:", err)
	}
	defer l.Close()
	marker := fmt.Sprintf("sentient1-test-%d", time.Now().UnixNano())
	query := fmt.Sprintf("*[System[Provider[@Name='%s']]]", src)

	sub, err := Subscribe("Application", query, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got := make(chan string, 8)
	go sub.Run(ctx, func(x string) { got <- x })
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	l.Info(1, marker)
	for {
		select {
		case x := <-got:
			if strings.Contains(x, marker) {
				t.Logf("event delivered in %v", time.Since(start))
				bm := sub.BookmarkXML()
				if !strings.Contains(bm, "RecordId") {
					t.Fatalf("bookmark not advanced: %q", bm)
				}
				cancel()
				sub.Close()
				// Resuming from the bookmark must not replay the same event.
				l.Info(1, marker+"-2")
				sub2, err := Subscribe("Application", query, bm)
				if err != nil {
					t.Fatal(err)
				}
				defer sub2.Close()
				ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel2()
				got2 := make(chan string, 8)
				go sub2.Run(ctx2, func(x string) { got2 <- x })
				select {
				case x := <-got2:
					if !strings.Contains(x, marker+"-2") {
						t.Fatalf("replayed wrong event after bookmark: %s", x)
					}
				case <-ctx2.Done():
					t.Fatal("event written while unsubscribed was not replayed from bookmark")
				}
				return
			}
		case <-ctx.Done():
			t.Fatal("event not delivered")
		}
	}
}
