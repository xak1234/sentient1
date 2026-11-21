// Package evtlog subscribes to Windows event log channels (pull model) with
// bookmarks so no event is missed across service restarts, and parses the
// Security 4663 "object access" events that bait reads produce.
package evtlog

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wevtapi               = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe      = wevtapi.NewProc("EvtSubscribe")
	procEvtNext           = wevtapi.NewProc("EvtNext")
	procEvtRender         = wevtapi.NewProc("EvtRender")
	procEvtClose          = wevtapi.NewProc("EvtClose")
	procEvtCreateBookmark = wevtapi.NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark = wevtapi.NewProc("EvtUpdateBookmark")
)

const (
	evtSubscribeToFutureEvents     = 1
	evtSubscribeStartAfterBookmark = 3
	evtRenderEventXML              = 1
	evtRenderBookmark              = 2
	errorNoMoreItems               = 259
	errorInsufficientBuffer        = 122
	errorEvtQueryResultStale       = 15011
	errorEvtQueryResultInvalidPos  = 15012
)

type handle uintptr

func evtClose(h handle) {
	if h != 0 {
		procEvtClose.Call(uintptr(h))
	}
}

// Subscription streams raw event XML from a channel.
type Subscription struct {
	sub      handle
	signal   windows.Handle
	bookmark handle

	mu     sync.Mutex
	lastBM string // rendered after each batch, so readers never touch the handle concurrently
}

// Subscribe starts a subscription. If bookmarkXML is non-empty, delivery
// resumes right after it (events that happened while we were stopped are
// replayed); otherwise only future events are delivered.
func Subscribe(channel, query, bookmarkXML string) (*Subscription, error) {
	signal, err := windows.CreateEvent(nil, 1, 1, nil)
	if err != nil {
		return nil, err
	}
	s := &Subscription{signal: signal, lastBM: bookmarkXML}
	var bmArg *uint16
	if bookmarkXML != "" {
		bmArg, _ = windows.UTF16PtrFromString(bookmarkXML)
	}
	bm, _, e := procEvtCreateBookmark.Call(uintptr(unsafe.Pointer(bmArg)))
	if bm == 0 && bookmarkXML != "" {
		// Corrupt bookmark: start fresh rather than fail.
		bookmarkXML, s.lastBM = "", ""
		bm, _, e = procEvtCreateBookmark.Call(0)
	}
	if bm == 0 {
		windows.CloseHandle(signal)
		return nil, fmt.Errorf("EvtCreateBookmark: %w", e)
	}
	s.bookmark = handle(bm)

	ch, _ := windows.UTF16PtrFromString(channel)
	q, _ := windows.UTF16PtrFromString(query)
	flags, bmUse := uintptr(evtSubscribeToFutureEvents), uintptr(0)
	if bookmarkXML != "" {
		flags, bmUse = evtSubscribeStartAfterBookmark, bm
	}
	h, _, e := procEvtSubscribe.Call(0, uintptr(signal), uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)), bmUse, 0, 0, flags)
	if h == 0 && bookmarkXML != "" {
		// e.g. the log was cleared and the bookmark points nowhere.
		h, _, e = procEvtSubscribe.Call(0, uintptr(signal), uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)), 0, 0, 0, evtSubscribeToFutureEvents)
	}
	if h == 0 {
		s.Close()
		return nil, fmt.Errorf("EvtSubscribe(%s): %w", channel, e)
	}
	s.sub = handle(h)
	return s, nil
}

func (s *Subscription) Close() {
	evtClose(s.sub)
	evtClose(s.bookmark)
	if s.signal != 0 {
		windows.CloseHandle(s.signal)
	}
	s.sub, s.bookmark, s.signal = 0, 0, 0
}

// Run delivers each event's XML to fn until ctx is done. After fn returns the
// bookmark advances past that event.
func (s *Subscription) Run(ctx context.Context, fn func(xml string)) error {
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(stop)
	go func() {
		<-ctx.Done()
		windows.SetEvent(stop)
	}()
	events := make([]handle, 64)
	for {
		ev, err := windows.WaitForMultipleObjects([]windows.Handle{s.signal, stop}, false, windows.INFINITE)
		if err != nil {
			return err
		}
		if ev == windows.WAIT_OBJECT_0+1 {
			return ctx.Err()
		}
		for {
			var n uint32
			r, _, e := procEvtNext.Call(uintptr(s.sub), uintptr(len(events)), uintptr(unsafe.Pointer(&events[0])), 0, 0, uintptr(unsafe.Pointer(&n)))
			if r == 0 {
				var errno windows.Errno
				if errors.As(e, &errno) && (errno == errorNoMoreItems || errno == windows.ERROR_TIMEOUT) {
					break
				}
				if errors.As(e, &errno) && (errno == errorEvtQueryResultStale || errno == errorEvtQueryResultInvalidPos) {
					return fmt.Errorf("event subscription went stale (log cleared?): %w", e)
				}
				return fmt.Errorf("EvtNext: %w", e)
			}
			for i := uint32(0); i < n; i++ {
				x, err := render(events[i], evtRenderEventXML)
				if err == nil {
					fn(x)
				}
				procEvtUpdateBookmark.Call(uintptr(s.bookmark), uintptr(events[i]))
				evtClose(events[i])
			}
			if n > 0 {
				if x, err := render(s.bookmark, evtRenderBookmark); err == nil {
					s.mu.Lock()
					s.lastBM = x
					s.mu.Unlock()
				}
			}
		}
		windows.ResetEvent(s.signal)
	}
}

// BookmarkXML returns the current position, to persist and pass to Subscribe later.
func (s *Subscription) BookmarkXML() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastBM
}

func render(h handle, flag uintptr) (string, error) {
	buf := make([]uint16, 4096)
	for {
		var used, props uint32
		r, _, e := procEvtRender.Call(0, uintptr(h), flag, uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			return windows.UTF16ToString(buf[:used/2]), nil
		}
		var errno windows.Errno
		if errors.As(e, &errno) && errno == errorInsufficientBuffer && int(used/2) > len(buf) {
			buf = make([]uint16, used/2+1)
			continue
		}
		return "", fmt.Errorf("EvtRender: %w", e)
	}
}

// ---- Event XML parsing ----

type rawEvent struct {
	System struct {
		EventID       int    `xml:"EventID"`
		EventRecordID uint64 `xml:"EventRecordID"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Channel string `xml:"Channel"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

// Event is a parsed event with named EventData fields.
type Event struct {
	ID       int
	RecordID uint64
	Time     time.Time
	Channel  string
	Data     map[string]string
}

func Parse(x string) (*Event, error) {
	var r rawEvent
	if err := xml.Unmarshal([]byte(x), &r); err != nil {
		return nil, err
	}
	e := &Event{ID: r.System.EventID, RecordID: r.System.EventRecordID, Channel: r.System.Channel, Data: map[string]string{}}
	e.Time, _ = time.Parse(time.RFC3339Nano, r.System.TimeCreated.SystemTime)
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	for _, d := range r.Data {
		e.Data[d.Name] = strings.TrimSpace(d.Value)
	}
	return e, nil
}

// ObjectAccess is a decoded Security 4663 event.
type ObjectAccess struct {
	RecordID    uint64
	Time        time.Time
	ObjectName  string
	ObjectType  string
	ProcessID   uint32
	ProcessName string
	User        string
	UserSID     string
	AccessMask  uint32
}

// AsObjectAccess decodes a 4663 event.
func (e *Event) AsObjectAccess() (*ObjectAccess, bool) {
	if e.ID != 4663 {
		return nil, false
	}
	oa := &ObjectAccess{
		RecordID:    e.RecordID,
		Time:        e.Time,
		ObjectName:  e.Data["ObjectName"],
		ObjectType:  e.Data["ObjectType"],
		ProcessName: e.Data["ProcessName"],
		UserSID:     e.Data["SubjectUserSid"],
	}
	if u := e.Data["SubjectUserName"]; u != "" {
		oa.User = u
		if d := e.Data["SubjectDomainName"]; d != "" {
			oa.User = d + `\` + u
		}
	}
	oa.ProcessID = uint32(parseNum(e.Data["ProcessId"]))
	oa.AccessMask = uint32(parseNum(e.Data["AccessMask"]))
	return oa, true
}

func parseNum(s string) uint64 {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		v, _ := strconv.ParseUint(s[2:], 16, 64)
		return v
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

// BaitQuery is the XPath subscription filter for bait access events.
const BaitQuery = "*[System[EventID=4663]]"
