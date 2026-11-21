package engine

import (
	"testing"
	"time"
)

func TestDelayedEventDoesNotTargetReusedPID(t *testing.T) {
	now := time.Now()
	ct := now.UnixNano()/100 + 116444736000000000
	if !EventPredatesProcess(ct, now.Add(-time.Second)) {
		t.Fatal("replayed event not rejected")
	}
	if EventPredatesProcess(ct, now.Add(time.Second)) {
		t.Fatal("current event rejected")
	}
	if EventPredatesProcess(0, now) {
		t.Fatal("unknown creation time incorrectly treated as reuse")
	}
}
