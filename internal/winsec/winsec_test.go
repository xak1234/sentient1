package winsec

import (
	"testing"
	"unsafe"
)

func TestEmptyACL(t *testing.T) {
	a := EmptyACL()
	b := (*[8]byte)(unsafe.Pointer(a))
	if b[0] != 2 || *(*uint16)(unsafe.Pointer(&b[2])) != 8 || aclAceCount(a) != 0 {
		t.Fatalf("bad empty ACL header: % x", b[:])
	}
}
