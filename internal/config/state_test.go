package config

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Many goroutines (which Go moves between OS threads) taking the state lock at
// once: it must be exclusive, and never get stuck.
func TestStateLockIsExclusiveAcrossGoroutines(t *testing.T) {
	old := stateLockName
	stateLockName = fmt.Sprintf(`Local\SENTIENT1TestLock-%d`, time.Now().UnixNano())
	defer func() { stateLockName = old }()

	var inside, maxInside int32
	var wg sync.WaitGroup
	deadline := time.Now().Add(20 * time.Second)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				unlock, err := lockState()
				if err != nil {
					t.Errorf("lock: %v", err)
					return
				}
				n := atomic.AddInt32(&inside, 1)
				for {
					m := atomic.LoadInt32(&maxInside)
					if n <= m || atomic.CompareAndSwapInt32(&maxInside, m, n) {
						break
					}
				}
				time.Sleep(time.Millisecond) // invite the scheduler to move us
				atomic.AddInt32(&inside, -1)
				unlock()
			}
		}()
	}
	wg.Wait()
	if time.Now().After(deadline) {
		t.Fatal("lock was too slow (stuck?)")
	}
	if maxInside != 1 {
		t.Fatalf("%d goroutines held the lock at once", maxInside)
	}
}
