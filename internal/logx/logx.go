// Package logx is a tiny size-capped file logger for the service.
package logx

import (
	"fmt"
	"os"
	"sync"
	"time"
)

type Logger struct {
	mu   sync.Mutex
	path string
	max  int64
	echo bool
}

func New(path string, echo bool) *Logger { return &Logger{path: path, max: 5 << 20, echo: echo} }

func (l *Logger) Printf(format string, args ...any) {
	line := time.Now().Format("2006-01-02 15:04:05.000 ") + fmt.Sprintf(format, args...) + "\n"
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.echo {
		fmt.Print(line)
	}
	if fi, err := os.Stat(l.path); err == nil && fi.Size() > l.max {
		os.Remove(l.path + ".1")
		os.Rename(l.path, l.path+".1")
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	f.WriteString(line)
	f.Close()
}
