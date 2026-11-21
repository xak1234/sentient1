// Package svcctl manages the SENTIENT1 Windows service.
package svcctl

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/xak1234/sentient1/internal/paths"
)

// State is a human-readable service state.
type State string

const (
	NotInstalled State = "not installed"
	Running      State = "running"
	Stopped      State = "stopped"
	Starting     State = "starting"
	Stopping     State = "stopping"
	Unknown      State = "unknown"
)

// Status works without admin rights.
func Status() (State, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return Unknown, err
	}
	defer windows.CloseServiceHandle(h)
	name, _ := windows.UTF16PtrFromString(paths.ServiceName)
	s, err := windows.OpenService(h, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return NotInstalled, nil
		}
		return Unknown, err
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(s, &st); err != nil {
		return Unknown, err
	}
	switch st.CurrentState {
	case windows.SERVICE_RUNNING:
		return Running, nil
	case windows.SERVICE_STOPPED:
		return Stopped, nil
	case windows.SERVICE_START_PENDING:
		return Starting, nil
	case windows.SERVICE_STOP_PENDING:
		return Stopping, nil
	}
	return Unknown, nil
}

// InstallOrUpdate registers the service to run exe at boot, as LocalSystem,
// restarting automatically if it ever dies.
func InstallOrUpdate(exe string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(paths.ServiceName)
	if err == nil {
		defer s.Close()
		c, err := s.Config()
		if err != nil {
			return err
		}
		c.BinaryPathName = fmt.Sprintf(`"%s" service run`, exe)
		c.DisplayName, c.Description, c.StartType = paths.ServiceDisplayName, paths.ServiceDescription, mgr.StartAutomatic
		if err := s.UpdateConfig(c); err != nil {
			return err
		}
	} else {
		s, err = m.CreateService(paths.ServiceName, exe, mgr.Config{
			DisplayName: paths.ServiceDisplayName,
			Description: paths.ServiceDescription,
			StartType:   mgr.StartAutomatic,
		}, "service", "run")
		if err != nil {
			return err
		}
		defer s.Close()
	}
	return s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 3600)
}

func open() (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, err
	}
	s, err := m.OpenService(paths.ServiceName)
	if err != nil {
		m.Disconnect()
		return nil, nil, err
	}
	return m, s, nil
}

func Start() error {
	m, s, err := open()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	if st, _ := Status(); st == Running {
		return nil
	}
	if err := s.Start(); err != nil {
		return err
	}
	return waitFor(svc.Running, 20*time.Second)
}

func Stop() error {
	m, s, err := open()
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	if st, _ := Status(); st == Stopped || st == NotInstalled {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	return waitFor(svc.Stopped, 30*time.Second)
}

func Delete() error {
	Stop()
	m, s, err := open()
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	return s.Delete()
}

// Control sends a control code (e.g. svc.ParamChange to reload config).
func Control(c svc.Cmd) error {
	m, s, err := open()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	_, err = s.Control(c)
	return err
}

func waitFor(want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m, s, err := open()
		if err != nil {
			return err
		}
		q, err := s.Query()
		s.Close()
		m.Disconnect()
		if err != nil {
			return err
		}
		if q.State == want {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("service did not reach the expected state within %v (see %s)", timeout, paths.LogFile())
}
