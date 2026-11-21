package engine

import "time"

// EventPredatesProcess detects a delayed/replayed audit record whose PID has
// since been reused. FILETIME counts 100 ns intervals from 1601-01-01.
func EventPredatesProcess(createTime int64, eventTime time.Time) bool {
	if createTime <= 0 || eventTime.IsZero() {
		return false
	}
	const epoch int64 = 116444736000000000
	ticks := createTime - epoch
	created := time.Unix(ticks/10000000, (ticks%10000000)*100)
	return created.After(eventTime.Add(2 * time.Millisecond))
}
