package security

import (
	"strings"
	"time"
)

type Times interface {
	Duration(string) time.Duration
	Expires(string) time.Time
	Expiration(string) string
}

var defaultDuration time.Duration = time.Now().Add(time.Minute * 60).Sub(time.Now())

func parseDuration(value string) time.Duration {
	d, err := time.ParseDuration(value)
	if err != nil {
		return defaultDuration
	}
	return d
}

func NewTimes(s *Manager) Times {
	t := &times{
		timefunc: time.Now,
		values:   make(map[string]time.Duration),
		format:   s.Setting("TIMESTAMP_FORMAT"),
	}
	for k, _ := range s.Settings {
		spl := strings.Split(k, "_")
		if spl[len(spl)-1] == "DURATION" {
			t.values[k] = parseDuration(s.Setting(k))
		}
	}
	return t
}

type times struct {
	timefunc func() time.Time
	format   string
	values   map[string]time.Duration
}

func (t *times) Duration(key string) time.Duration {
	if d, ok := t.values[strings.ToUpper(key)]; ok {
		return d
	}
	return defaultDuration
}

func (t *times) Expires(key string) time.Time {
	return t.timefunc().Add(t.Duration(key))
}

func (t *times) Expiration(key string) string {
	return t.Expires(key).Format(t.format)
}
