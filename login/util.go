package login

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func (l *Manager) Setting(key string) string {
	if item, err := l.App.Env.Store.Query(storekey(key)); err == nil {
		return item.String()
	}
	if item, ok := l.Settings[strings.ToUpper(key)]; ok {
		return item
	}
	return ""
}

func (l *Manager) Int64Setting(key string) int64 {
	v := l.Setting(key)
	if v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			return i
		}
	}
	return 0
}

func storekey(key string) string {
	return fmt.Sprintf("LOGIN_%s", strings.ToUpper(key))
}

func cookieseconds(d string) int {
	base, err := strconv.Atoi(d)
	if err != nil {
		base = 31
	}
	return int((time.Duration(base*24) * time.Hour) / time.Second)
}
