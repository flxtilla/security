package login

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func (l *Manager) Setting(key string) string {
	if item, ok := l.App.Env.Store[storekey(key)]; ok {
		return item.Value
	}
	if item, ok := l.Settings[strings.ToUpper(key)]; ok {
		return item
	}
	return ""
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
