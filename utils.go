package security

import (
	"fmt"
	"strconv"
	"strings"
)

func storekey(key string) string {
	return fmt.Sprintf("SECURITY_%s", strings.ToUpper(key))
}

func (m *Manager) Setting(key string) string {
	if item, ok := m.App.Env.Store[storekey(key)]; ok {
		return item.Value
	}
	if item, ok := m.Settings[strings.ToUpper(key)]; ok {
		return item
	}
	return ""
}

func (m *Manager) BoolSetting(key string) bool {
	b, err := strconv.ParseBool(m.Setting(key))
	if err == nil {
		return b
	}
	return false
}

type msg [2]string

func Msg(text string, label string) msg {
	return [2]string{text, label}
}
