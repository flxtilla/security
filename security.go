package security

import (
	"strings"

	"github.com/thrisp/flotilla"
	"github.com/thrisp/login"
	"github.com/thrisp/principal"
)

var (
	defaultsettings map[string]string = map[string]string{
		"confirmable":  "f",
		"registerable": "f",
		"recoverable":  "f",
		"trackable":    "f",
		"passwordable": "t",
		"changeable":   "f",
	}
	msg             [2]string
	defaultmessages map[string]msg = map[string]msg{
		"unauthorized": []string{"You do not have permission to view this resource.", "error"},
	}
	Form         string
	defaultforms map[string]Form
)

type Manager struct {
	app       *flotilla.App
	login     *login.Manager
	principal *principal.Manager
}

func securityctxfuncs(m *Manager) map[string]interface{}

func New(c ...Configuration) *Manager {}

func (m *Manager) Init(app *flotilla.App)

func (m *Manager) Setting(key string) string {
	if item, ok := m.App.Env.Store[storekey(key)]; ok {
		return item.Value
	}
	if item, ok := m.Settings[strings.ToUpper(key)]; ok {
		return item
	}
	return ""
}

type State struct{}
