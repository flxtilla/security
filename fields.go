package security

import (
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/thrisp/fork"
	"github.com/thrisp/security/user"
)

func UserName(s *Manager, name string, options ...string) fork.Field {
	return &userName{
		name: name,
		Processor: fork.NewProcessor(
			userNamewidget(s, options...),
			[]interface{}{
				ValidEmail,
				s.ValidUserName,
			},
			nil,
		),
	}
}

func userNamewidget(s *Manager, options ...string) fork.Widget {
	return fork.NewWidget(
		fmt.Sprintf(
			`<input type="email" name="{{ .Name }}" value="{{ .UserName }}" placeholder="email address" %s>`,
			strings.Join(options, " "),
		))
}

type userName struct {
	name         string
	UserName     string
	user         user.User
	validateable bool
	fork.Processor
}

func (u *userName) New() fork.Field {
	var newfield userName = *u
	newfield.UserName = ""
	newfield.user = user.AnonymousUser
	newfield.validateable = false
	return &newfield
}

func (u *userName) Name(name ...string) string {
	if len(name) > 0 {
		u.name = strings.Join(name, "-")
	}
	return u.name
}

func (u *userName) Get() *fork.Value {
	return fork.NewValue(u.user)
}

func (u *userName) Set(r *http.Request) {
	v := u.Filter(u.Name(), r)
	u.UserName = v.String()
	u.validateable = true
}

func (u *userName) Validateable() bool {
	return u.validateable
}

func ValidEmail(u *userName) error {
	if u.validateable {
		_, err := mail.ParseAddress(u.UserName)
		if err != nil {
			return fmt.Errorf("Invalid email address: %s", err.Error())
		}
	}
	return nil
}

func (s *Manager) ValidUserName(u *userName) error {
	if u.validateable {
		if u.UserName == "" {
			return MsgError(s, "email_not_provided")
		}
		user := s.Get(u.UserName)
		if user.Anonymous() {
			return MsgError(s, "user_does_not_exist")
		}
		if !user.Active() {
			return MsgError(s, "disabled_account")
		}
		u.user = user
	}
	return nil
}

func PassWord(name string, options ...string) fork.Field {
	return fork.PassWordField(name, nil, nil, options...)
}

var confirmOne = PassWord("confirmable-one", `placeholder="password"`)
var confirmTwo = PassWord("confirmable-two", `placeholder="confirm password"`)

type next struct {
	m            *Manager
	name         string
	Url          string
	validateable bool
	fork.Processor
}

func nextwidget(options ...string) fork.Widget {
	return fork.NewWidget(fmt.Sprintf(`<input type="hidden" name="{{ .Name }}" value="{{ .Url }}" %s>`, strings.Join(options, " ")))
}

func Next(s *Manager, name string, options ...string) fork.Field {
	return &next{
		m:    s,
		name: name,
		Processor: fork.NewProcessor(
			nextwidget(options...),
			nil,
			[]interface{}{nextfilter},
		),
	}
}

func nextfilter(in string) string {
	if in == "" {
		return "/"
	}
	return in
}

func (n *next) New() fork.Field {
	var newfield next = *n
	newfield.Url = ""
	newfield.validateable = false
	return &newfield
}

func (n *next) Name(name ...string) string {
	if len(name) > 0 {
		n.name = strings.Join(name, "-")
	}
	return n.name
}

func (n *next) Get() *fork.Value {
	return fork.NewValue(n.Url)
}

func (n *next) Set(r *http.Request) {
	var nxturl string
	nxturl = n.Filter(n.Name(), r).String()
	if nxt, ok := nxtByQueryParam(r); ok {
		nxturl = nxt
	}
	if nxt, ok := nxtByPath(r, n.m); ok {
		nxturl = nxt
	}
	n.Url = nxturl
	n.validateable = true
}

func (n *next) Validateable() bool {
	return n.validateable
}

type leasedToken struct {
	m            *Manager
	name         string
	key          string
	validateable bool
	returned     string
	fork.Processor
}

func leasedTokenWidget(options ...string) fork.Widget {
	return fork.NewWidget(fmt.Sprintf(`<input type="hidden" name="{{ .Name }}" value="{{ .Token }}" %s>`, strings.Join(options, " ")))
}

func LeasedToken(m *Manager, name string, options ...string) fork.Field {
	return &leasedToken{
		m:    m,
		name: name,
		Processor: fork.NewProcessor(
			leasedTokenWidget(options...),
			[]interface{}{ValidateLeasedToken},
			nil,
		),
	}
}

func (l *leasedToken) New() fork.Field {
	var newfield leasedToken = *l
	newfield.returned = ""
	newfield.validateable = false
	return &newfield
}

func (l *leasedToken) Name(name ...string) string {
	if len(name) > 0 {
		l.name = strings.Join(name, "-")
	}
	return l.name
}

func (l *leasedToken) Get() *fork.Value {
	return fork.NewValue(l.returned)
}

func (l *leasedToken) Set(r *http.Request) {
	l.returned = l.Filter(l.Name(), r).String()
	l.validateable = true
}

func (l *leasedToken) Validateable() bool {
	return l.validateable
}

func (l *leasedToken) Token() string {
	return l.m.generateToken("leased_token", time.Now().String())
}

func ValidateLeasedToken(l *leasedToken) error {
	if l.validateable {
		if !validLeasedToken(l.m, l.returned) {
			return InvalidToken
		}
	}
	return nil
}
