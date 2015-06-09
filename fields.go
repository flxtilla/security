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

type securityName struct {
	name string
}

func (s *securityName) Name() string {
	return s.name
}

func (s *securityName) ReName(rename ...string) string {
	if len(rename) > 0 {
		s.name = strings.Join(rename, "-")
	}
	return s.name
}

func (s *securityName) Copy() *securityName {
	var ret securityName = *s
	return &ret
}

func UserName(s *Manager, name string, options ...string) fork.Field {
	return &userName{
		securityName: &securityName{name},
		Processor: fork.NewProcessor(
			userNamewidget(s, options...),
			fork.NewValidater(ValidEmail, s.ValidUserName),
			fork.NewFilterer(),
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
	*securityName
	UserName string
	user     user.User
	fork.Processor
}

func (u *userName) New() fork.Field {
	var newfield userName = *u
	newfield.UserName = ""
	newfield.user = user.AnonymousUser
	newfield.SetValidateable(false)
	return &newfield
}

func (u *userName) Get() *fork.Value {
	return fork.NewValue(u.user)
}

func (u *userName) Set(r *http.Request) {
	v := u.Filter(u.Name(), r)
	u.UserName = v.String()
	u.SetValidateable(true)
}

var InvalidEmail = SecurityError(`Invalid email address: %s`)

func ValidEmail(u *userName) error {
	if u.Validateable() {
		_, err := mail.ParseAddress(u.UserName)
		if err != nil {
			return InvalidEmail.Out(err)
		}
	}
	return nil
}

func (s *Manager) ValidUserName(u *userName) error {
	if u.Validateable() {
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
	m *Manager
	*securityName
	Url string
	fork.Processor
}

func nextwidget(options ...string) fork.Widget {
	return fork.NewWidget(fmt.Sprintf(`<input type="hidden" name="{{ .Name }}" value="{{ .Url }}" %s>`, strings.Join(options, " ")))
}

func Next(s *Manager, name string, options ...string) fork.Field {
	return &next{
		m:            s,
		securityName: &securityName{name},
		Processor: fork.NewProcessor(
			nextwidget(options...),
			fork.NewValidater(),
			fork.NewFilterer(nextfilter),
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
	newfield.SetValidateable(false)
	return &newfield
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
	n.SetValidateable(true)
}

type leasedToken struct {
	m *Manager
	*securityName
	key      string
	returned string
	fork.Processor
}

func leasedTokenWidget(options ...string) fork.Widget {
	return fork.NewWidget(fmt.Sprintf(`<input type="hidden" name="{{ .Name }}" value="{{ .Token }}" %s>`, strings.Join(options, " ")))
}

func LeasedToken(m *Manager, name string, options ...string) fork.Field {
	return &leasedToken{
		m:            m,
		securityName: &securityName{name},
		Processor: fork.NewProcessor(
			leasedTokenWidget(options...),
			fork.NewValidater(ValidateLeasedToken),
			fork.NewFilterer(),
		),
	}
}

func (l *leasedToken) New() fork.Field {
	var newfield leasedToken = *l
	newfield.returned = ""
	newfield.SetValidateable(false)
	return &newfield
}

func (l *leasedToken) Get() *fork.Value {
	return fork.NewValue(l.returned)
}

func (l *leasedToken) Set(r *http.Request) {
	l.returned = l.Filter(l.Name(), r).String()
	l.SetValidateable(true)
}

func (l *leasedToken) Token() string {
	return l.m.generateToken("leased_token", time.Now().String())
}

var InvalidLeasedToken = SecurityError("leased token is invalid")

func ValidateLeasedToken(l *leasedToken) error {
	if l.Validateable() {
		if !validLeasedToken(l.m, l.returned) {
			return InvalidLeasedToken
		}
	}
	return nil
}
