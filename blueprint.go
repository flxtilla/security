package security

import (
	"fmt"
	"net/http"

	"github.com/thrisp/flotilla"
)

func request(f flotilla.Ctx) *http.Request {
	rq, _ := f.Call("request")
	return rq.(*http.Request)
}

func (s *Manager) redirectAfter(f flotilla.Ctx, form Form, messages ...string) {
	s.Flash(f, messages...)
	f.Call("redirect", 302, s.nxtAbsolute(request(f), form))
}

func (s *Manager) forwardTo(f flotilla.Ctx, template string, messages ...string) {
	s.Flash(f, messages...)
	f.Call("rendertemplate", template, nil)
}

func (s *Manager) formFail(f flotilla.Ctx, form Form, template string) {
	f.Call("set", form.Tag(), form)
	s.forwardTo(f, template, "form_error")
}

type IfValid func(flotilla.Ctx, *Manager, Form)

func posted(f flotilla.Ctx, key string, ifvalid IfValid) {
	s, r := manager(f), request(f)
	form := s.Forms.byKey(key).Fresh()
	form.Process(r)
	_, valid := form.Check()
	if valid {
		ifvalid(f, s, form)
	}
	if !valid {
		s.formFail(f, form, fmt.Sprintf("%s.html", key))
	}
}

func AnonymousRequired(h flotilla.Manage) flotilla.Manage {
	return func(f flotilla.Ctx) {
		s := manager(f)
		auth := s.CurrentUser().Authenticated()
		if !auth {
			h(f)
		}
		if auth {
			f.Call("redirect", 303, s.Setting("after_login_url"))
		}
	}
}

func LoginRequired(h flotilla.Manage) flotilla.Manage {
	return func(f flotilla.Ctx) {
		s := manager(f)
		auth := s.CurrentUser().Authenticated()
		if !auth {
			Unauthenticated(f, s)
		}
		if auth {
			h(f)
		}
	}
}

func Unauthenticated(f flotilla.Ctx, s *Manager) {
	s.Flash(f, "unauthenticated")
	if h := s.login.Handlers["unauthenticated"]; h != nil {
		h(f)
	}
	f.Call("redirect", 303, s.Setting("login_url"))
}

func getLogout(f flotilla.Ctx) {
	s := manager(f)
	s.LogoutUser()
	s.redirectAfter(f, nil, "logout_successful")
}

func getLogin(f flotilla.Ctx) {
	f.Call("rendertemplate", "login.html", nil)
}

func postLogin(f flotilla.Ctx) {
	posted(
		f,
		"login",
		func(f flotilla.Ctx, s *Manager, form Form) {
			user := formUser(form)
			remember, _ := formRememberMe(form)
			s.LoginUser(user, remember, f)
			s.redirectAfter(f, form, "login_successful")
		},
	)
}

func getSendLogin(f flotilla.Ctx) {
	f.Call("rendertemplate", "passwordless_login.html", nil)
}

func postSendLogin(f flotilla.Ctx) {
	posted(
		f,
		"passwordless_login",
		func(f flotilla.Ctx, s *Manager, form Form) {
			s.sendInstructions(f, form, "getPasswordlessToken")
			s.redirectAfter(f, form, "login_email_sent")
		},
	)
}

func tokenLogin(f flotilla.Ctx) {
	s, t := manager(f), paramToken(f, "token")
	usr, remember, valid := validUserToken(s, "passwordless", t)
	if valid {
		s.LoginUser(usr, remember, f)
		s.redirectAfter(f, nil, "login_successful")
	} else {
		s.forwardTo(f, "passwordless_login.html", "invalid_login_token")
	}
}

func getSendReset(f flotilla.Ctx) {
	f.Call("rendertemplate", "send_reset.html", nil)
}

func postSendReset(f flotilla.Ctx) {
	posted(
		f,
		"send_reset",
		func(f flotilla.Ctx, s *Manager, form Form) {
			s.sendInstructions(f, form, "getResetToken")
			s.redirectAfter(f, form, "reset_instructions_sent")
		},
	)
}

func getResetPassword(f flotilla.Ctx) {
	s, t := manager(f), paramToken(f, "token")
	_, _, exists := validUserToken(s, "send_reset", t)
	if exists {
		f.Call("rendertemplate", "reset.html", nil)
	}
	if !exists {
		s.forwardTo(f, "send_reset.html", "invalid_reset_token")
	}
}

func postResetPassword(f flotilla.Ctx) {
	posted(
		f,
		"reset_password",
		func(f flotilla.Ctx, s *Manager, form Form) {
			usr, err := UpdatePassword(form)
			if err != nil {
				s.formFail(f, form, "reset.html")
			}
			if err == nil {
				remember, _ := formRememberMe(form)
				s.LoginUser(usr, remember, f)
				s.redirectAfter(f, form, "reset_successful")
			}
		},
	)
}

func getChangePassword(f flotilla.Ctx) {
	f.Call("rendertemplate", "change.html", nil)
}

func postChangePassword(f flotilla.Ctx) {
	posted(
		f,
		"change_password",
		func(f flotilla.Ctx, s *Manager, form Form) {
			_, err := UpdatePassword(form)
			if err != nil {
				s.formFail(f, form, "change.html")
			}
			if err == nil {
				s.redirectAfter(f, form, "password_change")
			}
		},
	)
}

func getRegister(f flotilla.Ctx) {
	f.Call("rendertemplate", "register.html", nil)
}

func postRegister(f flotilla.Ctx) {
	posted(
		f,
		"register",
		func(f flotilla.Ctx, s *Manager, form Form) {
			usr := formNewUser(form)
			password := formPassword(form, "confirmable-one")
			if _, err := s.New(usr, password); err != nil {
				s.formFail(f, form, "register.html")
			}
			if s.BoolSetting("confirmable") {
				s.sendInstructions(f, form, "getConfirmToken")
				s.redirectAfter(f, form, "confirm_registration")
			} else {
				s.Flash(f, "registration_success")
				f.Call("redirect", 302, s.Setting(s.ManagerLogin()))
			}
		},
	)
}

func getSendConfirm(f flotilla.Ctx) {
	f.Call("rendertemplate", "send_confirmation.html", nil)
}

func postSendConfirm(f flotilla.Ctx) {
	posted(
		f,
		"send_confirmation",
		func(f flotilla.Ctx, s *Manager, form Form) {
			s.sendInstructions(f, form, "getConfirmToken")
			s.redirectAfter(f, form, "confirmation_request_sent")
		},
	)
}

func getConfirmUser(f flotilla.Ctx) {
	f.Call("rendertemplate", "confirm_user.html", nil)
}

func postConfirmUser(f flotilla.Ctx) {
	posted(
		f,
		"confirm_user",
		func(f flotilla.Ctx, s *Manager, form Form) {
		},
	)
}

func securityRouteConfig(name, method, base string, m []flotilla.Manage) flotilla.RouteConf {
	return func(rt *flotilla.Route) error {
		rt.Rename(name)
		rt.Method = method
		rt.Base = base
		rt.Managers = m
		return nil
	}
}

func SecurityRoute(b *flotilla.Blueprint, name string, method string, path string, m ...flotilla.Manage) {
	b.Manage(flotilla.NewRoute(securityRouteConfig(name, method, path, m)))
}

func makeBlueprint(s *Manager) *flotilla.Blueprint {
	bp := flotilla.NewBlueprint(s.Setting("blueprint_prefix"))

	SecurityRoute(bp, "logout", "GET", s.Setting("logout_url"), LoginRequired(getLogout))

	passwordless := s.BoolSetting("passwordless")

	lurl := s.Setting("login_url")

	if !passwordless {
		SecurityRoute(bp, "getLogin", "GET", lurl, AnonymousRequired(getLogin))
		SecurityRoute(bp, "postLogin", "POST", lurl, AnonymousRequired(postLogin))
	}

	if passwordless {
		plurl := s.Setting("passwordless_url")
		SecurityRoute(bp, "getSendLogin", "GET", plurl, AnonymousRequired(getSendLogin))
		SecurityRoute(bp, "postSendLogin", "POST", plurl, AnonymousRequired(postSendLogin))
		pturl := fmt.Sprintf("%s/:token", plurl)
		SecurityRoute(bp, "getPasswordlessToken", "GET", pturl, AnonymousRequired(tokenLogin))
	}

	if s.BoolSetting("recoverable") {
		srurl := s.Setting("send_reset_url")
		SecurityRoute(bp, "getSendReset", "GET", srurl, AnonymousRequired(getSendReset))
		SecurityRoute(bp, "postSendReset", "POST", srurl, AnonymousRequired(postSendReset))
		rurl := s.Setting("reset_url")
		rturl := fmt.Sprintf("%s/:token", rurl)
		SecurityRoute(bp, "getResetToken", "GET", rturl, AnonymousRequired(getResetPassword))
		SecurityRoute(bp, "postResetToken", "POST", rurl, AnonymousRequired(postResetPassword))
	}

	if s.BoolSetting("changeable") {
		curl := s.Setting("change_url")
		SecurityRoute(bp, "getChangePassword", "GET", curl, LoginRequired(getChangePassword))
		SecurityRoute(bp, "postChangePassword", "POST", curl, LoginRequired(postChangePassword))
	}

	if s.BoolSetting("registerable") {
		rurl := s.Setting("register_url")
		SecurityRoute(bp, "getRegister", "GET", rurl, AnonymousRequired(getRegister))
		SecurityRoute(bp, "postRegister", "POST", rurl, AnonymousRequired(postRegister))
	}

	if s.BoolSetting("confirmable") {
		curl := s.Setting("confirm_url")
		SecurityRoute(bp, "getSendConfirmation", "GET", curl, getSendConfirm)
		SecurityRoute(bp, "postSendConfirmation", "POST", curl, postSendConfirm)
		turl := fmt.Sprintf("%s/:token", s.Setting("confirm_url"))
		SecurityRoute(bp, "getConfirmToken", "GET", turl, getConfirmUser)
		SecurityRoute(bp, "postConfirmToken", "POST", turl, postConfirmUser)
	}

	return bp
}
