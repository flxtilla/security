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
	valid, _ := form.Check(form)
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
			f.Call("redirect", 303, s.BlueprintUrl("after_login_url"))
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
	if h := s.login.Reloaders["unauthenticated"]; h != nil {
		h(f)
	}
	f.Call("redirect", 303, s.BlueprintUrl("login_url"))
}

func getLogout(f flotilla.Ctx) {
	s := manager(f)
	s.LogoutUser(f)
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
			user, _ := formUser(form)
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
			s.sendNotice(f, form, "getPasswordlessToken", "passwordless")
			s.redirectAfter(f, form, "login_email_sent")
		},
	)
}

func tokenLogin(f flotilla.Ctx) {
	s, t := manager(f), tokenFromUrl(f, "token")
	tkn, err := s.Signatory("passwordless").Valid(t)
	if err != nil {
		s.forwardTo(f, "passwordless_login.html", "invalid_login_token")
	} else {
		usr, remember := validUserToken(s, tkn)
		s.LoginUser(usr, remember, f)
		s.redirectAfter(f, nil, "login_successful")
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
			s.sendNotice(f, form, "getResetToken", "send_reset")
			_, email := formUser(form)
			s.redirectAfter(f, form, "reset_instructions_sent", email)
		},
	)
}

func getResetPassword(f flotilla.Ctx) {
	s, t := manager(f), tokenFromUrl(f, "token")
	tkn, err := s.Signatory("send_reset").Valid(t)
	if err != nil {
		s.forwardTo(f, "send_reset.html", "invalid_reset_token")
	} else {
		usr, _ := validUserToken(s, tkn)
		fu := fmt.Sprintf("forUser:%s", usr.Email())
		vr := fmt.Sprintf("validReset:%s", s.Signatory("reset_password").SignedString())
		form := s.Forms.byKey("reset_password").Fresh(fu, vr)
		f.Call("set", form.Tag(), form)
		f.Call("rendertemplate", "reset_password.html", nil)
	}
}

func postResetPassword(f flotilla.Ctx) {
	posted(
		f,
		"reset_password",
		func(f flotilla.Ctx, s *Manager, form Form) {
			t, err := s.Signatory("signed").Valid(formSigned(form))
			if err != nil {
				s.formFail(f, form, "send_reset.html")
			}
			usr := s.Get(claimString(t.Claims["forUser"]))
			newpassword := formPassword(form, "confirmable-one")
			usr.Update("password", newpassword)
			if s.BoolSetting("notify_password_reset") {
				s.sendNotice(f, form, "getResetToken", "reset_password")
			}
			remember, _ := formRememberMe(form)
			s.LoginUser(usr, remember, f)
			s.redirectAfter(f, form, "reset_successful")
		},
	)
}

func getChangePassword(f flotilla.Ctx) {
	f.Call("rendertemplate", "change_password.html", nil)
}

func postChangePassword(f flotilla.Ctx) {
	posted(
		f,
		"change_password",
		func(f flotilla.Ctx, s *Manager, form Form) {
			usr, _ := formUser(form)
			newpassword := formPassword(form, "confirmable-one")
			usr.Update("password", newpassword)
			if s.BoolSetting("notify_password_change") {
				s.sendNotice(f, form, "getResetToken", "reset_password")
			}
			s.redirectAfter(f, form, "change_password")
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
			_, usr := formUser(form)
			password := formPassword(form, "confirmable-one")
			if _, err := s.New(usr, password); err != nil {
				s.formFail(f, form, "register.html")
			}
			if s.BoolSetting("confirmable") {
				sendConfirm(f, s, form)
			} else {
				s.Flash(f, "registration_success")
				f.Call("redirect", 302, s.BlueprintUrl(s.ManagerLogin()))
			}
		},
	)
}

func sendConfirm(f flotilla.Ctx, s *Manager, form Form) {
	s.sendNotice(f, form, "getConfirmUser", "send_confirm")
	s.redirectAfter(f, form, "confirm_registration")
}

func getSendConfirm(f flotilla.Ctx) {
	f.Call("rendertemplate", "send_confirm.html", nil)
}

func postSendConfirm(f flotilla.Ctx) {
	posted(
		f,
		"send_confirm",
		sendConfirm,
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
			usr, _ := formUser(form)
			var mess string
			if usr.Confirmed() {
				mess = "already_confirmed"
			}
			usr.Confirm()
			if usr.Confirmed() {
				mess = "email_confirmed"
			} else {
				mess = "confirmation_fail"
			}
			s.redirectAfter(f, form, mess)
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
	bp := flotilla.NewBlueprint(s.Prefix())

	SecurityRoute(bp, "logout", "GET", s.Setting("logout_url"), LoginRequired(getLogout))

	if !s.Passwordless() {
		lurl := s.Url("login_url")
		SecurityRoute(bp, "getLogin", "GET", lurl, AnonymousRequired(getLogin))
		SecurityRoute(bp, "postLogin", "POST", lurl, AnonymousRequired(postLogin))
	}

	if s.Passwordless() {
		plurl := s.Url("passwordless_url")
		SecurityRoute(bp, "getSendLogin", "GET", plurl, AnonymousRequired(getSendLogin))
		SecurityRoute(bp, "postSendLogin", "POST", plurl, AnonymousRequired(postSendLogin))
		SecurityRoute(bp, "getPasswordlessToken", "GET", s.Url("passwordless_token_url"), AnonymousRequired(tokenLogin))
	}

	if s.BoolSetting("recoverable") {
		srurl := s.Url("send_reset_url")
		SecurityRoute(bp, "getSendReset", "GET", srurl, AnonymousRequired(getSendReset))
		SecurityRoute(bp, "postSendReset", "POST", srurl, AnonymousRequired(postSendReset))
		SecurityRoute(bp, "getResetToken", "GET", s.Url("reset_token_url"), AnonymousRequired(getResetPassword))
		SecurityRoute(bp, "postResetPassword", "POST", s.Url("reset_url"), AnonymousRequired(postResetPassword))
	}

	if s.BoolSetting("changeable") {
		curl := s.Url("change_url")
		SecurityRoute(bp, "getChangePassword", "GET", curl, LoginRequired(getChangePassword))
		SecurityRoute(bp, "postChangePassword", "POST", curl, LoginRequired(postChangePassword))
	}

	if s.BoolSetting("registerable") {
		rurl := s.Url("register_url")
		SecurityRoute(bp, "getRegister", "GET", rurl, AnonymousRequired(getRegister))
		SecurityRoute(bp, "postRegister", "POST", rurl, AnonymousRequired(postRegister))
	}

	if s.BoolSetting("confirmable") {
		curl := s.Url("send_confirm_url")
		SecurityRoute(bp, "getSendConfirm", "GET", curl, getSendConfirm)
		SecurityRoute(bp, "postSendConfirm", "POST", curl, postSendConfirm)
		SecurityRoute(bp, "getConfirmUser", "GET", s.Url("confirm_token_url"), getConfirmUser)
		SecurityRoute(bp, "postConfirmUser", "POST", s.Url("confirm_user_url"), postConfirmUser)
	}

	return bp
}
