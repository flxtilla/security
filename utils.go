package security

import (
	"fmt"
	"net/http"

	"github.com/thrisp/flotilla"
	"github.com/thrisp/fork"
	"github.com/thrisp/security/token"
	"github.com/thrisp/security/user"
)

type securityError struct {
	errf string
	vals []interface{}
}

func (f *securityError) Error() string {
	return fmt.Sprintf("[security] %s", fmt.Sprintf(f.errf, f.vals...))
}

func (f *securityError) Out(vals ...interface{}) *securityError {
	f.vals = vals
	return f
}

func SecurityError(errf string) *securityError {
	return &securityError{errf: errf}
}

func existsIn(s string, l ...string) bool {
	for _, x := range l {
		if s == x {
			return true
		}
	}
	return false
}

func nxtByQueryParam(r *http.Request) string {
	return r.URL.Query().Get("next")
}

func nxtByForm(form fork.Form) string {
	v := form.Values()
	return v["next"].String()
}

func nxtByPath(r *http.Request, s *Manager) string {
	k := s.BlueprintUrlKey(r.URL.Path)
	after := fmt.Sprintf("AFTER_%s", k)
	return s.BlueprintUrl(after)
}

func (s *Manager) nxtAbsolute(r *http.Request, form Form) string {
	var nxt string
	nxt = nxtByQueryParam(r)
	if nxt == "" && form != nil {
		nxt = nxtByForm(form)
	}
	if nxt == "" {
		nxt = nxtByPath(r, s)
	}
	return nxt
}

func ctxBool(f flotilla.Ctx, key string) (bool, error) {
	b, _ := f.Call("get", key)
	if ret, ok := b.(bool); ok {
		return ret, nil
	}
	return false, fmt.Errorf("Ctx value %s does not exist or is not a boolean value", key)
}

//func UpdatePassword(f Form) (user.User, error) {
//	usr := formUser(f)
//	newpassword := formPassword(f, "confirmable-one")
//	return usr, usr.Update("password", newpassword)
//}

func tokenFromUrl(f flotilla.Ctx, key string) string {
	t, _ := f.Call("paramString", key)
	return t.(string)
}

func claimString(i interface{}) string {
	if ret, ok := i.(string); ok {
		return ret
	}
	return ""
}

func claimBool(i interface{}) bool {
	if ret, ok := i.(bool); ok {
		return ret
	}
	return false
}

func validUserToken(s *Manager, tkn *token.Token) (user.User, bool) {
	id, remember := tkn.Claims["ut"], tkn.Claims["remember"]
	usr := s.Get(claimString(id))
	if !usr.Anonymous() {
		return usr, claimBool(remember)
	}
	return nil, false
}
