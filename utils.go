package security

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/thrisp/flotilla"
	"github.com/thrisp/fork"
	"github.com/thrisp/security/user"
)

type securityError struct {
	err  string
	vals []interface{}
}

func (f *securityError) Error() string {
	return fmt.Sprintf("[security] %s", fmt.Sprintf(f.err, f.vals...))
}

func (f *securityError) Out(vals ...interface{}) *securityError {
	f.vals = vals
	return f
}

func SecurityError(err string) *securityError {
	return &securityError{err: err}
}

func existsIn(s string, l ...string) bool {
	for _, x := range l {
		if s == x {
			return true
		}
	}
	return false
}

func nxtByQueryParam(r *http.Request) (string, bool) {
	ret := r.URL.Query().Get("next")
	if ret != "" {
		return ret, true
	}
	return "", false
}

func nxtByPath(r *http.Request, m *Manager) (string, bool) {
	k, _ := m.settingByValue(r.URL.Path)
	if nxt := m.Setting(fmt.Sprintf("after_%s", k)); nxt != "" {
		return nxt, true
	}
	return "", false
}

func nxtByForm(form fork.Form) (string, bool) {
	v := form.Values()
	nxt := v["next"].String()
	if nxt != "" {
		return nxt, true
	}
	return nxt, false
}

func (s *Manager) nxtAbsolute(r *http.Request, form Form) string {
	var nxt string
	nxt, _ = nxtByQueryParam(r)
	if nxt == "" && form != nil {
		nxt, _ = nxtByForm(form)
	}
	if nxt == "" {
		nxt, _ = nxtByPath(r, s)
	}
	if nxt == "" {
		nxt = "/"
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

func packSignable(items ...string) []byte {
	var prep string
	if len(items) > 1 {
		prep = strings.Join(items, ":")
	} else {
		prep = items[0]
	}
	return base64Encode([]byte(prep))
}

func unpackSignable(in []byte) []string {
	dec, err := base64Decode(in)
	if err != nil {
		return []string{err.Error()}
	}
	return strings.Split(string(dec), ":")
}

func (s *Manager) generateToken(key string, items ...string) string {
	sgn := s.Signatory(key)
	in := packSignable(items...)
	signed := sgn.Sign(in)
	return string(signed)
}

func paramToken(f flotilla.Ctx, key string) string {
	t, _ := f.Call("paramString", key)
	return t.(string)
}

var InvalidToken = SecurityError("invalid token")

func validToken(s *Manager, key, token string) ([]string, error) {
	sgn := s.Signatory(key)
	within, err := time.ParseDuration(s.Setting(fmt.Sprintf("%s_duration", key)))
	if err != nil {
		return nil, err
	}
	if signed, ok := sgn.Verify([]byte(token), within); ok {
		return unpackSignable(signed), nil
	}
	return nil, InvalidToken
}

func validUserToken(s *Manager, key, token string) (user.User, bool, bool) {
	in, err := validToken(s, key, token)
	if err == nil {
		user := s.Get(in[0])
		if !user.Anonymous() {
			remember, err := strconv.ParseBool(in[1])
			if err != nil {
				remember = false
			}
			return user, remember, true
		}
	}
	return nil, false, false
}

func validLeasedToken(s *Manager, token string) bool {
	sgn := s.Signatory("leased_token")
	within, err := time.ParseDuration(s.Setting("leased_token_duration"))
	if err != nil {
		return false
	}
	if _, ok := sgn.Verify([]byte(token), within); ok {
		return true
	}
	return false
}

func UpdatePassword(f Form) (user.User, error) {
	usr := formUser(f)
	newpassword := formPassword(f, "confirmable-one")
	return usr, usr.Update("password", newpassword)
}

//func (s *Manager) ConfirmUser(u user.User) error {
//	u.Update("confirmed", "true")
//}
