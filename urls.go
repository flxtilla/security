package security

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/thrisp/flotilla"
)

type Urls interface {
	Prefix() string
	Url(string) string
	BlueprintUrl(string) string
	BlueprintUrlKey(string) string
	External(flotilla.Ctx, string, ...string) string
	Relative(flotilla.Ctx, string, ...string) string
}

type urls struct {
	prefix    string
	relative  map[string]string
	reversebp map[string]string
}

func (s *Manager) NewUrls() Urls {
	prefix := s.Setting("BLUEPRINT_PREFIX")
	relative := make(map[string]string)
	for k, _ := range s.Settings {
		ks := strings.Split(k, "_")
		if ks[len(ks)-1] == "URL" {
			relative[k] = s.Setting(k)
		}
	}
	u := &urls{
		prefix:   prefix,
		relative: relative,
	}
	u.reverseBlueprintUrls()
	return u
}

func (u *urls) Prefix() string {
	if u.prefix != "/" {
		return u.prefix
	}
	return ""
}

func (u *urls) Url(k string) string {
	if url, ok := u.relative[strings.ToUpper(k)]; ok {
		return url
	}
	return "/"
}

func (u *urls) BlueprintUrl(k string) string {
	if ur := u.Url(k); ur != "/" {
		var j []string
		j = append(j, u.prefix)
		j = append(j, ur)
		return path.Clean(filepath.ToSlash(strings.Join(j, "")))
	}
	return "/"
}

func (u *urls) BlueprintUrlKey(k string) string {
	var key string
	if ky, ok := u.reversebp[k]; ok {
		key = ky
	}
	if key == "" {
		spl := strings.Split(k, "/")
		spl[len(spl)-1] = ":token"
		nk := strings.Join(spl, "/")
		if nky, ok := u.reversebp[nk]; ok {
			key = nky
		}
	}
	return key
}

func (u *urls) reverseBlueprintUrls() {
	rv := make(map[string]string)
	for k, _ := range u.relative {
		rv[u.BlueprintUrl(k)] = k
	}
	u.reversebp = rv
}

func (u *urls) External(f flotilla.Ctx, route string, params ...string) string {
	url, _ := f.Call("urlfor", route, true, params)
	return url.(string)
}

func (u *urls) Relative(f flotilla.Ctx, route string, params ...string) string {
	url, _ := f.Call("urlfor", route, false, params)
	return url.(string)
}

//a.AddCtxProcessor("urls", securityUrls(s.Urls))
//func securityUrls(u Urls) func(flotilla.Ctx) Urls {
//	return func(c flotilla.Ctx) Urls {
//		return u
//	}
//}
