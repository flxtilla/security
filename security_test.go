package security

import (
	"fmt"
	"testing"

	"github.com/thrisp/flotilla"
)

func TestSecurity(t *testing.T) {
	a := flotilla.New("securityTest")
	m := New()
	m.Init(a)
	a.Configure()
	fmt.Printf("%+v\n%+v\n", a.Env, m)
}

//func TestSigner(t *testing.T) {
//x := NewTimeSignatory("test", "salt", md5.New)
//h := hmac.New(func() hash.Hash {
//	return md5.New()
//}, []byte("secret"))

//s := NewBase64TimeSigner(h)
//fmt.Printf("%+v\n%+v\n", h, s)
//hx := x.Sign([]byte("hello"))
//y, err := x.Verify(hx, time.Second)
//fmt.Printf("%+v\n%s\n%s\n%+v\n", x, hx, y, err)
//}
