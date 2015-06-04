package security

import (
	"fmt"
	"testing"

	"github.com/thrisp/flotilla"
)

func TestSecurity(t *testing.T) {
	a := flotilla.New("securityTest")
	s := New(Setting("recoverable:t", "changeable:t", "REGISTERABLE:t", "confirmable:t", "trackable:t"))
	s.Init(a)
	a.Configure()
	fmt.Printf("///\n%#v\n", s)
	//for k, v := range templatemacros(m.Forms) {
	//	vv := v.(func() template.HTML)
	//	fmt.Printf("///%s\n%#v\n", k, vv())
	//}
	fmt.Printf("///\n%#v\n", a.Routes())
}

//func TestPW(t *testing.T) {
//	a := flotilla.New("securityTest")
//	m := New()
//	m.Init(a)
//	a.Configure()
//	fmt.Printf("%s\n", m.password.Encode("hello"))
//}

//func TestSigner(t *testing.T) {
//	x := NewTimeSignatory("test", "salt", md5.New)
//	hx := x.Sign([]byte("hello"))
//	y, err := x.Verify(hx, time.Second)
//	fmt.Printf("%+v\n%s\n%s\n%+v\n", x, hx, y, err)
//}
