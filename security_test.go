package security

import (
	"fmt"
	"testing"

	"github.com/thrisp/flotilla"
	"github.com/thrisp/login"
)

type TestDataStore struct {
	users map[string]User
}

func NewTestDataStore() *TestDataStore {
	return &TestDataStore{
		users: make(map[string]User),
	}
}

func (t *TestDataStore) Get(s string) User {
	return t.GetLoginUser(s).(User)
}

func (t *TestDataStore) GetLoginUser(s string) login.User {
	return t.users[s]
}

func (t *TestDataStore) Put(User) (User, error) {
	return nil, nil
}

func (t *TestDataStore) Delete(User) error {
	return nil
}

func (t *TestDataStore) CreateRole(...string) {}

func (t *TestDataStore) GetRole(string) Role {
	return nil
}

func TestSecurity(t *testing.T) {
	a := flotilla.New("securityTest")
	m := New(WithDataStore(NewTestDataStore()))
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
