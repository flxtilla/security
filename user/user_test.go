package user

import (
	"errors"
	"fmt"
	"testing"

	"github.com/thrisp/security/principal"
)

type testDataStore struct {
	users map[string]*testUser
}

func TDataStore() *testDataStore {
	return &testDataStore{
		users: make(map[string]*testUser),
	}
}

func (td *testDataStore) New(name string, password string) (User, error) {
	usr := &testUser{Username: name, Password: password}
	td.users[usr.Username] = usr
	return usr, nil
}

func (td *testDataStore) Get(s string) User {
	if u, ok := td.users[s]; ok {
		return u
	}
	return AnonymousUser
}

var NotATestUser = errors.New("test data store requires a *testUser")

func (td *testDataStore) Put(u User) (User, error) {
	nu, ok := u.(*testUser)
	if !ok {
		return u, NotATestUser
	}
	td.users[nu.Username] = nu
	return u, nil
}

func (td *testDataStore) Delete(u User) error {
	nu, ok := u.(*testUser)
	if !ok {
		return NotATestUser
	}
	delete(td.users, nu.Username)
	return nil
}

type testUser struct {
	principal.Identity
	Username  string
	Password  string
	Local     string
	active    bool
	confirmed bool
}

func (u *testUser) Authenticate(provided string) error {
	if provided == u.Password {
		return nil
	}
	return errors.New("unauthenticated")
}

func (u *testUser) Authenticated() bool {
	return true
}

func (u *testUser) Confirm() {
	u.confirmed = true
}

func (u *testUser) Confirmed() bool {
	return u.confirmed
}

func (u *testUser) Active() bool {
	return u.active
}

func (u *testUser) Anonymous() bool {
	return false
}

func (u *testUser) Email() string {
	return fmt.Sprintf("%s@test.com", u.Username)
}

func (u *testUser) Id() string {
	return u.Username
}

func (u *testUser) Token(key string) string {
	return u.Id()
}

func (u *testUser) Validate(key string, token string) bool {
	if token == u.Id() {
		return true
	}
	return false
}

func (u *testUser) Update(key, value string) error {
	if key == "Local" {
		u.Local = value
		return nil
	}
	return errors.New("only Local may be updated")
}

func TestUserandDataStore(t *testing.T) {
	td := TDataStore()
	usr, err := td.New("test", "test")
	if err != nil {
		t.Errorf("[user] error creating new user: %s", err)
	}
	if usr.Id() != "test" || usr.Email() != "test@test.com" {
		t.Errorf("[user] problem with new user data: %s", usr)
	}
	gu1 := td.Get("test")
	if gu1.Anonymous() || gu1.Id() != usr.Id() {
		t.Errorf("[user] user retrieved from store is not equivalent to created user: %s - %s", gu1, usr)
	}
	usr.Update("Local", "new local value")
	usr.(*testUser).Password = "changed"
	td.Put(usr)
	gu2 := td.Get("test").(*testUser)
	if gu2.Password != "changed" || gu2.Local != "new local value" {
		t.Errorf("[user] user changed and put back resulted in an error: %s", gu2)
	}
	td.Delete(gu2)
	gu3 := td.Get("test")
	if !gu3.Anonymous() {
		t.Errorf("[user] was not deleted: %s", gu3)
	}
}
