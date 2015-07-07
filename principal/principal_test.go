package principal

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/thrisp/flotilla"
)

var (
	n1 string     = "role:a"
	n2 string     = "role:b"
	n3 string     = "role:c"
	n4 string     = "item:key:gold"
	e1 string     = "garlic"
	e2 string     = "onion"
	p0 Permission = NewPermission("p0", 1, 2, 3, "four", "anonymous")
	p1 Permission = NewPermission("p1", n1, n2)
	p2 Permission = NewPermission("p2", n3)
	p3 Permission = NewPermission("p3", "role:a", n4)
	p4 Permission = NewPermission("p4")
)

type TestIdentities map[string]Identity

var testIdentities TestIdentities = TestIdentities{
	"t1": NewIdentity("t1", n1),
	"t2": NewIdentity("t2", n2, "role:c"),
	"t3": NewIdentity("t3", n3, n4),
	"t4": NewIdentity("t4", n1, n2),
}

func (t TestIdentities) Get(id string) Identity {
	if i, ok := t[id]; ok {
		return i
	}
	return NewIdentity(id, id)
}

func (t TestIdentities) Handle(i Identity, c flotilla.Ctx) {
	c.Call("setsession", "identity_id", i.Tag())
}

func (t TestIdentities) Load(c flotilla.Ctx) Identity {
	iid, _ := c.Call("getsession", "identity_id")
	if iid != nil {
		return t.Get(iid.(string))
	}
	return Anonymous
}

func (t TestIdentities) Remove(c flotilla.Ctx) {
	c.Call("deletesession", "identity_id")
}

func testapp(t *testing.T, name string, m *Manager) *flotilla.App {
	a := flotilla.New(name)
	a.Messaging.Queues["out"] = func(message string) {}
	m.Init(a)
	err := a.Configure()
	if err != nil {
		t.Errorf("Error in app configuration: %s", err.Error())
	}
	return a
}

func basemanager(c ...Configuration) *Manager {
	c = append(
		c,
		IdentityLoad(testIdentities.Load),
		IdentityHandle(testIdentities.Handle),
		IdentityRemove(testIdentities.Remove),
	)
	p := New(c...)
	return p
}

func TestExtension(t *testing.T) {
	var exists bool = false
	a := testapp(t, "principalExtension", basemanager())
	exp, _ := flotilla.NewExpectation(
		200, "GET", "/test",
		func(t *testing.T) flotilla.Manage {
			return func(c flotilla.Ctx) {
				l, _ := c.Call("principal")
				if _, ok := l.(*Manager); ok {
					exists = true
				}
				c.Call("serveplain", 200, "ok")
			}
		},
	)
	exp.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			if !exists {
				t.Errorf("[principal] extension does not exist")
			}
		},
	)
	flotilla.SimplePerformer(t, a, exp).Perform()
}

func SetIdentity(i Identity) flotilla.Expectation {
	exp, _ := flotilla.NewExpectation(
		200, "GET", fmt.Sprintf("/identity/%s/setup", i.Tag()),
		func(t *testing.T) flotilla.Manage {
			return func(c flotilla.Ctx) {
				manager(c).Change(i, c)
				ci := currentidentity(c)
				if i.Tag() != ci.Tag() {
					t.Errorf(`identity should be %s, but was %+v`, i.Tag(), ci)
				}
			}
		},
	)
	return exp
}

func RemoveIdentity() flotilla.Expectation {
	var anon Identity = Anonymous
	exp, _ := flotilla.NewExpectation(
		200, "GET", "/identity/1",
		func(t *testing.T) flotilla.Manage {
			return func(c flotilla.Ctx) {
				manager(c).Remove(c)
				anon = currentidentity(c)
				c.Call("serveplain", 200, "ok")
			}
		},
	)
	exp.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			if anon.Tag() != "anonymous" {
				t.Errorf("identity was %+v, but should be Anonymous", anon)
			}
		},
	)
	return exp
}

func TestIdentity(t *testing.T) {
	a := testapp(t, "testIdentity", basemanager())
	exp1 := SetIdentity(testIdentities.Get("t1"))
	exp2 := RemoveIdentity()
	exp3 := SetIdentity(testIdentities.Get("t2"))
	exp4, _ := flotilla.NewExpectation(
		200, "GET", "/identity/2",
		func(t *testing.T) flotilla.Manage {
			return func(c flotilla.Ctx) {
				idty, _ := c.Call("currentidentity")
				ci := idty.(Identity)
				if ci.Tag() != "t2" {
					t.Errorf(`identity should be "t2", but was %+v`, ci)
				}
				c.Call("serveplain", 200, "ok")
			}
		},
	)
	flotilla.SessionPerformer(t, a, exp1, exp2, exp3, exp4).Perform()
}

type tidentity struct {
	i Identity
	p []Permission
	e bool
}

func Tidentity(i Identity, expects bool, p ...Permission) *tidentity {
	return &tidentity{
		i: i,
		p: p,
		e: expects,
	}
}

func (i *tidentity) testAllow(t *testing.T) {
	for _, p := range i.p {
		ir := i.i.Can(p)
		if ir != i.e {
			t.Errorf(
				"%s : identity.Can was %t, expected %t",
				i.i.Tag(), ir, i.e,
			)
		}
		pr := p.Allows(i.i)
		if pr != i.e {
			t.Errorf(
				"%s : permission.Allows was %t, expected %t",
				p.Tag(), pr, i.e,
			)
		}
	}
}

func (i *tidentity) testRequire(t *testing.T) {
	for _, p := range i.p {
		ir := i.i.Must(p)
		if ir != i.e {
			t.Errorf("%s identity.Must was %t, expected %t", i.i.Tag(), ir, i.e)
		}
		pr := p.Requires(i.i)
		if pr != i.e {
			t.Errorf("%s permission.Requires was %t, expected %t", p.Tag(), pr, i.e)
		}
	}
}

func needHandlerAllow(t *testing.T, i *tidentity) flotilla.Tanage {
	return func(t *testing.T) flotilla.Manage {
		return func(c flotilla.Ctx) {
			i.testAllow(t)
			c.Call("serveplain", 200, "ok")
		}
	}
}

func needHandlerRequire(t *testing.T, i *tidentity) flotilla.Tanage {
	return func(t *testing.T) flotilla.Manage {
		return func(c flotilla.Ctx) {
			i.testRequire(t)
			c.Call("serveplain", 200, "ok")
		}
	}
}

func TestPermission(t *testing.T) {
	if p0.Tag() != "p0" {
		t.Errorf(`permission tag was %s, but should be "p0"`)
	}
}

func TestPermissions(t *testing.T) {
	a := testapp(t, "testPermissions", basemanager())
	ti := testIdentities.Get("t4")
	exp0 := SetIdentity(ti)
	exp1, _ := flotilla.NewExpectation(
		200, "GET", "/permission_allow",
		needHandlerAllow(t, Tidentity(ti, true, p0)),
	)
	exp2, _ := flotilla.NewExpectation(
		200, "GET", "/permission_allow_no",
		needHandlerAllow(t, Tidentity(ti, false, p2)),
	)
	exp3, _ := flotilla.NewExpectation(
		200, "GET", "/permission_require",
		needHandlerRequire(t, Tidentity(ti, true, p1)),
	)
	exp4, _ := flotilla.NewExpectation(
		200, "GET", "/permission_require_no",
		needHandlerRequire(t, Tidentity(ti, false, p2)),
	)
	flotilla.SessionPerformer(t, a, exp0, exp1, exp2, exp3, exp4).Perform()
}

func TestSufficient(t *testing.T) {
	a := testapp(
		t,
		"testSufficient",
		basemanager(Unauthorized(
			func(c flotilla.Ctx) {
				c.Call("serveplain", 403, "testing: unauthorized")
			},
		)),
	)
	ti := testIdentities.Get("t4")
	exp1 := SetIdentity(ti)
	exp2, _ := flotilla.NewExpectation(
		200, "GET", "/sufficient/yes",
		func(t *testing.T) flotilla.Manage {
			return Sufficient(func(c flotilla.Ctx) {}, p0)
		},
	)
	exp3, _ := flotilla.NewExpectation(
		403, "GET", "/sufficient/no",
		func(t *testing.T) flotilla.Manage {
			return Sufficient(func(c flotilla.Ctx) {
				t.Error("[principal] Handler was called, but should not be called")
			},
				p2,
			)
		},
	)
	flotilla.SessionPerformer(t, a, exp1, exp2, exp3).Perform()
}

func TestNecessary(t *testing.T) {
	a := testapp(t, "testNecessary", basemanager())
	ti := testIdentities.Get("t4")
	exp1 := SetIdentity(ti)
	exp2, _ := flotilla.NewExpectation(
		200, "GET", "/necessary/yes",
		func(t *testing.T) flotilla.Manage {
			return Necessary(func(c flotilla.Ctx) {}, p1)
		},
	)
	exp3, _ := flotilla.NewExpectation(
		403, "GET", "/necessary/no",
		func(t *testing.T) flotilla.Manage {
			return Necessary(func(c flotilla.Ctx) {
				t.Error("[principal] Handler was called, but should not be called")
			},
				p3,
			)
		},
	)
	flotilla.SessionPerformer(t, a, exp1, exp2, exp3).Perform()
}
