package security

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/thrisp/flotilla"
)

func TestUrls(t *testing.T) {
	a := testApp(testManager())

	exp, _ := GeneralExpectation(func(t *testing.T, c flotilla.Ctx, m *Manager) {
		req, _ := c.Call("request")
		if request, ok := req.(*http.Request); ok {
			request.Host = "local:"
		}

		ext := m.Urls.External(c, "getConfirmUser", "token-string")
		rel := m.Urls.Relative(c, "getConfirmUser", "token-string")

		relext := fmt.Sprintf("//local:%s", rel)

		if ext != relext {
			t.Errorf("external url was %s\nrelative url made external was %s\n",
				ext,
				relext,
			)
		}
	})

	flotilla.SimplePerformer(t, a, exp).Perform()
}
