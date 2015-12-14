package security

import (
	"testing"
	"time"

	"github.com/thrisp/flotilla"
)

func approximiteOneHour(t *testing.T, d time.Duration) {
	h := d.Hours()
	if h < 0.999999999 || h > 1 {
		t.Errorf("default duration should approximate 1, but was %d", h)
	}

}

func TestDefaultTime(t *testing.T) {
	var InvalidString string = "invalid"
	approximiteOneHour(t, parseDuration(InvalidString))
	a := testApp(New())

	exp, _ := GeneralExpectation(func(t *testing.T, c flotilla.Ctx, m *Manager) {
		approximiteOneHour(t, m.Times.Duration(InvalidString))
	})

	flotilla.SimplePerformer(t, a, exp).Perform()
}
