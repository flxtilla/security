package token

import (
	"testing"
	"time"
)

var testSignatoryToken string = `A9s2YkQyS5XsUhmkqzvZ4UcD1RIiZfuacmtfmJWEPt9FR1MZ6AdIa2s4tuKnX8f7R65W6xv4yT3UsvccFX9llnuy_w6aPG_wgeSnggpjuL172uNaEeLcDn7FI-TIwdR7NOowoI7OJh3ViteMB2mhHo37fiYTijBHkQ==`

func TestSignatory(t *testing.T) {
	s := NewSignatory("TEST", time.UnixDate, "abcdefghijklmnop", NewSigner("HS256", "SIGNER-KEY"))
	tknOut := s.SignedString("TESTING:TRUE")
	var tknIn string = tknOut
	validTkn, err := s.Valid(tknIn)
	if err != nil {
		t.Errorf("Expected signatory token to be valid, but was not: %s", err.Error())
	}
	if clm, ok := validTkn.Claims["TESTING"].(string); ok {
		if clm != "TRUE" {
			t.Errorf(`Expected claim "TESTING" to be true, but was %s`, clm)
		}
	}
	_, err = s.Valid(testSignatoryToken)
	if err != nil {
		t.Errorf("Existing test token was not valid with created Signatory")
	}
}
