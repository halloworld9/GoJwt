package jwt

import (
	"os"
	"testing"
)

const (
	success = "\u2713"
	failed  = "\u2717"
)

func TestToken(t *testing.T) {

	t.Logf("Testing token api")
	{
		if err := os.Setenv("JWT_SECRET", "test"); err != nil {
			t.Fatalf("\t\tError setting JWT secret %v", err)
		}
		testID := 0
		{
			t.Logf("\t\tStart test numner %d", testID)
			payload := Payload{}
			payload["testId"] = testID
			payload["test"] = "asd"

			token, err := NewToken(&payload)
			if err != nil {
				t.Fatalf("\t\tError creating token: %s\n", err)
			}
			ok := token.RawToken == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoiYXNkIiwidGVzdElkIjowfQ.qsUTjnIUmhflesHpCMCg2ayo6iB-fAo2UbSVxUQfpDE"

			if ok {
				t.Logf("%s\t\tEnd test number %d", success, testID)
			} else {
				t.Fatalf("%s\t\tFaliled test number %d, wrong token %s", failed, testID, token.RawToken)
			}

		}

		testID++
		t.Logf("\t\tStart test numner %d", testID)
		{
			token, err := NewTokenFromRaw("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoiYXNkIiwidGVzdElkIjowfQ.y-kv_jHniYRpjEkMIy0DX09C_el1cT7kAuPRbFrMY84")
			if err != nil {
				t.Fatalf("%s\t\t Error creating token: %s\n", failed, err)
			}
			if token.Valid {
				t.Fatalf("%s\t\t Token should be invalid: %s", failed, token.RawToken)
			} else {
				t.Logf("%s\t\tEnd test number %d", success, testID)
			}
		}
		testID++
		t.Logf("\t\tStart test numner %d", testID)
		{
			token, err := NewTokenFromRaw("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoiYXNkIiwidGVzdElkIjowfQ.qsUTjnIUmhflesHpCMCg2ayo6iB-fAo2UbSVxUQfpDE")
			if err != nil {
				t.Fatalf("%s\t\t Error creating token: %s\n", failed, err)
			}
			if token.Valid {
				t.Logf("%s\t\tEnd test number %d", success, testID)
			} else {
				t.Fatalf("%s\t\t Token should be valid: %s", failed, token.RawToken)
			}
		}
	}
}
