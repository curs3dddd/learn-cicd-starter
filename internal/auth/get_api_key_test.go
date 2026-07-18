package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr string
	}{
		{
			name: "valid api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey secret123"},
			},
			expectedKey: "secret123",
			expectedErr: "",
		},
		{
			name:        "missing authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name: "wrong authorization type",
			headers: http.Header{
				"Authorization": []string{"Bearer secret123"},
			},
			expectedKey: "",
			expectedErr: "malformed authorization header",
		},
		{
			name: "missing api key value",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey: "",
			expectedErr: "malformed authorization header",
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded.Error(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actualKey, err := GetAPIKey(tc.headers)

			if actualKey != tc.expectedKey {
				t.Errorf("expected key %q, got %q", tc.expectedKey, actualKey)
			}

			if tc.expectedErr == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				return
			}

			if err == nil {
				t.Errorf("expected error %q, got nil", tc.expectedErr)
				return
			}

			if err.Error() != tc.expectedErr {
				t.Errorf("expected error %q, got %q", tc.expectedErr, err.Error())
			}
		})
	}
}
