package domain

import (
	"errors"
	"testing"
)

func TestRemoteAccessValidate(t *testing.T) {
	tests := []struct {
		name      string
		settings  RemoteAccess
		badFields []string
	}{
		{name: "default", settings: DefaultRemoteAccess()},
		{name: "uploaded on port 1", settings: RemoteAccess{Enabled: true, Port: 1, CertificateSource: CertificateUploaded}},
		{name: "port 0", settings: RemoteAccess{Port: 0, CertificateSource: CertificateSelfSigned}, badFields: []string{"port"}},
		{name: "port too high", settings: RemoteAccess{Port: 65536, CertificateSource: CertificateSelfSigned}, badFields: []string{"port"}},
		{name: "unknown source", settings: RemoteAccess{Port: 8443, CertificateSource: "acme"}, badFields: []string{"certificateSource"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.settings.Validate()
			if len(tt.badFields) == 0 {
				if err != nil {
					t.Fatalf("Validate = %v", err)
				}
				return
			}
			var v *ValidationError
			if !errors.As(err, &v) {
				t.Fatalf("Validate = %v, want a ValidationError", err)
			}
			for _, field := range tt.badFields {
				if v.Fields[field] == "" {
					t.Errorf("fields = %v, want %s", v.Fields, field)
				}
			}
		})
	}
}

func TestDefaultRemoteAccess(t *testing.T) {
	d := DefaultRemoteAccess()
	if d.Enabled || d.Port != 8443 || d.CertificateSource != CertificateSelfSigned {
		t.Fatalf("DefaultRemoteAccess = %+v", d)
	}
}
