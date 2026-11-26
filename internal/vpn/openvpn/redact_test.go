package openvpn

import "testing"

func TestRedactorWarning(t *testing.T) {
	hidden := newRedactor("alice", "", "  ", "open sesame")
	tests := []struct {
		name string
		in   Warning
		want Warning
	}{
		{"username as directive", Warning{Directive: "alice", Message: "is unknown"}, Warning{Directive: hiddenValue, Message: "is unknown"}},
		{"password token", Warning{Directive: "sesame"}, Warning{Directive: hiddenValue}},
		{"credential inside", Warning{Directive: "alice-x"}, Warning{Directive: hiddenValue}},
		{
			"file name in message", Warning{Directive: "ca", File: "alice", Message: `references the file "alice"`},
			Warning{Directive: "ca", File: hiddenValue, Message: `references the file "(hidden)"`},
		},
		{"other directive", Warning{Directive: "float"}, Warning{Directive: "float"}},
		{"empty", Warning{}, Warning{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hidden.warning(tt.in); got != tt.want {
				t.Errorf("warning = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestRedactorWithoutCredentialsHidesNothing(t *testing.T) {
	if newRedactor("", " ").hides("anything") {
		t.Error("a redactor without credentials hides text")
	}
}
