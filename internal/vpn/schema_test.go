package vpn

import (
	"encoding/json"
	"testing"
)

func TestConditionValidate(t *testing.T) {
	tests := []struct {
		name    string
		c       Condition
		wantErr bool
	}{
		{name: "key and equals", c: Condition{Key: "authMode", Equals: []string{"password"}}},
		{name: "secret", c: Condition{Secret: "tlsAuthKey"}},
		{name: "empty", c: Condition{}, wantErr: true},
		{name: "key without equals", c: Condition{Key: "authMode"}, wantErr: true},
		{name: "equals without key", c: Condition{Equals: []string{"x"}}, wantErr: true},
		{name: "secret and key", c: Condition{Secret: "s", Key: "k", Equals: []string{"x"}}, wantErr: true},
		{name: "secret and equals", c: Condition{Secret: "s", Equals: []string{"x"}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate = %v, want error %v", err, tt.wantErr)
			}
		})
	}
}

func TestFormSchemaValidate(t *testing.T) {
	schema := func(condition Condition) FormSchema {
		return FormSchema{Sections: []Section{{Key: "s", Fields: []Field{
			{Key: "authMode", Type: FieldSelect},
			{Key: "tlsAuthKey", Type: FieldSecret},
			{Key: "dependent", Type: FieldSelect, VisibleWhen: &condition},
		}}}}
	}
	tests := []struct {
		name      string
		condition Condition
		wantErr   bool
	}{
		{name: "setting condition", condition: Condition{Key: "authMode", Equals: []string{"password"}}},
		{name: "secret condition", condition: Condition{Secret: "tlsAuthKey"}},
		{name: "key names a secret", condition: Condition{Key: "tlsAuthKey", Equals: []string{"x"}}, wantErr: true},
		{name: "key names no field", condition: Condition{Key: "missing", Equals: []string{"x"}}, wantErr: true},
		{name: "secret names a setting", condition: Condition{Secret: "authMode"}, wantErr: true},
		{name: "invalid form", condition: Condition{Secret: "tlsAuthKey", Key: "authMode"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := schema(tt.condition).Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate = %v, want error %v", err, tt.wantErr)
			}
		})
	}
}

func TestFormSchemaValidatePresets(t *testing.T) {
	schema := func(presets map[string]any) FormSchema {
		return FormSchema{Sections: []Section{{Key: "s", Fields: []Field{
			{Key: "template", Type: FieldSelect, Options: []Option{{Value: "a", Presets: presets}}},
			{Key: "proposals", Type: FieldStringList},
			{Key: "psk", Type: FieldSecret},
		}}}}
	}
	tests := []struct {
		name    string
		presets map[string]any
		wantErr bool
	}{
		{name: "none"},
		{name: "setting", presets: map[string]any{"proposals": []string{"aes256gcm16-ecp256"}}},
		{name: "secret", presets: map[string]any{"psk": "x"}, wantErr: true},
		{name: "unknown field", presets: map[string]any{"missing": "x"}, wantErr: true},
		{name: "own field", presets: map[string]any{"template": "b"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := schema(tt.presets).Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate = %v, want error %v", err, tt.wantErr)
			}
		})
	}
}

func TestFormSchemaValidateEncoding(t *testing.T) {
	tests := []struct {
		name    string
		field   Field
		wantErr bool
	}{
		{name: "no encoding", field: Field{Key: "f", Type: FieldText}},
		{name: "base64 multi-line secret", field: Field{Key: "f", Type: FieldSecret, Multiline: true, Encoding: EncodingBase64}},
		{name: "base64 single-line secret", field: Field{Key: "f", Type: FieldSecret, Encoding: EncodingBase64}, wantErr: true},
		{name: "base64 textarea", field: Field{Key: "f", Type: FieldTextarea, Multiline: true, Encoding: EncodingBase64}, wantErr: true},
		{name: "unknown encoding", field: Field{Key: "f", Type: FieldSecret, Multiline: true, Encoding: "hex"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schema := FormSchema{Sections: []Section{{Key: "s", Fields: []Field{tt.field}}}}
			if err := schema.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate = %v, want error %v", err, tt.wantErr)
			}
		})
	}
}

func TestFieldEncodingJSON(t *testing.T) {
	b, err := json.Marshal(Field{Key: "p", Type: FieldSecret, LabelKey: "l", Multiline: true, Encoding: EncodingBase64})
	if err != nil || string(b) != `{"key":"p","type":"secret","labelKey":"l","multiline":true,"encoding":"base64"}` {
		t.Errorf("Marshal = %s, %v", b, err)
	}
}

func TestSecretConditionJSON(t *testing.T) {
	b, err := json.Marshal(Condition{Secret: "tlsAuthKey"})
	if err != nil || string(b) != `{"secret":"tlsAuthKey"}` {
		t.Errorf("Marshal = %s, %v", b, err)
	}
}
