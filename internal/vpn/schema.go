package vpn

import (
	"errors"
	"fmt"
)

// FieldType is the kind of input the frontend renders for a field.
type FieldType string

// Field types of a FormSchema.
const (
	FieldText       FieldType = "text"
	FieldNumber     FieldType = "number"
	FieldSelect     FieldType = "select"
	FieldSecret     FieldType = "secret"
	FieldTextarea   FieldType = "textarea"
	FieldStringList FieldType = "stringList"
	FieldBool       FieldType = "bool"
)

// FormSchema describes the profile form of a driver as ordered sections.
// The frontend renders the form from it, so a new driver needs no new page.
type FormSchema struct {
	Sections []Section `json:"sections"`
}

// Section groups related fields under a heading.
type Section struct {
	Key      string  `json:"key"`
	LabelKey string  `json:"labelKey"`
	Fields   []Field `json:"fields"`
}

// Field is one input of the profile form. Key is the setting or secret key
// the value is stored under; secret fields (type FieldSecret) are stored in
// Profile.Secrets, all others in Profile.Settings.
type Field struct {
	Key      string    `json:"key"`
	Type     FieldType `json:"type"`
	LabelKey string    `json:"labelKey"`
	// Required applies only while the field is visible.
	Required bool `json:"required,omitempty"`
	// Multiline marks secret fields that hold multi-line text such as PEM.
	Multiline   bool       `json:"multiline,omitempty"`
	Options     []Option   `json:"options,omitempty"`
	Default     any        `json:"default,omitempty"`
	VisibleWhen *Condition `json:"visibleWhen,omitempty"`
	Placeholder string     `json:"placeholder,omitempty"`
}

// Option is one choice of a select field.
type Option struct {
	Value    string `json:"value"`
	LabelKey string `json:"labelKey"`
}

// Condition makes a field visible only while the field named Key holds one
// of the values in Equals, or, when Secret is set instead, while the secret
// field named Secret has a value (stored, being replaced, or typed in). The
// two forms are mutually exclusive.
type Condition struct {
	Key    string   `json:"key,omitempty"`
	Equals []string `json:"equals,omitempty"`
	Secret string   `json:"secret,omitempty"`
}

// Validate checks that c uses exactly one of its two forms.
func (c Condition) Validate() error {
	switch {
	case c.Secret != "" && (c.Key != "" || len(c.Equals) > 0):
		return errors.New("condition sets secret together with key or equals")
	case c.Secret != "":
		return nil
	case c.Key == "" || len(c.Equals) == 0:
		return errors.New("condition needs key and equals, or secret")
	}
	return nil
}

// Validate checks every condition of the schema: its form, and that it
// refers to a non-secret field (key) or a secret field (secret) of the
// schema.
func (s FormSchema) Validate() error {
	types := map[string]FieldType{}
	for _, section := range s.Sections {
		for _, f := range section.Fields {
			types[f.Key] = f.Type
		}
	}
	for _, section := range s.Sections {
		for _, f := range section.Fields {
			if err := validateVisibility(f, types); err != nil {
				return fmt.Errorf("field %q: %w", f.Key, err)
			}
		}
	}
	return nil
}

func validateVisibility(f Field, types map[string]FieldType) error {
	c := f.VisibleWhen
	if c == nil {
		return nil
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Secret != "" {
		if types[c.Secret] != FieldSecret {
			return fmt.Errorf("condition secret %q is not a secret field", c.Secret)
		}
		return nil
	}
	if fieldType, ok := types[c.Key]; !ok || fieldType == FieldSecret {
		return fmt.Errorf("condition key %q is not a setting field", c.Key)
	}
	return nil
}
