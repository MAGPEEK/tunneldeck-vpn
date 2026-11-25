package vpn

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
// of the values in Equals.
type Condition struct {
	Key    string   `json:"key"`
	Equals []string `json:"equals"`
}
