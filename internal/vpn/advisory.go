package vpn

// AdvisorySeverity tells how much an Advisory matters to the user.
type AdvisorySeverity string

// Advisory severities.
const (
	AdvisoryInfo    AdvisorySeverity = "info"
	AdvisoryWarning AdvisorySeverity = "warning"
	AdvisoryDanger  AdvisorySeverity = "danger"
)

// Advisory is a finding about a profile that departs from current practice
// (SPEC §5). Advisories never block saving or connecting. Code is stable;
// the UI translates by code. Field names the setting or secret key the
// finding is about, or is empty when it concerns the profile as a whole.
type Advisory struct {
	Code     string           `json:"code"`
	Severity AdvisorySeverity `json:"severity"`
	Field    string           `json:"field,omitempty"`
}
