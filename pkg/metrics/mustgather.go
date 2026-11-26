package metrics

// MustGatherAttempt records the started and outcome metrics of a single
// must-gather attempt. The started counter is incremented on creation; callers
// must call Finish exactly once to record the outcome.
type MustGatherAttempt struct {
	source    string
	alertType string
	product   string
}

// StartMustGatherAttempt increments MustGatherStarted and returns the attempt
// whose outcome must be recorded with Finish. Empty source or alertType values
// are recorded as "unknown".
func StartMustGatherAttempt(source, alertType, product string) *MustGatherAttempt {
	if source == "" {
		source = MustGatherSourceUnknown
	}
	if alertType == "" {
		alertType = MustGatherSourceUnknown
	}
	a := &MustGatherAttempt{source: source, alertType: alertType, product: product}
	Inc(MustGatherStarted, a.source, a.alertType, a.product)
	return a
}

// Finish increments MustGatherOutcome for the attempt.
func (a *MustGatherAttempt) Finish(status, reason string) {
	Inc(MustGatherOutcome, status, reason, a.source, a.alertType, a.product)
}
