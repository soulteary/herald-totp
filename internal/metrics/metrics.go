package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	metrics "github.com/soulteary/metrics-kit"
)

var (
	// Registry is the Prometheus registry for herald-totp metrics
	Registry *metrics.Registry

	// VerifyTotal counts verify attempts by result and reason
	VerifyTotal *prometheus.CounterVec

	// EnrollStartTotal counts enroll/start calls
	EnrollStartTotal prometheus.Counter

	// EnrollConfirmTotal counts enroll/confirm by result
	EnrollConfirmTotal *prometheus.CounterVec
)

func init() {
	Init()
}

// Init initializes herald-totp metrics
func Init() {
	Registry = metrics.NewRegistry("herald_totp")
	VerifyTotal = Registry.Counter("verify_total").
		Help("Total TOTP verify attempts").
		Labels("result", "reason").
		BuildVec()
	EnrollStartTotal = Registry.Counter("enroll_start_total").
		Help("Total TOTP enroll/start calls").
		Build()
	EnrollConfirmTotal = Registry.Counter("enroll_confirm_total").
		Help("Total TOTP enroll/confirm by result").
		Labels("result").
		BuildVec()
}

// RecordVerify records a verify attempt (result: "success" or "failure", reason: e.g. "invalid", "replay")
func RecordVerify(result, reason string) {
	if VerifyTotal != nil {
		VerifyTotal.WithLabelValues(result, reason).Inc()
	}
}

// RecordEnrollStart records an enroll/start call
func RecordEnrollStart() {
	if EnrollStartTotal != nil {
		EnrollStartTotal.Inc()
	}
}

// RecordEnrollConfirm records an enroll/confirm (result: "success" or "failure")
func RecordEnrollConfirm(result string) {
	if EnrollConfirmTotal != nil {
		EnrollConfirmTotal.WithLabelValues(result).Inc()
	}
}
