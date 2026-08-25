package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func counterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()
	metric := &dto.Metric{}
	if err := counter.Write(metric); err != nil {
		t.Fatalf("write counter: %v", err)
	}
	return metric.GetCounter().GetValue()
}

func TestInitAndRecord(t *testing.T) {
	Init()
	if Registry == nil || VerifyTotal == nil || EnrollStartTotal == nil || EnrollConfirmTotal == nil {
		t.Fatal("Init should initialize every metric")
	}

	verify := VerifyTotal.WithLabelValues("success", "totp")
	verifyBefore := counterValue(t, verify)
	RecordVerify("success", "totp")
	if got := counterValue(t, verify); got != verifyBefore+1 {
		t.Fatalf("verify counter = %v, want %v", got, verifyBefore+1)
	}

	enrollBefore := counterValue(t, EnrollStartTotal)
	RecordEnrollStart()
	if got := counterValue(t, EnrollStartTotal); got != enrollBefore+1 {
		t.Fatalf("enroll start counter = %v, want %v", got, enrollBefore+1)
	}

	confirm := EnrollConfirmTotal.WithLabelValues("failure")
	confirmBefore := counterValue(t, confirm)
	RecordEnrollConfirm("failure")
	if got := counterValue(t, confirm); got != confirmBefore+1 {
		t.Fatalf("enroll confirm counter = %v, want %v", got, confirmBefore+1)
	}
}

func TestRecordWithNilCollectors(t *testing.T) {
	oldVerify := VerifyTotal
	oldEnrollStart := EnrollStartTotal
	oldEnrollConfirm := EnrollConfirmTotal
	VerifyTotal = nil
	EnrollStartTotal = nil
	EnrollConfirmTotal = nil
	defer func() {
		VerifyTotal = oldVerify
		EnrollStartTotal = oldEnrollStart
		EnrollConfirmTotal = oldEnrollConfirm
	}()

	RecordVerify("failure", "invalid")
	RecordEnrollStart()
	RecordEnrollConfirm("failure")
}
