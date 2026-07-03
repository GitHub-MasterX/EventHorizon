package main

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestExtendedDisconnectUpdatesDurationMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetrics(registry)

	handleMetric(
		"Telnet disconnect 127.0.0.1 500 1250 0 client_disconnect true",
		m,
	)

	assertCounter(t, m.totalTrappedTime.WithLabelValues("Telnet"), 500)
	assertCounter(t, m.completedSessions.WithLabelValues("telnet", "client_disconnect"), 1)
	assertCounter(t, m.earlyDisconnect.WithLabelValues("telnet"), 1)
	assertCounter(t, m.firstResponseExit.WithLabelValues("telnet"), 1)
	assertCounter(t, m.protocolActions.WithLabelValues("telnet", "disconnect"), 1)

	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range metricFamilies {
		if family.GetName() != "eventhorizon_session_duration_ms" {
			continue
		}
		if len(family.Metric) != 1 {
			t.Fatalf("duration histogram metric count = %d, want 1", len(family.Metric))
		}
		histogram := family.Metric[0].GetHistogram()
		if histogram.GetSampleCount() != 1 {
			t.Fatalf("duration sample count = %d, want 1", histogram.GetSampleCount())
		}
		if histogram.GetSampleSum() != 1250 {
			t.Fatalf("duration sample sum = %f, want 1250", histogram.GetSampleSum())
		}
		return
	}
	t.Fatal("duration histogram was not gathered")
}

func TestLegacyDisconnectDoesNotInventSessionDuration(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetrics(registry)

	handleMetric("CoAP disconnect 127.0.0.1 2000", m)

	assertCounter(t, m.totalTrappedTime.WithLabelValues("CoAP"), 2000)
	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	if hasMetricFamily(metricFamilies, "eventhorizon_session_duration_ms") {
		t.Fatal("legacy disconnect created a duration histogram")
	}
	if hasMetricFamily(metricFamilies, "eventhorizon_completed_sessions_total") {
		t.Fatal("legacy disconnect created a completed-session counter")
	}
}

func TestProtocolActionAllowlist(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetrics(registry)

	handleMetric("MQTT protocol_action mqtt_publish", m)
	handleMetric("MQTT protocol_action raw/topic/value", m)

	assertCounter(t, m.protocolActions.WithLabelValues("mqtt", "mqtt_publish"), 1)
	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range metricFamilies {
		if family.GetName() == "eventhorizon_protocol_actions_total" && len(family.Metric) != 1 {
			t.Fatalf("protocol action series count = %d, want 1", len(family.Metric))
		}
	}
}

func assertCounter(t *testing.T, metric prometheus.Metric, want float64) {
	t.Helper()
	dtoMetric := &dto.Metric{}
	if err := metric.Write(dtoMetric); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	if got := dtoMetric.GetCounter().GetValue(); got != want {
		t.Fatalf("counter = %f, want %f", got, want)
	}
}

func hasMetricFamily(metricFamilies []*dto.MetricFamily, name string) bool {
	for _, family := range metricFamilies {
		if family.GetName() == name {
			return true
		}
	}
	return false
}
