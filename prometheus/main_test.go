package main

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestExtendedDisconnectUpdatesDurationMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetrics(registry)
	m.activeClients.WithLabelValues("Telnet").Set(1)

	handleMetric(
		"Telnet disconnect 127.0.0.1 500 1250 0 client_disconnect true",
		m,
	)

	assertCounter(t, m.totalTrappedTime.WithLabelValues("Telnet"), 500)
	assertGauge(t, m.activeClients.WithLabelValues("Telnet"), 0)
	assertCounter(t, m.completedSessions.WithLabelValues("telnet", "client_disconnect"), 1)
	assertCounter(t, m.earlyDisconnect.WithLabelValues("telnet"), 1)
	assertCounter(t, m.firstResponseExit.WithLabelValues("telnet"), 1)
	assertCounter(t, m.protocolActions.WithLabelValues("telnet", "disconnect"), 1)
	assertCounter(t, m.exporterMessages.WithLabelValues("accepted"), 1)

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
	m.activeClients.WithLabelValues("CoAP").Set(1)

	handleMetric("CoAP disconnect 127.0.0.1 2000", m)

	assertCounter(t, m.totalTrappedTime.WithLabelValues("CoAP"), 2000)
	assertGauge(t, m.activeClients.WithLabelValues("CoAP"), 0)
	assertCounter(t, m.protocolActions.WithLabelValues("coap", "disconnect"), 1)
	assertCounter(t, m.exporterMessages.WithLabelValues("accepted"), 1)
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

func TestInvalidExtendedDisconnectDoesNotMutateLifecycle(t *testing.T) {
	tests := []struct {
		name            string
		line            string
		malformedReason string
	}{
		{
			name:            "missing duration",
			line:            "Telnet disconnect 127.0.0.1 500 0 client_disconnect false",
			malformedReason: "missing_fields",
		},
		{
			name:            "invalid duration number",
			line:            "Telnet disconnect 127.0.0.1 500 nope 0 client_disconnect false",
			malformedReason: "invalid_number",
		},
		{
			name:            "unsupported protocol",
			line:            "Unknown disconnect 127.0.0.1 500 500 0 client_disconnect false",
			malformedReason: "unknown_server",
		},
		{
			name:            "invalid bounded reason",
			line:            "Telnet disconnect 127.0.0.1 500 500 0 arbitrary_reason false",
			malformedReason: "unsupported_event",
		},
		{
			name:            "malformed extended message",
			line:            "Telnet disconnect 127.0.0.1 500 500 0 client_disconnect false extra",
			malformedReason: "unknown_format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			m := newMetrics(registry)
			m.activeClients.WithLabelValues("Telnet").Set(1)

			handleMetric(tt.line, m)

			assertCounter(t, m.totalTrappedTime.WithLabelValues("Telnet"), 0)
			assertGauge(t, m.activeClients.WithLabelValues("Telnet"), 1)
			assertCounter(t, m.protocolActions.WithLabelValues("telnet", "disconnect"), 0)
			assertCounter(t, m.completedSessions.WithLabelValues("telnet", "client_disconnect"), 0)
			assertCounter(t, m.completedSessions.WithLabelValues("telnet", "unknown"), 0)
			assertCounter(t, m.exporterMalformedMessages.WithLabelValues(tt.malformedReason), 1)
			assertCounter(t, m.exporterMessages.WithLabelValues("accepted"), 0)
			assertCounter(t, m.exporterMessages.WithLabelValues("rejected"), 1)

			metricFamilies, err := registry.Gather()
			if err != nil {
				t.Fatalf("gather metrics: %v", err)
			}
			if hasMetricFamily(metricFamilies, "eventhorizon_session_duration_ms") {
				t.Fatal("malformed disconnect created a duration histogram")
			}
		})
	}
}

func TestLegacyInactivityReasonMapsToTimeout(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetrics(registry)

	handleMetric(
		"MQTT disconnect 127.0.0.1 5000 5000 1 inactivity false",
		m,
	)

	assertCounter(t, m.completedSessions.WithLabelValues("mqtt", "timeout"), 1)
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

func TestConnectUpdatesSessionStartAccounting(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetrics(registry)
	db = nil

	handleMetric("Telnet connect 127.0.0.1", m)

	assertCounter(t, m.totalConnects.WithLabelValues("Telnet"), 1)
	assertCounter(t, m.sessionStarts.WithLabelValues("telnet"), 1)
	assertCounter(t, m.protocolActions.WithLabelValues("telnet", "connect"), 1)
	assertCounter(t, m.exporterMessages.WithLabelValues("accepted"), 1)
}

func TestReliabilityMetricEvents(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetrics(registry)

	handleMetric("MQTT read_error reset", m)
	handleMetric("MQTT write_error broken_pipe", m)
	handleMetric("MQTT bytes_sent 12", m)
	handleMetric("MQTT bytes_received 7", m)

	assertCounter(t, m.readErrors.WithLabelValues("mqtt", "reset"), 1)
	assertCounter(t, m.writeErrors.WithLabelValues("mqtt", "closed"), 1)
	assertCounter(t, m.bytesSent.WithLabelValues("mqtt"), 12)
	assertCounter(t, m.bytesReceived.WithLabelValues("mqtt"), 7)
	assertCounter(t, m.exporterMessages.WithLabelValues("accepted"), 4)
}

func TestMalformedMetricMessagesAreCounted(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetrics(registry)

	handleMetric("", m)
	handleMetric("Unknown connect 127.0.0.1", m)
	handleMetric("Telnet disconnect 127.0.0.1 nope", m)
	handleMetric("Telnet protocol_action", m)
	handleMetric("Telnet unsupported_event", m)

	assertCounter(t, m.exporterMalformedMessages.WithLabelValues("empty_message"), 1)
	assertCounter(t, m.exporterMalformedMessages.WithLabelValues("unknown_server"), 1)
	assertCounter(t, m.exporterMalformedMessages.WithLabelValues("invalid_number"), 1)
	assertCounter(t, m.exporterMalformedMessages.WithLabelValues("missing_fields"), 1)
	assertCounter(t, m.exporterMalformedMessages.WithLabelValues("unsupported_event"), 1)
	assertCounter(t, m.exporterMessages.WithLabelValues("rejected"), 5)
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

func assertGauge(t *testing.T, metric prometheus.Metric, want float64) {
	t.Helper()
	dtoMetric := &dto.Metric{}
	if err := metric.Write(dtoMetric); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	if got := dtoMetric.GetGauge().GetValue(); got != want {
		t.Fatalf("gauge = %f, want %f", got, want)
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
