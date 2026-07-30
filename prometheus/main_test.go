package main

import (
	"bytes"
	"fmt"
	"log"
	"strconv"
	"strings"
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
	assertCounter(t, m.sessionInteractionDepth.WithLabelValues("telnet", "0"), 1)
	assertCounter(t, m.firstResponseExit.WithLabelValues("telnet"), 1)
	assertCounter(t, m.protocolActions.WithLabelValues("telnet", "disconnect"), 1)
	assertCounter(t, m.exporterMessages.WithLabelValues("accepted"), 1)

	assertHistogram(t, m.sessionDuration.WithLabelValues("telnet"), 1, 1250)
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
	assertHistogramCount(t, m.sessionDuration.WithLabelValues("telnet"), 0)
	assertCounter(t, m.completedSessions.WithLabelValues("telnet", "client_disconnect"), 0)
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
		{
			name:            "unsupported depth",
			line:            "Telnet disconnect 127.0.0.1 500 500 4 client_disconnect false",
			malformedReason: "unsupported_event",
		},
		{
			name:            "negative depth",
			line:            "Telnet disconnect 127.0.0.1 500 500 -1 client_disconnect false",
			malformedReason: "invalid_number",
		},
		{
			name:            "invalid depth number",
			line:            "MQTT disconnect 127.0.0.1 500 500 nope client_disconnect false",
			malformedReason: "invalid_number",
		},
		{
			name:            "depth overflow",
			line:            "MQTT disconnect 127.0.0.1 500 500 4294967296 client_disconnect false",
			malformedReason: "invalid_number",
		},
		{
			name:            "known but unsupported depth protocol",
			line:            "CoAP disconnect 127.0.0.1 500 500 0 client_disconnect false",
			malformedReason: "unsupported_event",
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
			for _, protocol := range []string{"telnet", "mqtt"} {
				for _, depth := range []string{"0", "1", "2", "3"} {
					assertCounter(t, m.sessionInteractionDepth.WithLabelValues(protocol, depth), 0)
				}
			}
			assertCounter(t, m.exporterMalformedMessages.WithLabelValues(tt.malformedReason), 1)
			assertCounter(t, m.exporterMessages.WithLabelValues("accepted"), 0)
			assertCounter(t, m.exporterMessages.WithLabelValues("rejected"), 1)

			assertHistogramCount(t, m.sessionDuration.WithLabelValues("telnet"), 0)
		})
	}
}

func TestInteractionDepthLevelsAndEarlyDisconnectCompatibility(t *testing.T) {
	for _, protocol := range []struct {
		server string
		label  string
	}{
		{server: "Telnet", label: "telnet"},
		{server: "MQTT", label: "mqtt"},
	} {
		for depth := 0; depth <= 3; depth++ {
			t.Run(protocol.label+"_depth_"+strconv.Itoa(depth), func(t *testing.T) {
				registry := prometheus.NewRegistry()
				m := newMetrics(registry)
				m.activeClients.WithLabelValues(protocol.server).Set(1)

				handleMetric(fmt.Sprintf(
					"%s disconnect 127.0.0.1 25 50 %d client_disconnect false",
					protocol.server, depth), m)

				assertCounter(t, m.completedSessions.WithLabelValues(protocol.label, "client_disconnect"), 1)
				assertCounter(t, m.sessionInteractionDepth.WithLabelValues(protocol.label, strconv.Itoa(depth)), 1)
				wantEarly := float64(0)
				if depth == 0 {
					wantEarly = 1
				}
				assertCounter(t, m.earlyDisconnect.WithLabelValues(protocol.label), wantEarly)
				assertGauge(t, m.activeClients.WithLabelValues(protocol.server), 0)
			})
		}
	}
}

func TestRepeatedInteractionDepthEventsAndBoundedLabels(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetrics(registry)

	handleMetric("Telnet disconnect 127.0.0.1 10 10 3 client_disconnect false", m)
	handleMetric("Telnet disconnect 127.0.0.1 20 20 3 client_disconnect false", m)
	assertCounter(t, m.sessionInteractionDepth.WithLabelValues("telnet", "3"), 2)

	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range metricFamilies {
		if family.GetName() != "eventhorizon_session_interaction_depth_total" {
			continue
		}
		if len(family.Metric) != 8 {
			t.Fatalf("interaction depth series count = %d, want 8", len(family.Metric))
		}
		allowedProtocols := map[string]bool{"telnet": true, "mqtt": true}
		allowedDepths := map[string]bool{"0": true, "1": true, "2": true, "3": true}
		for _, metric := range family.Metric {
			labels := map[string]string{}
			for _, pair := range metric.Label {
				labels[pair.GetName()] = pair.GetValue()
			}
			if len(labels) != 2 || !allowedProtocols[labels["protocol"]] || !allowedDepths[labels["depth_level"]] {
				t.Fatalf("unexpected interaction depth labels: %#v", labels)
			}
		}
		return
	}
	t.Fatal("interaction depth metric family was not gathered")
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

func TestApplicationByteMetrics(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		protocol  string
		direction string
		want      float64
	}{
		{name: "valid Telnet bytes received", line: "Telnet bytes_received 17", protocol: "telnet", direction: "received", want: 17},
		{name: "valid Telnet bytes sent", line: "Telnet bytes_sent 11", protocol: "telnet", direction: "sent", want: 11},
		{name: "valid MQTT bytes received", line: "MQTT bytes_received 29", protocol: "mqtt", direction: "received", want: 29},
		{name: "valid MQTT bytes sent", line: "MQTT bytes_sent 23", protocol: "mqtt", direction: "sent", want: 23},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			m := newMetrics(registry)

			handleMetric(tt.line, m)

			if tt.direction == "received" {
				assertCounter(t, m.bytesReceived.WithLabelValues(tt.protocol), tt.want)
				assertCounter(t, m.bytesSent.WithLabelValues(tt.protocol), 0)
			} else {
				assertCounter(t, m.bytesSent.WithLabelValues(tt.protocol), tt.want)
				assertCounter(t, m.bytesReceived.WithLabelValues(tt.protocol), 0)
			}
			assertCounter(t, m.exporterMessages.WithLabelValues("accepted"), 1)
			assertCounter(t, m.exporterMessages.WithLabelValues("rejected"), 0)
		})
	}
}

func TestMalformedApplicationByteMetricsDoNotMutateCounters(t *testing.T) {
	tests := []struct {
		name            string
		line            string
		malformedReason string
	}{
		{name: "zero value is not an I/O success", line: "Telnet bytes_received 0", malformedReason: "invalid_number"},
		{name: "invalid numeric value", line: "Telnet bytes_received nope", malformedReason: "invalid_number"},
		{name: "negative value", line: "MQTT bytes_sent -1", malformedReason: "invalid_number"},
		{name: "uint64 overflow", line: "MQTT bytes_received 18446744073709551616", malformedReason: "invalid_number"},
		{name: "ssize_t overflow", line: "Telnet bytes_sent 9223372036854775808", malformedReason: "invalid_number"},
		{name: "missing field", line: "Telnet bytes_sent", malformedReason: "missing_fields"},
		{name: "extra field", line: "MQTT bytes_received 7 extra", malformedReason: "unknown_format"},
		{name: "unsupported protocol", line: "CoAP bytes_sent 7", malformedReason: "unsupported_event"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			m := newMetrics(registry)

			handleMetric(tt.line, m)

			assertCounter(t, m.bytesReceived.WithLabelValues("telnet"), 0)
			assertCounter(t, m.bytesSent.WithLabelValues("telnet"), 0)
			assertCounter(t, m.bytesReceived.WithLabelValues("mqtt"), 0)
			assertCounter(t, m.bytesSent.WithLabelValues("mqtt"), 0)
			assertCounter(t, m.exporterMalformedMessages.WithLabelValues(tt.malformedReason), 1)
			assertCounter(t, m.exporterMessages.WithLabelValues("accepted"), 0)
			assertCounter(t, m.exporterMessages.WithLabelValues("rejected"), 1)
		})
	}
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

func TestFieldSafeModeDoesNotRequireGeoDatabase(t *testing.T) {
	db = nil
	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
		}
		db = nil
	})

	if err := openGeoDatabase("/missing/field-safe.mmdb", true); err != nil {
		t.Fatalf("field-safe mode unexpectedly required GeoIP data: %v", err)
	}
	if db != nil {
		t.Fatal("field-safe mode unexpectedly opened a GeoIP database")
	}
	if err := openGeoDatabase("/missing/non-field.mmdb", false); err == nil {
		t.Fatal("non-field mode accepted a missing GeoIP database")
	}
}

func TestFieldSafeModeRetainsBoundedMetricsWithoutRawSeriesOrLogs(t *testing.T) {
	t.Setenv("EVENTHORIZON_FIELD_SAFE_MODE", "true")

	registry := prometheus.NewRegistry()
	m := newMetrics(registry)
	var logs bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldOutput) })

	handleMetric("Telnet action 203.0.113.8 raw-client-input", m)
	handleMetric("MQTT CONNECT private-version", m)
	handleMetric("MQTT SUBSCRIBE private/topic 1", m)
	handleMetric("MQTT PUBLISH private/topic 1", m)
	handleMetric("MQTT credentials secret-user secret-password", m)
	handleMetric("MQTT bytes_sent not-a-number", m)

	assertCounter(t, m.protocolActions.WithLabelValues("telnet", "read"), 1)
	assertCounter(t, m.protocolActions.WithLabelValues("mqtt", "mqtt_connect"), 1)
	assertCounter(t, m.protocolActions.WithLabelValues("mqtt", "mqtt_subscribe"), 1)
	assertCounter(t, m.protocolActions.WithLabelValues("mqtt", "mqtt_publish"), 1)
	assertCounter(t, m.exporterMessages.WithLabelValues("accepted"), 5)
	assertCounter(t, m.exporterMessages.WithLabelValues("rejected"), 1)

	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range []string{
		"telnet_pit_input",
		"mqtt_pit_connect_versions",
		"mqtt_pit_subscribe_topics",
		"mqtt_pit_publish_topics",
		"mqtt_pit_credentials",
	} {
		if hasMetricFamily(metricFamilies, family) {
			t.Fatalf("field-safe mode exposed raw metric family %q", family)
		}
	}

	for _, sensitive := range []string{
		"203.0.113.8",
		"raw-client-input",
		"private-version",
		"private/topic",
		"secret-user",
		"secret-password",
		"not-a-number",
	} {
		if strings.Contains(logs.String(), sensitive) {
			t.Fatalf("field-safe mode logged sensitive value %q", sensitive)
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

func assertHistogramCount(t *testing.T, observer prometheus.Observer, want uint64) {
	assertHistogram(t, observer, want, 0)
}

func assertHistogram(t *testing.T, observer prometheus.Observer, wantCount uint64, wantSum float64) {
	t.Helper()
	metric, ok := observer.(prometheus.Metric)
	if !ok {
		t.Fatal("histogram observer does not implement prometheus.Metric")
	}
	dtoMetric := &dto.Metric{}
	if err := metric.Write(dtoMetric); err != nil {
		t.Fatalf("write histogram: %v", err)
	}
	histogram := dtoMetric.GetHistogram()
	if got := histogram.GetSampleCount(); got != wantCount {
		t.Fatalf("histogram count = %d, want %d", got, wantCount)
	}
	if got := histogram.GetSampleSum(); got != wantSum {
		t.Fatalf("histogram sum = %f, want %f", got, wantSum)
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
