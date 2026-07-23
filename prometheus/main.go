package main

import (
	// "bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"

	// "github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metrics struct {
	fieldSafeMode bool

	totalConnects    *prometheus.CounterVec
	totalTrappedTime *prometheus.CounterVec
	activeClients    *prometheus.GaugeVec
	clients          *prometheus.CounterVec

	sessionStarts             *prometheus.CounterVec
	completedSessions         *prometheus.CounterVec
	sessionDuration           *prometheus.HistogramVec
	earlyDisconnect           *prometheus.CounterVec
	firstResponseExit         *prometheus.CounterVec
	protocolActions           *prometheus.CounterVec
	sessionInteractionDepth   *prometheus.CounterVec
	exporterMalformedMessages *prometheus.CounterVec
	exporterMessages          *prometheus.CounterVec
	readErrors                *prometheus.CounterVec
	writeErrors               *prometheus.CounterVec
	bytesSent                 *prometheus.CounterVec
	bytesReceived             *prometheus.CounterVec

	upnpOtherHttpRequests  *prometheus.CounterVec
	upnpMSearchRequests    *prometheus.CounterVec
	upnpNonMSearchRequests *prometheus.CounterVec

	mqttMalformedConnect prometheus.Counter
	mqttConnectVersions  *prometheus.CounterVec
	mqttSubscribeTopics  *prometheus.CounterVec
	mqttCredentials      *prometheus.CounterVec
	telnetInput          *prometheus.CounterVec
	mqttPublishTopics    *prometheus.CounterVec
	mqttConacks          prometheus.Counter
	mqttUnsubscribe      prometheus.Counter
	mqttPubrec           prometheus.Counter
}

// Global variable
var db *maxminddb.Reader

func newMetrics(registerer prometheus.Registerer) *metrics {
	m := &metrics{
		fieldSafeMode: fieldSafeModeEnabled(),
		totalConnects: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "total_connects",
			Help: "Total client connections",
		}, []string{"server"}),
		totalTrappedTime: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "total_trapped_time_ms",
			Help: "Total time clients were trapped (ms)",
		}, []string{"server"}),
		activeClients: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "current_connected_clients",
			Help: "Currently connected clients",
		}, []string{"server"}),
		clients: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tarpitted_clients",
			Help: "Connected clients",
		}, []string{ /*"ip", */ "server", "country", "latitude", "longitude"}),
		sessionStarts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "eventhorizon_session_starts_total",
			Help: "DEPRECATED: duplicates total_connects; retained temporarily for compatibility",
		}, []string{"protocol"}),
		completedSessions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "eventhorizon_completed_sessions_total",
			Help: "Total completed EventHorizon sessions",
		}, []string{"protocol", "disconnect_reason"}),
		sessionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "eventhorizon_session_duration_ms",
			Help:    "Duration of completed EventHorizon sessions in milliseconds",
			Buckets: []float64{10, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000},
		}, []string{"protocol"}),
		earlyDisconnect: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "eventhorizon_early_disconnect_total",
			Help: "Completed sessions with zero meaningful client interactions",
		}, []string{"protocol"}),
		firstResponseExit: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "eventhorizon_first_response_exit_total",
			Help: "Completed sessions that exited after the first response and before another meaningful client interaction",
		}, []string{"protocol"}),
		protocolActions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "eventhorizon_protocol_actions_total",
			Help: "Total bounded protocol actions observed by EventHorizon",
		}, []string{"protocol", "action"}),
		sessionInteractionDepth: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "eventhorizon_session_interaction_depth_total",
			Help: "Completed Telnet and MQTT sessions by bounded final interaction depth level",
		}, []string{"protocol", "depth_level"}),
		exporterMalformedMessages: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "eventhorizon_exporter_malformed_messages_total",
			Help: "Malformed or unsupported metric messages received by the EventHorizon exporter",
		}, []string{"reason"}),
		exporterMessages: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "eventhorizon_exporter_messages_total",
			Help: "DEPRECATED: exporter message totals by parse status; use eventhorizon_exporter_malformed_messages_total for parser reliability",
		}, []string{"status"}),
		readErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "eventhorizon_read_errors_total",
			Help: "Bounded read-side runtime I/O outcomes; peer closure or reset may be normal client behavior",
		}, []string{"protocol", "reason"}),
		writeErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "eventhorizon_write_errors_total",
			Help: "Bounded write-side runtime I/O outcomes; peer closure or reset may be normal client behavior",
		}, []string{"protocol", "reason"}),
		bytesSent: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "eventhorizon_bytes_sent_total",
			Help: "Bytes returned by successful Telnet and MQTT client-facing writes; includes protocol framing and excludes failed or zero-byte I/O and internal telemetry",
		}, []string{"protocol"}),
		bytesReceived: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "eventhorizon_bytes_received_total",
			Help: "Bytes returned by successful Telnet and MQTT client-facing reads; includes protocol framing and excludes failed or zero-byte I/O and internal telemetry",
		}, []string{"protocol"}),
		// ---------------
		upnpOtherHttpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "upnp_other_http_requests",
			Help: "Number of http requests that are not for the .xml file",
		}, []string{"method", "url"}),
		upnpMSearchRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "upnp_M-Search_requests",
			Help: "Number of M-Search requests",
		}, []string{"ip"}),
		upnpNonMSearchRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "upnp_non_M-Search_requests",
			Help: "Number of SSDP requests that are not M-SEARCH",
		}, []string{"ip"}),
		// ---------------
		mqttMalformedConnect: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mqtt_pit_malformed_connects",
			Help: "Malformed MQTT CONNECT packets received",
		}),
		mqttConnectVersions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mqtt_pit_connect_versions",
			Help: "MQTT CONNECT versions used by clients",
		}, []string{"version"}),
		mqttSubscribeTopics: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mqtt_pit_subscribe_topics",
			Help: "MQTT SUBSCRIBE topics and QoS",
		}, []string{"topic", "qos"}),
		mqttCredentials: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mqtt_pit_credentials",
			Help: "MQTT credentials used",
		}, []string{"username", "password"}),
		telnetInput: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "telnet_pit_input",
			Help: "Attacker input captured from Telnet sessions",
		}, []string{"ip"}),
		mqttPublishTopics: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mqtt_pit_publish_topics",
			Help: "MQTT PUBLISH topic and QoS",
		}, []string{"topic", "qos"}),
		mqttConacks: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mqtt_pit_connack_counter",
			Help: "Total CONNACK requests for MQTT",
		}),
		mqttUnsubscribe: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mqtt_pit_unsub_counter",
			Help: "Total UNSUBSCRIBE requests for MQTT",
		}),
		mqttPubrec: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mqtt_pit_pubrec_counter",
			Help: "Total PUBREC requests for MQTT",
		}),
	}
	for _, protocol := range []string{"telnet", "mqtt"} {
		server := "Telnet"
		if protocol == "mqtt" {
			server = "MQTT"
		}
		m.totalConnects.WithLabelValues(server).Add(0)
		m.activeClients.WithLabelValues(server).Set(0)
		m.sessionStarts.WithLabelValues(protocol).Add(0)
		m.earlyDisconnect.WithLabelValues(protocol).Add(0)
		m.firstResponseExit.WithLabelValues(protocol).Add(0)
		m.sessionDuration.WithLabelValues(protocol)
		for _, reason := range []string{"client_disconnect", "read_error", "write_error", "timeout", "parse_error", "server_close", "unknown"} {
			m.completedSessions.WithLabelValues(protocol, reason).Add(0)
		}
		m.bytesSent.WithLabelValues(protocol).Add(0)
		m.bytesReceived.WithLabelValues(protocol).Add(0)
		for depthLevel := 0; depthLevel <= 3; depthLevel++ {
			m.sessionInteractionDepth.WithLabelValues(protocol, strconv.Itoa(depthLevel)).Add(0)
		}
	}
	registerer.MustRegister(m.totalConnects, m.totalTrappedTime, m.activeClients, m.clients,
		m.sessionStarts, m.completedSessions, m.sessionDuration, m.earlyDisconnect, m.firstResponseExit, m.protocolActions,
		m.sessionInteractionDepth,
		m.exporterMalformedMessages, m.exporterMessages, m.readErrors, m.writeErrors, m.bytesSent, m.bytesReceived,
		m.upnpOtherHttpRequests, m.upnpMSearchRequests, m.upnpNonMSearchRequests,
		m.mqttConacks, m.mqttUnsubscribe, m.mqttPubrec,
		m.mqttMalformedConnect, m.mqttConnectVersions, m.mqttSubscribeTopics, m.mqttCredentials, m.telnetInput, m.mqttPublishTopics)
	return m
}

func NewMetrics() *metrics {
	return newMetrics(prometheus.DefaultRegisterer)
}

func fieldSafeModeEnabled() bool {
	value := os.Getenv("EVENTHORIZON_FIELD_SAFE_MODE")
	if value == "" {
		return false
	}

	enabled, err := strconv.ParseBool(value)
	if err != nil {
		log.Printf("Ignoring invalid EVENTHORIZON_FIELD_SAFE_MODE value; field-safe mode remains disabled")
		return false
	}
	return enabled
}

func main() {
	var err error
	geoliteDbPath := os.Getenv("GEO_DB")
	// fmt.Print(geoliteDbPath+"\n")
	db, err = maxminddb.Open(geoliteDbPath)
	if err != nil {
		log.Fatal("Cannot open GeoLite2 database: ", err)
	}
	defer db.Close()

	// Register metrics
	m := NewMetrics()

	// test values
	// m.totalTrappedTime.WithLabelValues("Telnet").Add(10)
	// m.totalTrappedTime.WithLabelValues("UPnP").Add(20)
	// m.totalTrappedTime.WithLabelValues("MQTT").Add(30)
	// m.totalTrappedTime.WithLabelValues("CoAP").Add(40)
	// m.totalTrappedTime.WithLabelValues("SSH").Add(50)

	// Start socket listener
	go listenForMetrics("/tmp/tarpit_exporter.sock", m)

	// HTTP handler
	http.Handle("/metrics", promhttp.Handler())
	log.Println("Metrics available at :9101/metrics")
	log.Fatal(http.ListenAndServe(":9101", nil))
}

func listenForMetrics(socketPath string, metrics *metrics) {
	// Clean old socket
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("Failed to remove existing socket: %v", err)
	}

	conn, err := net.ListenPacket("unixgram", socketPath)
	if err != nil {
		log.Fatalf("Socket bind error: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			log.Println("Read error:", err)
			continue
		}
		handleMetric(strings.TrimSpace(string(buf[:n])), metrics)
	}
}

func handleMetric(line string, metrics *metrics) {
	line = strings.TrimSpace(line)
	if line == "" {
		rejectMetric(metrics, "empty_message", "Empty metric line")
		return
	}

	fields := strings.Fields(line)
	if !metrics.fieldSafeMode {
		log.Println(fields)
	}

	if len(fields) < 2 {
		rejectMetric(metrics, "missing_fields", "Malformed metric line (need at least 2 fields): %q", line)
		return
	}

	server := fields[0]
	command := fields[1]
	if _, ok := protocolLabel(server); !ok {
		rejectMetric(metrics, "unknown_server", "Unknown server in metric line: %q", line)
		return
	}

	switch command {
	case "connect":
		if len(fields) < 3 {
			rejectMetric(metrics, "missing_fields", "Malformed connect metric (need 3 fields): %q", line)
			return
		}
		ip := fields[2]
		if _, err := netip.ParseAddr(ip); err != nil {
			rejectMetric(metrics, "invalid_number", "Invalid client IP in connect metric line %q: %v", line, err)
			return
		}
		country := geoLookup(ip)
		lat := CapitalCoordinates[country].Latitude
		lon := CapitalCoordinates[country].Longitude
		// Reduce cardinality by removing ip
		handleConnect(server, country, lat, lon, metrics)
		observeSessionStart(server, metrics)
		observeProtocolAction(server, "connect", metrics)
		acceptMetric(metrics)
	case "disconnect":
		if len(fields) != 4 && len(fields) != 8 {
			reason := "unknown_format"
			if len(fields) < 8 {
				reason = "missing_fields"
			}
			rejectMetric(metrics, reason, "Malformed disconnect metric (need exactly 4 or 8 fields): %q", line)
			return
		}
		if _, err := netip.ParseAddr(fields[2]); err != nil {
			rejectMetric(metrics, "invalid_number", "Invalid client IP in disconnect metric line %q: %v", line, err)
			return
		}
		parsedTimeTrapped, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			rejectMetric(metrics, "invalid_number", "Invalid trapped time in metric line %q: %v", line, err)
			return
		}
		timeTrapped := float64(parsedTimeTrapped)
		if len(fields) == 4 {
			handleDisconnect(server, timeTrapped, metrics)
			observeProtocolAction(server, "disconnect", metrics)
			acceptMetric(metrics)
			return
		}

		// Extended format:
		// <server> disconnect <ip> <trapped_ms> <duration_ms>
		// <interaction_depth> <reason> <first_response_exit>
		durationMs, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil {
			rejectMetric(metrics, "invalid_number", "Invalid session duration in metric line %q: %v", line, err)
			return
		}
		interactionDepth, err := strconv.ParseUint(fields[5], 10, 32)
		if err != nil {
			rejectMetric(metrics, "invalid_number", "Invalid interaction depth in metric line %q: %v", line, err)
			return
		}
		protocol, supportedDepthProtocol := protocolLabel(server)
		if !supportedDepthProtocol || (protocol != "telnet" && protocol != "mqtt") {
			rejectMetric(metrics, "unsupported_event", "Interaction depth is unsupported for server in metric line: %q", line)
			return
		}
		if interactionDepth > 3 {
			rejectMetric(metrics, "unsupported_event", "Unsupported interaction depth in metric line: %q", line)
			return
		}
		disconnectReason, ok := canonicalDisconnectReason(fields[6])
		if !ok {
			rejectMetric(metrics, "unsupported_event", "Unsupported disconnect reason in metric line: %q", line)
			return
		}
		firstResponseExit, err := strconv.ParseBool(fields[7])
		if err != nil {
			rejectMetric(metrics, "invalid_number", "Invalid first-response-exit flag in metric line %q: %v", line, err)
			return
		}

		// Apply all lifecycle mutations only after the complete message is valid.
		handleDisconnect(server, timeTrapped, metrics)
		observeProtocolAction(server, "disconnect", metrics)
		observeCompletedSession(
			server,
			float64(durationMs),
			uint32(interactionDepth),
			disconnectReason,
			firstResponseExit,
			metrics,
		)
		acceptMetric(metrics)
	// UPnP
	case "otherHttpRequests":
		method := " "
		url := " "
		if len(fields) >= 3 {
			method = fields[2]
		}
		if len(fields) >= 4 {
			url = fields[3]
		}

		if !metrics.fieldSafeMode {
			metrics.upnpOtherHttpRequests.WithLabelValues(method, url).Inc()
		}
		observeProtocolAction(server, "upnp_http_request", metrics)
		acceptMetric(metrics)
	case "M-SEARCH":
		if len(fields) < 3 {
			rejectMetric(metrics, "missing_fields", "Malformed M-SEARCH metric (need 3 fields): %q", line)
			return
		}
		ip := fields[2]
		if !metrics.fieldSafeMode {
			metrics.upnpMSearchRequests.WithLabelValues(ip).Inc()
		}
		observeProtocolAction(server, "upnp_discovery", metrics)
		acceptMetric(metrics)
	case "non-M-SEARCH":
		if len(fields) < 3 {
			rejectMetric(metrics, "missing_fields", "Malformed non-M-SEARCH metric (need 3 fields): %q", line)
			return
		}
		ip := fields[2]
		if !metrics.fieldSafeMode {
			metrics.upnpNonMSearchRequests.WithLabelValues(ip).Inc()
		}
		observeProtocolAction(server, "upnp_discovery", metrics)
		acceptMetric(metrics)
	// MQTT
	case "CONNECT":
		if len(fields) < 3 {
			rejectMetric(metrics, "missing_fields", "Malformed MQTT CONNECT metric (need 3 fields): %q", line)
			return
		}
		version := fields[2]
		if !metrics.fieldSafeMode {
			metrics.mqttConnectVersions.WithLabelValues(version).Inc()
		}
		observeProtocolAction(server, "mqtt_connect", metrics)
		acceptMetric(metrics)

	case "malformedConnect":
		metrics.mqttMalformedConnect.Inc()
		observeProtocolAction(server, "malformed_connect", metrics)
		acceptMetric(metrics)

	case "SUBSCRIBE":
		if len(fields) < 4 {
			rejectMetric(metrics, "missing_fields", "Malformed SUBSCRIBE metric (need 4 fields): %q", line)
			return
		}
		topic := fields[2]
		qos := fields[3]
		if !metrics.fieldSafeMode {
			metrics.mqttSubscribeTopics.WithLabelValues(topic, qos).Inc()
		}
		observeProtocolAction(server, "mqtt_subscribe", metrics)
		acceptMetric(metrics)

	case "credentials":
		username := " "
		password := " "
		if len(fields) >= 3 {
			username = fields[2]
		}
		if len(fields) >= 4 {
			password = fields[3]
		}

		if !metrics.fieldSafeMode {
			metrics.mqttCredentials.WithLabelValues(username, password).Inc()
		}
		acceptMetric(metrics)

	case "PUBLISH":
		if len(fields) < 4 {
			rejectMetric(metrics, "missing_fields", "Malformed PUBLISH metric (need 4 fields): %q", line)
			return
		}
		topic := fields[2]
		qos := fields[3]
		if !metrics.fieldSafeMode {
			metrics.mqttPublishTopics.WithLabelValues(topic, qos).Inc()
		}
		observeProtocolAction(server, "mqtt_publish", metrics)
		acceptMetric(metrics)

	case "CONNACK":
		metrics.mqttConacks.Inc()
		observeProtocolAction(server, "mqtt_connack", metrics)
		acceptMetric(metrics)
	case "UNSUBSCRIBE":
		metrics.mqttUnsubscribe.Inc()
		observeProtocolAction(server, "mqtt_unsubscribe", metrics)
		acceptMetric(metrics)
	case "PUBREC":
		metrics.mqttPubrec.Inc()
		observeProtocolAction(server, "mqtt_pubrec", metrics)
		acceptMetric(metrics)
	case "action":
		if len(fields) < 4 {
			rejectMetric(metrics, "missing_fields", "Malformed Telnet action metric (need 4 fields): %q", line)
			return
		}
		ip := fields[2]
		if !metrics.fieldSafeMode {
			metrics.telnetInput.WithLabelValues(ip).Inc()
		}
		observeProtocolAction(server, "read", metrics)
		acceptMetric(metrics)
	case "protocol_action":
		if len(fields) != 3 {
			reason := "unknown_format"
			if len(fields) < 3 {
				reason = "missing_fields"
			}
			rejectMetric(metrics, reason, "Malformed protocol action metric: %q", line)
			return
		}
		if !allowedProtocolAction(fields[2]) {
			rejectMetric(metrics, "unsupported_event", "Unsupported protocol action in metric line: %q", line)
			return
		}
		observeProtocolAction(server, fields[2], metrics)
		acceptMetric(metrics)
	case "session_start":
		if len(fields) != 2 {
			rejectMetric(metrics, "unknown_format", "Malformed session_start metric: %q", line)
			return
		}
		observeSessionStart(server, metrics)
		acceptMetric(metrics)
	case "read_error":
		if len(fields) < 3 {
			rejectMetric(metrics, "missing_fields", "Malformed read_error metric (need 3 fields): %q", line)
			return
		}
		observeReadError(server, fields[2], metrics)
		acceptMetric(metrics)
	case "write_error":
		if len(fields) < 3 {
			rejectMetric(metrics, "missing_fields", "Malformed write_error metric (need 3 fields): %q", line)
			return
		}
		observeWriteError(server, fields[2], metrics)
		acceptMetric(metrics)
	case "bytes_sent", "bytes_received":
		byteCount, reason, err := parseApplicationByteMetric(server, fields)
		if err != nil {
			rejectMetric(metrics, reason, "Invalid %s metric line %q: %v", command, line, err)
			return
		}
		if command == "bytes_sent" {
			observeBytesSent(server, byteCount, metrics)
		} else {
			observeBytesReceived(server, byteCount, metrics)
		}
		acceptMetric(metrics)
	default:
		rejectMetric(metrics, "unsupported_event", "Unsupported metric command in line: %q", line)
	}
}

const maxSuccessfulIOBytes uint64 = 1<<63 - 1

func parseApplicationByteMetric(server string, fields []string) (float64, string, error) {
	if len(fields) != 3 {
		if len(fields) < 3 {
			return 0, "missing_fields", fmt.Errorf("need exactly 3 fields")
		}
		return 0, "unknown_format", fmt.Errorf("need exactly 3 fields")
	}

	protocol, ok := protocolLabel(server)
	if !ok || (protocol != "telnet" && protocol != "mqtt") {
		return 0, "unsupported_event", fmt.Errorf("byte metrics support only Telnet and MQTT")
	}

	byteCount, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return 0, "invalid_number", err
	}
	if byteCount == 0 {
		return 0, "invalid_number", fmt.Errorf("byte count must be positive")
	}
	if byteCount > maxSuccessfulIOBytes {
		return 0, "invalid_number", fmt.Errorf("byte count exceeds a positive 64-bit ssize_t result")
	}

	return float64(byteCount), "", nil
}

func acceptMetric(metrics *metrics) {
	metrics.exporterMessages.WithLabelValues("accepted").Inc()
}

func rejectMetric(metrics *metrics, reason string, format string, args ...any) {
	recordMalformedMetric(metrics, reason, format, args...)
	metrics.exporterMessages.WithLabelValues("rejected").Inc()
}

func recordMalformedMetric(metrics *metrics, reason string, format string, args ...any) {
	boundedReason := boundedMalformedReason(reason)
	metrics.exporterMalformedMessages.WithLabelValues(boundedReason).Inc()
	if metrics.fieldSafeMode {
		log.Printf("Rejected malformed metric: reason=%s", boundedReason)
		return
	}
	log.Printf(format, args...)
}

func protocolLabel(server string) (string, bool) {
	switch server {
	case "Telnet":
		return "telnet", true
	case "UPnP":
		return "upnp", true
	case "MQTT":
		return "mqtt", true
	case "CoAP":
		return "coap", true
	case "SSH":
		return "ssh", true
	default:
		return "", false
	}
}

func observeSessionStart(server string, metrics *metrics) {
	protocol, ok := protocolLabel(server)
	if !ok {
		return
	}
	metrics.sessionStarts.WithLabelValues(protocol).Inc()
}

func observeProtocolAction(server string, action string, metrics *metrics) {
	protocol, ok := protocolLabel(server)
	if !ok {
		return
	}
	if !allowedProtocolAction(action) {
		log.Printf("Ignoring unbounded protocol action %q for %s", action, server)
		return
	}
	metrics.protocolActions.WithLabelValues(protocol, action).Inc()
}

func observeReadError(server string, reason string, metrics *metrics) {
	protocol, ok := protocolLabel(server)
	if !ok {
		return
	}
	metrics.readErrors.WithLabelValues(protocol, boundedIOErrorReason(reason)).Inc()
}

func observeWriteError(server string, reason string, metrics *metrics) {
	protocol, ok := protocolLabel(server)
	if !ok {
		return
	}
	metrics.writeErrors.WithLabelValues(protocol, boundedIOErrorReason(reason)).Inc()
}

func observeBytesSent(server string, bytes float64, metrics *metrics) {
	protocol, ok := protocolLabel(server)
	if !ok {
		return
	}
	metrics.bytesSent.WithLabelValues(protocol).Add(bytes)
}

func observeBytesReceived(server string, bytes float64, metrics *metrics) {
	protocol, ok := protocolLabel(server)
	if !ok {
		return
	}
	metrics.bytesReceived.WithLabelValues(protocol).Add(bytes)
}

func allowedProtocolAction(action string) bool {
	switch action {
	case "connect", "disconnect", "read", "write", "banner",
		"mqtt_connect", "mqtt_publish", "mqtt_subscribe", "mqtt_disconnect",
		"mqtt_connack", "mqtt_pubrec", "mqtt_unsubscribe", "malformed_connect",
		"coap_request", "upnp_discovery", "upnp_http_request", "upnp_http_response":
		return true
	default:
		return false
	}
}

func boundedMalformedReason(reason string) string {
	switch reason {
	case "empty_message", "unknown_format", "unknown_server", "missing_fields", "invalid_number", "unsupported_event":
		return reason
	default:
		return "unknown_format"
	}
}

func boundedIOErrorReason(reason string) string {
	switch reason {
	case "eof", "timeout", "reset", "closed", "invalid_packet", "unknown":
		return reason
	case "connection_reset":
		return "reset"
	case "broken_pipe", "not_connected", "connection_aborted", "bad_fd":
		return "closed"
	case "timed_out", "would_block":
		return "timeout"
	default:
		return "unknown"
	}
}

func canonicalDisconnectReason(reason string) (string, bool) {
	switch reason {
	case "client_disconnect", "read_error", "write_error", "timeout", "parse_error", "server_close", "unknown":
		return reason, true
	case "inactivity":
		return "timeout", true
	default:
		return "", false
	}
}

func handleConnect(server string, country string, lat float64, lon float64, metrics *metrics) {
	switch server {
	case "Telnet":
		metrics.totalConnects.WithLabelValues("Telnet").Inc()
		metrics.activeClients.WithLabelValues("Telnet").Inc()
		metrics.clients.WithLabelValues("Telnet", country, fmt.Sprintf("%f", lat), fmt.Sprintf("%f", lon)).Inc()
	case "UPnP":
		metrics.totalConnects.WithLabelValues("UPnP").Inc()
		metrics.activeClients.WithLabelValues("UPnP").Inc()
		metrics.clients.WithLabelValues("UPnP", country, fmt.Sprintf("%f", lat), fmt.Sprintf("%f", lon)).Inc()
	case "MQTT":
		metrics.totalConnects.WithLabelValues("MQTT").Inc()
		metrics.activeClients.WithLabelValues("MQTT").Inc()
		metrics.clients.WithLabelValues("MQTT", country, fmt.Sprintf("%f", lat), fmt.Sprintf("%f", lon)).Inc()
	case "CoAP":
		metrics.totalConnects.WithLabelValues("CoAP").Inc()
		metrics.activeClients.WithLabelValues("CoAP").Inc()
		metrics.clients.WithLabelValues("CoAP", country, fmt.Sprintf("%f", lat), fmt.Sprintf("%f", lon)).Inc()
	case "SSH":
		metrics.totalConnects.WithLabelValues("SSH").Inc()
		metrics.activeClients.WithLabelValues("SSH").Inc()
		metrics.clients.WithLabelValues("SSH", country, fmt.Sprintf("%f", lat), fmt.Sprintf("%f", lon)).Inc()
	}
}

func handleDisconnect(server string, timeTrapped float64, metrics *metrics) {
	switch server {
	case "Telnet":
		metrics.activeClients.WithLabelValues("Telnet").Dec()
		metrics.totalTrappedTime.WithLabelValues("Telnet").Add(timeTrapped)
	case "UPnP":
		metrics.activeClients.WithLabelValues("UPnP").Dec()
		metrics.totalTrappedTime.WithLabelValues("UPnP").Add(timeTrapped)
	case "MQTT":
		metrics.activeClients.WithLabelValues("MQTT").Dec()
		metrics.totalTrappedTime.WithLabelValues("MQTT").Add(timeTrapped)
	case "CoAP":
		metrics.activeClients.WithLabelValues("CoAP").Dec()
		metrics.totalTrappedTime.WithLabelValues("CoAP").Add(timeTrapped)
	case "SSH":
		metrics.activeClients.WithLabelValues("SSH").Dec()
		metrics.totalTrappedTime.WithLabelValues("SSH").Add(timeTrapped)
	}

}

func observeCompletedSession(server string, durationMs float64, interactionDepth uint32,
	disconnectReason string, exitedAfterFirstResponse bool, metrics *metrics) {
	protocol, ok := protocolLabel(server)
	if !ok {
		return
	}

	metrics.completedSessions.WithLabelValues(protocol, disconnectReason).Inc()
	metrics.sessionDuration.WithLabelValues(protocol).Observe(durationMs)
	metrics.sessionInteractionDepth.WithLabelValues(protocol, strconv.FormatUint(uint64(interactionDepth), 10)).Inc()
	earlyDisconnect := metrics.earlyDisconnect.WithLabelValues(protocol)
	firstResponseExit := metrics.firstResponseExit.WithLabelValues(protocol)
	if interactionDepth == 0 {
		earlyDisconnect.Inc()
	}
	if exitedAfterFirstResponse {
		firstResponseExit.Inc()
	}
}

func parseTimeMs(s string) int64 {
	var ms int64
	_, _ = fmt.Sscanf(s, "%d", &ms)
	return ms
}

func geoLookup(ipStr string) string {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		log.Printf("Invalid IP address for GeoIP lookup %q: %v", ipStr, err)
		return ""
	}
	if db == nil {
		return ""
	}

	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	err = db.Lookup(ip).Decode(&record)
	if err != nil {
		log.Printf("GeoIP lookup failed for %q: %v", ipStr, err)
		return ""
	}
	fmt.Print(record.Country.ISOCode)

	return record.Country.ISOCode
}
