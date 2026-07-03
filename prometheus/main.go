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
	totalConnects    *prometheus.CounterVec
	totalTrappedTime *prometheus.CounterVec
	activeClients    *prometheus.GaugeVec
	clients          *prometheus.CounterVec

	completedSessions *prometheus.CounterVec
	sessionDuration   *prometheus.HistogramVec
	earlyDisconnect   *prometheus.CounterVec
	firstResponseExit *prometheus.CounterVec
	protocolActions   *prometheus.CounterVec

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
	registerer.MustRegister(m.totalConnects, m.totalTrappedTime, m.activeClients, m.clients,
		m.completedSessions, m.sessionDuration, m.earlyDisconnect, m.firstResponseExit, m.protocolActions,
		m.upnpOtherHttpRequests, m.upnpMSearchRequests, m.upnpNonMSearchRequests,
		m.mqttConacks, m.mqttUnsubscribe, m.mqttPubrec,
		m.mqttMalformedConnect, m.mqttConnectVersions, m.mqttSubscribeTopics, m.mqttCredentials, m.telnetInput, m.mqttPublishTopics)
	return m
}

func NewMetrics() *metrics {
	return newMetrics(prometheus.DefaultRegisterer)
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
	fields := strings.Fields(line)
	log.Println(fields)

	if len(fields) < 2 {
		log.Printf("Malformed metric line (need at least 2 fields): %q", line)
		return
	}

	server := fields[0]
	command := fields[1]

	switch command {
	case "connect":
		if len(fields) < 3 {
			log.Printf("Malformed connect metric (need 3 fields): %q", line)
			return
		}
		ip := fields[2]
		country := geoLookup(ip)
		lat := CapitalCoordinates[country].Latitude
		lon := CapitalCoordinates[country].Longitude
		// Reduce cardinality by removing ip
		handleConnect(server, country, lat, lon, metrics)
		observeProtocolAction(server, "connect", metrics)
	case "disconnect":
		if len(fields) < 4 {
			log.Printf("Malformed disconnect metric (need 4 fields): %q", line)
			return
		}
		// ip := fields[2]
		parsedTimeTrapped, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			fmt.Println("Error parsing timeTrapped:", err)
			return
		}
		timeTrapped := float64(parsedTimeTrapped)
		handleDisconnect(server, timeTrapped, metrics)
		observeProtocolAction(server, "disconnect", metrics)

		// Extended format:
		// <server> disconnect <ip> <trapped_ms> <duration_ms>
		// <interaction_depth> <reason> <first_response_exit>
		if len(fields) < 8 {
			return
		}
		durationMs, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil {
			log.Printf("Invalid session duration in metric line %q: %v", line, err)
			return
		}
		interactionDepth, err := strconv.ParseUint(fields[5], 10, 32)
		if err != nil {
			log.Printf("Invalid interaction depth in metric line %q: %v", line, err)
			return
		}
		firstResponseExit, err := strconv.ParseBool(fields[7])
		if err != nil {
			log.Printf("Invalid first-response-exit flag in metric line %q: %v", line, err)
			return
		}
		observeCompletedSession(
			server,
			float64(durationMs),
			uint32(interactionDepth),
			fields[6],
			firstResponseExit,
			metrics,
		)
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

		metrics.upnpOtherHttpRequests.WithLabelValues(method, url).Inc()
		observeProtocolAction(server, "upnp_http_request", metrics)
	case "M-SEARCH":
		if len(fields) < 3 {
			log.Printf("Malformed M-SEARCH metric (need 3 fields): %q", line)
			return
		}
		ip := fields[2]
		metrics.upnpMSearchRequests.WithLabelValues(ip).Inc()
		observeProtocolAction(server, "upnp_discovery", metrics)
	case "non-M-SEARCH":
		if len(fields) < 3 {
			log.Printf("Malformed non-M-SEARCH metric (need 3 fields): %q", line)
			return
		}
		ip := fields[2]
		metrics.upnpNonMSearchRequests.WithLabelValues(ip).Inc()
		observeProtocolAction(server, "upnp_discovery", metrics)
	// MQTT
	case "CONNECT":
		if len(fields) < 3 {
			log.Printf("Malformed MQTT CONNECT metric (need 3 fields): %q", line)
			return
		}
		version := fields[2]
		metrics.mqttConnectVersions.WithLabelValues(version).Inc()
		observeProtocolAction(server, "mqtt_connect", metrics)

	case "malformedConnect":
		metrics.mqttMalformedConnect.Inc()
		observeProtocolAction(server, "malformed_connect", metrics)

	case "SUBSCRIBE":
		if len(fields) < 4 {
			log.Printf("Malformed SUBSCRIBE metric (need 4 fields): %q", line)
			return
		}
		topic := fields[2]
		qos := fields[3]
		metrics.mqttSubscribeTopics.WithLabelValues(topic, qos).Inc()
		observeProtocolAction(server, "mqtt_subscribe", metrics)

	case "credentials":
		username := " "
		password := " "
		if len(fields) >= 3 {
			username = fields[2]
		}
		if len(fields) >= 4 {
			password = fields[3]
		}

		metrics.mqttCredentials.WithLabelValues(username, password).Inc()

	case "PUBLISH":
		if len(fields) < 4 {
			log.Printf("Malformed PUBLISH metric (need 4 fields): %q", line)
			return
		}
		topic := fields[2]
		qos := fields[3]
		metrics.mqttPublishTopics.WithLabelValues(topic, qos).Inc()
		observeProtocolAction(server, "mqtt_publish", metrics)

	case "CONNACK":
		metrics.mqttConacks.Inc()
		observeProtocolAction(server, "mqtt_connack", metrics)
	case "UNSUBSCRIBE":
		metrics.mqttUnsubscribe.Inc()
		observeProtocolAction(server, "mqtt_unsubscribe", metrics)
	case "PUBREC":
		metrics.mqttPubrec.Inc()
		observeProtocolAction(server, "mqtt_pubrec", metrics)
	case "action":
		if len(fields) < 4 {
			return
		}
		ip := fields[2]
		metrics.telnetInput.WithLabelValues(ip).Inc()
		observeProtocolAction(server, "read", metrics)
	case "protocol_action":
		if len(fields) != 3 {
			log.Printf("Malformed protocol action metric: %q", line)
			return
		}
		observeProtocolAction(server, fields[2], metrics)
	}
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

func boundedDisconnectReason(reason string) string {
	switch reason {
	case "client_disconnect", "inactivity", "read_error", "write_error":
		return reason
	default:
		return "unknown"
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

	metrics.completedSessions.WithLabelValues(protocol, boundedDisconnectReason(disconnectReason)).Inc()
	metrics.sessionDuration.WithLabelValues(protocol).Observe(durationMs)
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
	ip := netip.MustParseAddr(ipStr)

	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	err := db.Lookup(ip).Decode(&record)
	if err != nil {
		log.Panic(err)
	}
	fmt.Print(record.Country.ISOCode)

	return record.Country.ISOCode
}
