package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type mqttJSONProducerFixture struct {
	registry *prometheus.Registry
	port     int
	producer *exec.Cmd
	output   *bytes.Buffer
}

func startMQTTJSONProducerFixture(t *testing.T) *mqttJSONProducerFixture {
	t.Helper()
	testDirectory := t.TempDir()
	binaryPath := filepath.Join(testDirectory, "mqtt_pit_json_mvp")
	repositoryRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}

	compile := exec.Command(
		"gcc",
		"-Wall", "-Wextra", "-g", "-pthread",
		"-DEVENTHORIZON_JSON_METRIC_EVENTS",
		"-o", binaryPath,
		filepath.Join(repositoryRoot, "servers/mqtt_pit.c"),
		filepath.Join(repositoryRoot, "shared/structs.c"),
		filepath.Join(repositoryRoot, "shared/session_events.c"),
		filepath.Join(repositoryRoot, "shared/interaction_depth.c"),
		filepath.Join(repositoryRoot, "shared/metric_events.c"),
	)
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("compile isolated JSON MQTT producer: %v\n%s", err, output)
	}

	registry := prometheus.NewRegistry()
	metricState := newMetricEventMetrics(registry)
	metricSocketPath := filepath.Join(testDirectory, "metrics.sock")
	metricServer, err := startMetricEventServer(metricSocketPath, metricState)
	if err != nil {
		t.Fatalf("start metric event server: %v", err)
	}
	t.Cleanup(func() { _ = metricServer.Close() })

	port := reserveTCPPort(t)
	producerOutput := &bytes.Buffer{}
	producer := exec.Command(
		binaryPath,
		strconv.Itoa(port),
		"64",
		"20",
		"60000",
		"16",
		"64",
	)
	producer.Env = append(
		os.Environ(),
		"EVENTHORIZON_METRIC_SOCKET="+metricSocketPath,
		"EVENTHORIZON_SESSION_LOG="+filepath.Join(testDirectory, "sessions.jsonl"),
	)
	producer.Stdout = producerOutput
	producer.Stderr = producerOutput
	if err := producer.Start(); err != nil {
		t.Fatalf("start isolated JSON MQTT producer: %v", err)
	}
	t.Cleanup(func() {
		if producer.ProcessState == nil {
			_ = producer.Process.Kill()
			_ = producer.Wait()
		}
	})

	return &mqttJSONProducerFixture{
		registry: registry,
		port:     port,
		producer: producer,
		output:   producerOutput,
	}
}

func (fixture *mqttJSONProducerFixture) connect(t *testing.T) *net.TCPConn {
	t.Helper()
	connection, err := dialTCPEventually(fixture.port, 2*time.Second)
	if err != nil {
		_ = fixture.producer.Process.Kill()
		_ = fixture.producer.Wait()
		t.Fatalf("connect to isolated JSON MQTT producer: %v\n%s", err, fixture.output.String())
	}
	return connection
}

func TestMQTTJSONProducerFinalizesCleanEOFBeforeCONNECT(t *testing.T) {
	fixture := startMQTTJSONProducerFixture(t)
	connection := fixture.connect(t)
	t.Cleanup(func() { _ = connection.Close() })
	assertGatheredValueEventually(t, fixture.registry, "current_connected_clients", map[string]string{
		"server": "MQTT",
	}, 1)

	if err := connection.CloseWrite(); err != nil {
		t.Fatalf("close MQTT client write side: %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set MQTT read deadline: %v", err)
	}
	wireBytes, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("read MQTT EOF response: %v", err)
	}
	if len(wireBytes) != 0 {
		t.Fatalf("MQTT bytes before pre-CONNECT EOF finalization = %d, want 0", len(wireBytes))
	}

	assertGatheredValueEventually(t, fixture.registry, "total_connects", map[string]string{
		"server": "MQTT",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "current_connected_clients", map[string]string{
		"server": "MQTT",
	}, 0)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_finalizations_total", map[string]string{
		"finalization_reason": "peer_closed",
	}, 1)
	assertGatheredHistogramCountEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_duration_ms", nil, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_interaction_depth_total", map[string]string{
		"depth_level": "0",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_bytes_received_total", map[string]string{
		"protocol": "mqtt",
	}, 0)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_bytes_sent_total", map[string]string{
		"protocol": "mqtt",
	}, 0)
	assertGatheredHistogramCountEventually(t, fixture.registry, "eventhorizon_mqtt_connect_to_connack_duration_ms", nil, 0)
}

func TestMQTTJSONProducerExportsCONNECTCONNACKAndDISCONNECT(t *testing.T) {
	fixture := startMQTTJSONProducerFixture(t)
	connection := fixture.connect(t)
	t.Cleanup(func() { _ = connection.Close() })

	connectPacket := []byte{
		0x10, 0x10,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x04, 0x02, 0x00, 0x0a,
		0x00, 0x04, 'g', 's', 'o', 'c',
	}
	if written, err := connection.Write(connectPacket); err != nil {
		t.Fatalf("write MQTT 3.1.1 CONNECT: %v", err)
	} else if written != len(connectPacket) {
		t.Fatalf("CONNECT bytes = %d, want %d", written, len(connectPacket))
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set MQTT CONNACK deadline: %v", err)
	}
	connack := make([]byte, 4)
	if _, err := io.ReadFull(connection, connack); err != nil {
		t.Fatalf("read MQTT 3.1.1 CONNACK: %v", err)
	}
	wantConnack := []byte{0x20, 0x02, 0x00, 0x00}
	if !bytes.Equal(connack, wantConnack) {
		t.Fatalf("CONNACK = %x, want %x", connack, wantConnack)
	}

	disconnectPacket := []byte{0xe0, 0x00}
	if written, err := connection.Write(disconnectPacket); err != nil {
		t.Fatalf("write MQTT DISCONNECT: %v", err)
	} else if written != len(disconnectPacket) {
		t.Fatalf("DISCONNECT bytes = %d, want %d", written, len(disconnectPacket))
	}
	remainingWireBytes, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("read MQTT connection finalization: %v", err)
	}
	if len(remainingWireBytes) != 0 {
		t.Fatalf("unexpected MQTT bytes after CONNACK = %x", remainingWireBytes)
	}

	assertGatheredValueEventually(t, fixture.registry, "total_connects", map[string]string{
		"server": "MQTT",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "current_connected_clients", map[string]string{
		"server": "MQTT",
	}, 0)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_bytes_received_total", map[string]string{
		"protocol": "mqtt",
	}, float64(len(connectPacket)+len(disconnectPacket)))
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_bytes_sent_total", map[string]string{
		"protocol": "mqtt",
	}, float64(len(wantConnack)))
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_protocol_actions_total", map[string]string{
		"protocol": "mqtt",
		"action":   "connect_accepted",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_protocol_actions_total", map[string]string{
		"protocol": "mqtt",
		"action":   "connack_sent",
	}, 1)
	assertGatheredHistogramCountEventually(t, fixture.registry, "eventhorizon_mqtt_connect_to_connack_duration_ms", nil, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_finalizations_total", map[string]string{
		"finalization_reason": "disconnect_received",
	}, 1)
	assertGatheredHistogramCountEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_duration_ms", nil, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_interaction_depth_total", map[string]string{
		"depth_level": "1",
	}, 1)
	for _, reason := range malformedReasons {
		assertGatheredValueEventually(t, fixture.registry, "eventhorizon_exporter_malformed_messages_total", map[string]string{
			"reason": string(reason),
		}, 0)
	}
}

func TestMQTTJSONProducerRefusesStructurallyValidMQTT5CONNECT(t *testing.T) {
	fixture := startMQTTJSONProducerFixture(t)
	connection := fixture.connect(t)
	t.Cleanup(func() { _ = connection.Close() })

	connectPacket := []byte{
		0x10, 0x11,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x05, 0x02, 0x00, 0x0a,
		0x00,
		0x00, 0x04, 'g', 's', 'o', 'c',
	}
	if written, err := connection.Write(connectPacket); err != nil {
		t.Fatalf("write structurally valid MQTT 5.0 CONNECT: %v", err)
	} else if written != len(connectPacket) {
		t.Fatalf("MQTT 5.0 CONNECT bytes = %d, want %d", written, len(connectPacket))
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set MQTT 5.0 refusal deadline: %v", err)
	}
	wireBytes, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("read MQTT 5.0 refusal: %v", err)
	}
	wantRefusal := []byte{0x20, 0x03, 0x00, 0x84, 0x00}
	if !bytes.Equal(wireBytes, wantRefusal) {
		t.Fatalf("MQTT 5.0 refusal = %x, want %x", wireBytes, wantRefusal)
	}

	assertGatheredValueEventually(t, fixture.registry, "total_connects", map[string]string{
		"server": "MQTT",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "current_connected_clients", map[string]string{
		"server": "MQTT",
	}, 0)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_bytes_received_total", map[string]string{
		"protocol": "mqtt",
	}, float64(len(connectPacket)))
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_bytes_sent_total", map[string]string{
		"protocol": "mqtt",
	}, float64(len(wantRefusal)))
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_finalizations_total", map[string]string{
		"finalization_reason": "connect_refused",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_interaction_depth_total", map[string]string{
		"depth_level": "0",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_protocol_actions_total", map[string]string{
		"protocol": "mqtt",
		"action":   "connect_accepted",
	}, 0)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_protocol_actions_total", map[string]string{
		"protocol": "mqtt",
		"action":   "connack_sent",
	}, 0)
	assertGatheredHistogramCountEventually(t, fixture.registry, "eventhorizon_mqtt_connect_to_connack_duration_ms", nil, 0)
}

func TestMQTTJSONProducerRejectsInconsistentProtocolNameAndLevel(t *testing.T) {
	fixture := startMQTTJSONProducerFixture(t)
	connection := fixture.connect(t)
	t.Cleanup(func() { _ = connection.Close() })

	connectPacket := []byte{
		0x10, 0x10,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x03, 0x02, 0x00, 0x0a,
		0x00, 0x04, 'g', 's', 'o', 'c',
	}
	if written, err := connection.Write(connectPacket); err != nil {
		t.Fatalf("write inconsistent MQTT CONNECT: %v", err)
	} else if written != len(connectPacket) {
		t.Fatalf("inconsistent CONNECT bytes = %d, want %d", written, len(connectPacket))
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set inconsistent CONNECT refusal deadline: %v", err)
	}
	wireBytes, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("read inconsistent CONNECT refusal: %v", err)
	}
	wantRefusal := []byte{0x20, 0x02, 0x00, 0x01}
	if !bytes.Equal(wireBytes, wantRefusal) {
		t.Fatalf("inconsistent CONNECT refusal = %x, want %x", wireBytes, wantRefusal)
	}

	assertGatheredValueEventually(t, fixture.registry, "current_connected_clients", map[string]string{
		"server": "MQTT",
	}, 0)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_finalizations_total", map[string]string{
		"finalization_reason": "protocol_error",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_interaction_depth_total", map[string]string{
		"depth_level": "0",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_protocol_actions_total", map[string]string{
		"protocol": "mqtt",
		"action":   "connect_accepted",
	}, 0)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_protocol_actions_total", map[string]string{
		"protocol": "mqtt",
		"action":   "connack_sent",
	}, 0)
	assertGatheredHistogramCountEventually(t, fixture.registry, "eventhorizon_mqtt_connect_to_connack_duration_ms", nil, 0)
}

func TestMQTTJSONProducerCountsAcceptedQoS0PUBLISHAsOneOperation(t *testing.T) {
	fixture := startMQTTJSONProducerFixture(t)
	connection := fixture.connect(t)
	t.Cleanup(func() { _ = connection.Close() })

	connectPacket := []byte{
		0x10, 0x10,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x04, 0x02, 0x00, 0x0a,
		0x00, 0x04, 'g', 's', 'o', 'c',
	}
	if _, err := connection.Write(connectPacket); err != nil {
		t.Fatalf("write MQTT CONNECT: %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set MQTT CONNACK deadline: %v", err)
	}
	connack := make([]byte, 4)
	if _, err := io.ReadFull(connection, connack); err != nil {
		t.Fatalf("read MQTT CONNACK: %v", err)
	}
	wantConnack := []byte{0x20, 0x02, 0x00, 0x00}
	if !bytes.Equal(connack, wantConnack) {
		t.Fatalf("CONNACK = %x, want %x", connack, wantConnack)
	}

	publishPacket := []byte{0x30, 0x04, 0x00, 0x01, 'a', 'x'}
	disconnectPacket := []byte{0xe0, 0x00}
	operationBytes := append(append([]byte{}, publishPacket...), disconnectPacket...)
	if written, err := connection.Write(operationBytes); err != nil {
		t.Fatalf("write QoS 0 PUBLISH and DISCONNECT: %v", err)
	} else if written != len(operationBytes) {
		t.Fatalf("operation bytes = %d, want %d", written, len(operationBytes))
	}
	remainingWireBytes, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("read MQTT operation finalization: %v", err)
	}
	if len(remainingWireBytes) != 0 {
		t.Fatalf("unexpected response to QoS 0 PUBLISH = %x", remainingWireBytes)
	}

	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_protocol_actions_total", map[string]string{
		"protocol": "mqtt",
		"action":   "publish_received",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_finalizations_total", map[string]string{
		"finalization_reason": "disconnect_received",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_interaction_depth_total", map[string]string{
		"depth_level": "2",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_bytes_received_total", map[string]string{
		"protocol": "mqtt",
	}, float64(len(connectPacket)+len(operationBytes)))
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_bytes_sent_total", map[string]string{
		"protocol": "mqtt",
	}, float64(len(wantConnack)))
}

func TestMQTTJSONProducerFinalizesActiveConnectionOnShutdown(t *testing.T) {
	fixture := startMQTTJSONProducerFixture(t)
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- fixture.producer.Wait()
		close(waitDone)
	}()

	connection := fixture.connect(t)
	t.Cleanup(func() { _ = connection.Close() })
	assertGatheredValueEventually(t, fixture.registry, "current_connected_clients", map[string]string{
		"server": "MQTT",
	}, 1)

	if err := fixture.producer.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal isolated JSON MQTT producer: %v", err)
	}
	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatalf("isolated JSON MQTT producer shutdown: %v\n%s", err, fixture.output.String())
		}
	case <-time.After(2 * time.Second):
		_ = fixture.producer.Process.Kill()
		<-waitDone
		t.Fatal("isolated JSON MQTT producer did not stop after SIGTERM")
	}

	assertGatheredValueEventually(t, fixture.registry, "current_connected_clients", map[string]string{
		"server": "MQTT",
	}, 0)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_finalizations_total", map[string]string{
		"finalization_reason": "server_shutdown",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_interaction_depth_total", map[string]string{
		"depth_level": "0",
	}, 1)
	assertGatheredHistogramCountEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_duration_ms", nil, 1)
}

func TestMQTTJSONProducerFinalizesResetAsPrimaryReadError(t *testing.T) {
	fixture := startMQTTJSONProducerFixture(t)
	connection := fixture.connect(t)
	assertGatheredValueEventually(t, fixture.registry, "current_connected_clients", map[string]string{
		"server": "MQTT",
	}, 1)
	if err := connection.SetLinger(0); err != nil {
		_ = connection.Close()
		t.Fatalf("configure MQTT reset-on-close: %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("reset MQTT client connection: %v", err)
	}

	assertGatheredValueEventually(t, fixture.registry, "current_connected_clients", map[string]string{
		"server": "MQTT",
	}, 0)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_finalizations_total", map[string]string{
		"finalization_reason": "read_error",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_read_errors_total", map[string]string{
		"protocol": "mqtt",
		"reason":   "reset",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_interaction_depth_total", map[string]string{
		"depth_level": "0",
	}, 1)
	assertGatheredHistogramCountEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_duration_ms", nil, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_bytes_received_total", map[string]string{
		"protocol": "mqtt",
	}, 0)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_bytes_sent_total", map[string]string{
		"protocol": "mqtt",
	}, 0)
}

func TestMQTTJSONProducerRejectsOperationBeforeCONNECT(t *testing.T) {
	fixture := startMQTTJSONProducerFixture(t)
	connection := fixture.connect(t)
	t.Cleanup(func() { _ = connection.Close() })

	publishPacket := []byte{0x30, 0x04, 0x00, 0x01, 'a', 'x'}
	if written, err := connection.Write(publishPacket); err != nil {
		t.Fatalf("write pre-CONNECT PUBLISH: %v", err)
	} else if written != len(publishPacket) {
		t.Fatalf("pre-CONNECT PUBLISH bytes = %d, want %d", written, len(publishPacket))
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set pre-CONNECT finalization deadline: %v", err)
	}
	wireBytes, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("read pre-CONNECT finalization: %v", err)
	}
	if len(wireBytes) != 0 {
		t.Fatalf("response to pre-CONNECT PUBLISH = %x, want none", wireBytes)
	}

	assertGatheredValueEventually(t, fixture.registry, "current_connected_clients", map[string]string{
		"server": "MQTT",
	}, 0)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_finalizations_total", map[string]string{
		"finalization_reason": "protocol_error",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_interaction_depth_total", map[string]string{
		"depth_level": "0",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_protocol_actions_total", map[string]string{
		"protocol": "mqtt",
		"action":   "publish_received",
	}, 0)
}

func TestMQTTJSONProducerRejectsPINGREQBeforeCONNECT(t *testing.T) {
	fixture := startMQTTJSONProducerFixture(t)
	connection := fixture.connect(t)
	t.Cleanup(func() { _ = connection.Close() })

	pingPacket := []byte{0xc0, 0x00}
	if written, err := connection.Write(pingPacket); err != nil {
		t.Fatalf("write pre-CONNECT PINGREQ: %v", err)
	} else if written != len(pingPacket) {
		t.Fatalf("pre-CONNECT PINGREQ bytes = %d, want %d", written, len(pingPacket))
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set pre-CONNECT PINGREQ finalization deadline: %v", err)
	}
	wireBytes, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("read pre-CONNECT PINGREQ finalization: %v", err)
	}
	if len(wireBytes) != 0 {
		t.Fatalf("response to pre-CONNECT PINGREQ = %x, want none", wireBytes)
	}

	assertGatheredValueEventually(t, fixture.registry, "current_connected_clients", map[string]string{
		"server": "MQTT",
	}, 0)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_finalizations_total", map[string]string{
		"finalization_reason": "protocol_error",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_interaction_depth_total", map[string]string{
		"depth_level": "0",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_bytes_sent_total", map[string]string{
		"protocol": "mqtt",
	}, 0)
}

func TestMQTTJSONProducerRespondsToValidPINGREQWithoutDepthOrAction(t *testing.T) {
	fixture := startMQTTJSONProducerFixture(t)
	connection := fixture.connect(t)
	t.Cleanup(func() { _ = connection.Close() })

	connectPacket := []byte{
		0x10, 0x10,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x04, 0x02, 0x00, 0x0a,
		0x00, 0x04, 'g', 's', 'o', 'c',
	}
	if _, err := connection.Write(connectPacket); err != nil {
		t.Fatalf("write MQTT CONNECT: %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set MQTT response deadline: %v", err)
	}
	connack := make([]byte, 4)
	if _, err := io.ReadFull(connection, connack); err != nil {
		t.Fatalf("read MQTT CONNACK: %v", err)
	}

	pingPacket := []byte{0xc0, 0x00}
	if _, err := connection.Write(pingPacket); err != nil {
		t.Fatalf("write MQTT PINGREQ: %v", err)
	}
	pingResponse := make([]byte, 2)
	if _, err := io.ReadFull(connection, pingResponse); err != nil {
		t.Fatalf("read MQTT PINGRESP: %v", err)
	}
	wantPingResponse := []byte{0xd0, 0x00}
	if !bytes.Equal(pingResponse, wantPingResponse) {
		t.Fatalf("PINGRESP = %x, want %x", pingResponse, wantPingResponse)
	}

	disconnectPacket := []byte{0xe0, 0x00}
	if _, err := connection.Write(disconnectPacket); err != nil {
		t.Fatalf("write MQTT DISCONNECT: %v", err)
	}
	if _, err := io.ReadAll(connection); err != nil {
		t.Fatalf("read MQTT PING fixture finalization: %v", err)
	}

	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_bytes_received_total", map[string]string{
		"protocol": "mqtt",
	}, float64(len(connectPacket)+len(pingPacket)+len(disconnectPacket)))
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_bytes_sent_total", map[string]string{
		"protocol": "mqtt",
	}, float64(len(connack)+len(pingResponse)))
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_interaction_depth_total", map[string]string{
		"depth_level": "1",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_finalizations_total", map[string]string{
		"finalization_reason": "disconnect_received",
	}, 1)
}

func TestMQTTJSONProducerExpiresAcceptedKeepAliveAtOneAndAHalfIntervals(t *testing.T) {
	fixture := startMQTTJSONProducerFixture(t)
	connection := fixture.connect(t)
	t.Cleanup(func() { _ = connection.Close() })

	connectPacket := []byte{
		0x10, 0x10,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x04, 0x02, 0x00, 0x01,
		0x00, 0x04, 'g', 's', 'o', 'c',
	}
	if _, err := connection.Write(connectPacket); err != nil {
		t.Fatalf("write one-second Keep Alive CONNECT: %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set Keep Alive wire deadline: %v", err)
	}
	connack := make([]byte, 4)
	if _, err := io.ReadFull(connection, connack); err != nil {
		t.Fatalf("read Keep Alive CONNACK: %v", err)
	}
	startedWaiting := time.Now()
	remainingWireBytes, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("wait for Keep Alive finalization: %v", err)
	}
	if len(remainingWireBytes) != 0 {
		t.Fatalf("maintenance bytes before Keep Alive finalization = %x, want none", remainingWireBytes)
	}
	if elapsed := time.Since(startedWaiting); elapsed < 1400*time.Millisecond {
		t.Fatalf("Keep Alive finalization observed after %s, want no earlier than 1.4s test tolerance", elapsed)
	}

	assertGatheredValueEventually(t, fixture.registry, "current_connected_clients", map[string]string{
		"server": "MQTT",
	}, 0)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_finalizations_total", map[string]string{
		"finalization_reason": "keep_alive_timeout",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_interaction_depth_total", map[string]string{
		"depth_level": "1",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_protocol_actions_total", map[string]string{
		"protocol": "mqtt",
		"action":   "connect_accepted",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_protocol_actions_total", map[string]string{
		"protocol": "mqtt",
		"action":   "connack_sent",
	}, 1)
}

func TestMQTTJSONProducerRefusesStructurallyValidWillCONNECT(t *testing.T) {
	fixture := startMQTTJSONProducerFixture(t)
	connection := fixture.connect(t)
	t.Cleanup(func() { _ = connection.Close() })

	connectPacket := []byte{
		0x10, 0x16,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x04, 0x06, 0x00, 0x0a,
		0x00, 0x04, 'g', 's', 'o', 'c',
		0x00, 0x01, 'w',
		0x00, 0x01, 'x',
	}
	if _, err := connection.Write(connectPacket); err != nil {
		t.Fatalf("write supported-version Will CONNECT: %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set Will CONNECT refusal deadline: %v", err)
	}
	wireBytes, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("read Will CONNECT refusal: %v", err)
	}
	wantRefusal := []byte{0x20, 0x02, 0x00, 0x03}
	if !bytes.Equal(wireBytes, wantRefusal) {
		t.Fatalf("Will CONNECT refusal = %x, want %x", wireBytes, wantRefusal)
	}

	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_finalizations_total", map[string]string{
		"finalization_reason": "connect_refused",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_interaction_depth_total", map[string]string{
		"depth_level": "0",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_protocol_actions_total", map[string]string{
		"protocol": "mqtt",
		"action":   "connect_accepted",
	}, 0)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_protocol_actions_total", map[string]string{
		"protocol": "mqtt",
		"action":   "connack_sent",
	}, 0)
	assertGatheredHistogramCountEventually(t, fixture.registry, "eventhorizon_mqtt_connect_to_connack_duration_ms", nil, 0)
}

func TestMQTTJSONProducerRejectsSecondCONNECTWithoutDoubleCounting(t *testing.T) {
	fixture := startMQTTJSONProducerFixture(t)
	connection := fixture.connect(t)
	t.Cleanup(func() { _ = connection.Close() })

	connectPacket := []byte{
		0x10, 0x10,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x04, 0x02, 0x00, 0x0a,
		0x00, 0x04, 'g', 's', 'o', 'c',
	}
	if _, err := connection.Write(connectPacket); err != nil {
		t.Fatalf("write first MQTT CONNECT: %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set repeated CONNECT deadline: %v", err)
	}
	connack := make([]byte, 4)
	if _, err := io.ReadFull(connection, connack); err != nil {
		t.Fatalf("read first MQTT CONNACK: %v", err)
	}
	if _, err := connection.Write(connectPacket); err != nil {
		t.Fatalf("write second MQTT CONNECT: %v", err)
	}
	remainingWireBytes, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("read repeated CONNECT finalization: %v", err)
	}
	if len(remainingWireBytes) != 0 {
		t.Fatalf("response to second MQTT CONNECT = %x, want none", remainingWireBytes)
	}

	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_protocol_actions_total", map[string]string{
		"protocol": "mqtt",
		"action":   "connect_accepted",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_protocol_actions_total", map[string]string{
		"protocol": "mqtt",
		"action":   "connack_sent",
	}, 1)
	assertGatheredHistogramCountEventually(t, fixture.registry, "eventhorizon_mqtt_connect_to_connack_duration_ms", nil, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_finalizations_total", map[string]string{
		"finalization_reason": "protocol_error",
	}, 1)
	assertGatheredValueEventually(t, fixture.registry, "eventhorizon_mqtt_network_connection_interaction_depth_total", map[string]string{
		"depth_level": "1",
	}, 1)
}
