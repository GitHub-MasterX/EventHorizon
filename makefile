CC = gcc
CFLAGS = -Wall -Wextra -g -pthread

STRUCTS = shared/structs.c shared/session_events.c shared/interaction_depth.c

TELNET_TARGET = bin/telnet_pit
UPNP_TARGET = bin/upnp_pit
MQTT_TARGET = bin/mqtt_pit
COAP_TARGET = bin/coap_pit
BYTE_METRIC_TEST_TARGET = bin/byte_metric_test
INTERACTION_DEPTH_TEST_TARGET = bin/interaction_depth_test

TELNET_SRC = servers/telnet_pit.c
UPNP_SRC = servers/upnp_pit.c
MQTT_SRC = servers/mqtt_pit.c
COAP_SRC = servers/coap_pit.c

GO_DIR = prometheus
GO_TARGET = bin/prometheus_exporter
GO_SRCS := $(wildcard prometheus/*.go)

BIN_DIR = bin

# Default Rule
all: $(TELNET_TARGET) $(UPNP_TARGET) $(MQTT_TARGET) $(COAP_TARGET) $(GO_TARGET)

$(TELNET_TARGET): $(TELNET_SRC) $(STRUCTS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ 

$(UPNP_TARGET): $(UPNP_SRC) $(STRUCTS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ 

$(MQTT_TARGET): $(MQTT_SRC) $(STRUCTS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ 

$(COAP_TARGET): $(COAP_SRC) $(STRUCTS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ 

$(BYTE_METRIC_TEST_TARGET): tests/byte_metric_test.c $(STRUCTS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(INTERACTION_DEPTH_TEST_TARGET): tests/interaction_depth_test.c shared/interaction_depth.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(GO_TARGET): $(GO_SRCS) | $(BIN_DIR)
	cd $(GO_DIR) && go build -o ../$(GO_TARGET)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Aliases
telnet_pit: $(TELNET_TARGET)
upnp_pit:   $(UPNP_TARGET)
mqtt_pit:   $(MQTT_TARGET)
coap_pit:	$(COAP_TARGET)
prometheus: $(GO_TARGET)
test-byte-metrics: $(BYTE_METRIC_TEST_TARGET)
	./$(BYTE_METRIC_TEST_TARGET)
test-interaction-depth: $(INTERACTION_DEPTH_TEST_TARGET)
	./$(INTERACTION_DEPTH_TEST_TARGET)
test-deployment-controller:
	python3 -m unittest tests/test_deployment_controller.py -v
test: test-byte-metrics test-interaction-depth test-deployment-controller

PROTOCOL ?= telnet
SESSIONS ?= 100
CONCURRENCY ?= 5

validation-exact:
	./scripts/run_controlled_validation.sh --protocol telnet --profile exact --scenario matrix --sessions 40 --concurrency 2
	./scripts/run_controlled_validation.sh --protocol mqtt --profile exact --scenario matrix --sessions 40 --concurrency 2

validation-load:
	./scripts/run_controlled_validation.sh --protocol $(PROTOCOL) --profile load --sessions $(SESSIONS) --concurrency $(CONCURRENCY)

clean:
	rm -f $(TELNET_TARGET) $(UPNP_TARGET) $(MQTT_TARGET) $(GO_TARGET) $(BYTE_METRIC_TEST_TARGET) $(INTERACTION_DEPTH_TEST_TARGET)

.PHONY: all clean test test-byte-metrics test-interaction-depth test-deployment-controller validation-exact validation-load
