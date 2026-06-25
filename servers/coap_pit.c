#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/time.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include "../shared/structs.h"

#define CLASS_REQUEST 0x0
#define DETAIL_GET 0x1
#define DETAIL_POST 0x2
#define DETAIL_PUT 0x3
#define DETAIL_DELETE 0x4
#define TYPE_CONFIRMABLE 0x0
#define TYPE_NON_CONFIRMABLE 0x1
#define TYPE_ACK 0x2
#define TYPE_RST 0x3
#define MAX_BUF_LEN 1024
#define SERVER_ID "CoAP"

struct coapClient *clients = NULL;

int port = 5683;
int timeout = -1;
int delay = 1000;
int ACK_TIMEOUT = 2000;
int MAX_RETRANSMIT = 4;
int maxNoClients = 4096;
int sockFd;
static unsigned long coapEventCounter = 0;

static void makeCoapEventId(char *buffer, size_t len, long long eventMs) {
    coapEventCounter += 1;
    session_events_make_request_id(buffer, len, "coap", coapEventCounter, eventMs);
}

static const char *coapTypeName(uint8_t type) {
    switch (type) {
        case TYPE_CONFIRMABLE:
            return "confirmable";
        case TYPE_NON_CONFIRMABLE:
            return "non_confirmable";
        case TYPE_ACK:
            return "ack";
        case TYPE_RST:
            return "reset";
        default:
            return "unknown";
    }
}

static const char *coapMethodName(uint8_t class, uint8_t detail) {
    if (class != CLASS_REQUEST) {
        return "non_request";
    }

    switch (detail) {
        case DETAIL_GET:
            return "GET";
        case DETAIL_POST:
            return "POST";
        case DETAIL_PUT:
            return "PUT";
        case DETAIL_DELETE:
            return "DELETE";
        default:
            return "unknown";
    }
}

static void emitCoapAction(const char *eventId, const char *action, const char *fields) {
    session_events_write_action("coap", eventId, action, fields);
}

static void emitCoapSendEvent(const char *eventId, const char *responseKind,
                              int bytesSent, long long handlingDurationMs,
                              unsigned int interactionDepth) {
    char fields[256];
    snprintf(fields, sizeof(fields),
        "\"transport\":\"udp\",\"response_kind\":\"%s\",\"bytes_sent\":%d,\"write_result\":\"%s\",\"handling_duration_ms\":%lld,\"interaction_depth\":%u",
        responseKind,
        bytesSent > 0 ? bytesSent : 0,
        bytesSent >= 0 ? "success" : "write_error",
        handlingDurationMs < 0 ? 0 : handlingDurationMs,
        interactionDepth);
    emitCoapAction(eventId, "response_sent", fields);
}

void addClient(struct coapClient *client) {
    HASH_ADD(hh, clients, clientAddr, sizeof(struct sockaddr_in), client);
}

void deleteClient(struct coapClient *client) {
    HASH_DEL(clients, client);
    free(client);
}

struct coapClient *findExistingClient(struct sockaddr_in *addr) {
    struct coapClient *result = NULL;
    HASH_FIND(hh, clients, addr, sizeof(struct sockaddr_in), result);
    return result;
}

int sendCoapBlockResponse(uint16_t messageId, uint8_t* token, uint8_t tkl, uint32_t* blockNumber, struct sockaddr_in* addr, socklen_t addrLen) {
    if(*blockNumber > 0xFFFFF) {
        *blockNumber = 0;
    }
    // Block2 Option (delta = 23, length = 1)
    // NUM(20 bits) | (M=1) | SZX=2(64 bytes)
    uint32_t block_opt_value = (*blockNumber << 4) | (0b1 << 3) | 0x02;
    uint8_t block_len = (block_opt_value <= 0xFF) ? 1 :
                        (block_opt_value <= 0xFFFF) ? 2 : 3;
    
    int payloadLength = 5;
    int responseLength = 4           // base CoAP header
                   + tkl             // token length
                   + 1               // option delta+length byte
                   + 1               // extended delta byte
                   + block_len       // block2 value (1–3 bytes)
                   + 1               // payload marker
                   + payloadLength;  // actual payload
    char response[responseLength];
    
    // Version (1) | Type (CON) | TKL
    response[0] = (0b01 << 6) | (0b0 << 4) | (tkl & 0b1111);;
    // class (2) | detail (5). Content response
    response[1] = (0b010 << 5) | (0b101);
    response[2] = (messageId >> 8) & 0xFF;
    response[3] = messageId & 0xFF;

    int index = 4;

    // Token
    for (int i = 0; i < tkl; i++) {
        response[index++] = token[i];
    }

    // Option Delta 13 | block length
    response[index++] = (0b1101 << 4) | block_len;
    response[index++] = 23 - 13;  // Block2 option (rfc7959 sect. 6)
    if (block_len == 1) {
        response[index++] = block_opt_value & 0xFF;
    } else if (block_len == 2) {
        response[index++] = (block_opt_value >> 8) & 0xFF;
        response[index++] = block_opt_value & 0xFF;
    } else {
        response[index++] = (block_opt_value >> 16) & 0xFF;
        response[index++] = (block_opt_value >> 8) & 0xFF;
        response[index++] = block_opt_value & 0xFF;
    }

    // Payload marker
    response[index++] = 0xFF;

    // Payload
    for (int i = 0; i < payloadLength; i++) {
        response[index++] = 'A';
    }

    return sendto(sockFd, response, index, 0, (struct sockaddr *)addr, addrLen);
}

int sendPing(uint16_t messageId, struct sockaddr_in* addr, socklen_t addrLen) {
    uint8_t ping[4];
    ping[0] = (1 << 6) | (0 << 4) | 0;      // Version=1, Type=CON, TKL=0
    ping[1] = 0x00;                         // Code = 0.00 (Empty)
    ping[2] = (messageId >> 8) & 0xFF;      // Message ID MSB
    ping[3] = messageId & 0xFF;             // Message ID LSB

    return sendto(sockFd, ping, sizeof(ping), 0, (struct sockaddr *)addr, addrLen);
}

int main(int argc, char* argv[]) {
    setbuf(stdout, NULL);

    // testing
    // char msg[256];
    // snprintf(msg, sizeof(msg), "%s connect %s\n",
    //     SERVER_ID, "17.117.247.220");
    // fprintf(stderr, "%s", msg);
    // sendMetric(msg);
    //     // testing
    // snprintf(msg, sizeof(msg), "%s connect %s\n",
    //     SERVER_ID, "74.17.158.179");
    // fprintf(stderr, "%s", msg);
    // sendMetric(msg);
    (void)argc;
    port = atoi(argv[1]);
    delay = atoi(argv[2]);
    ACK_TIMEOUT = atoi(argv[3]);
    MAX_RETRANSMIT = atoi(argv[4]);
    maxNoClients = atoi(argv[5]);
    struct sockaddr_in serverAddr;
    heap_init(&clientQueueCoap, maxNoClients);
    session_events_init(NULL);

    if ((sockFd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "SSDP Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind to all interfaces and ports
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    // Join the multicast group
    // struct ip_mreq mreq;
    // mreq.imr_multiaddr.s_addr = inet_addr("224.0.1.187");
    // mreq.imr_interface.s_addr = INADDR_ANY;
    // setsockopt(sockFd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    if (bind(sockFd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        fprintf(stderr, "Bind failed");
        close(sockFd);
        exit(EXIT_FAILURE);
    }

    printf("CoAP listener started on port %d\n", port);

    struct pollfd pollFd;
    memset(&pollFd, 0, sizeof(pollFd));
    pollFd.fd = sockFd;
    pollFd.events = POLLIN;

    while (1) {
        long long now = currentTimeMs();

        while (clientQueueCoap.size > 0) {
            if(clientQueueCoap.heapArray[0]->sendNext <= now){
                struct baseClient *bc = heap_pop(&clientQueueCoap);
                struct coapClient *c = (struct coapClient *)bc;
                
                // Handle retransmits
                if(!c->receivedAck || !c->receivedRst) {
                    if(c->retransmits < MAX_RETRANSMIT) {
                        c->base.sendNext = now + (ACK_TIMEOUT << (c->retransmits));
                        c->base.timeConnected += (ACK_TIMEOUT << (c->retransmits));
                        c->retransmits += 1;

                        if(!c->receivedAck) {
                            int out = sendCoapBlockResponse(c->messageId, c->token, c->tkl, &c->blockNumber, &c->clientAddr, c->addrLen);
                            c->interactionDepth += 1;
                            emitCoapSendEvent(c->sessionId, "block2_retransmit", out, 0, c->interactionDepth);
                        } else {
                            int out = sendPing(c->messageId, &c->clientAddr, c->addrLen);
                            c->interactionDepth += 1;
                            emitCoapSendEvent(c->sessionId, "ping_retransmit", out, 0, c->interactionDepth);
                        }

                        // printf("Token contents: ");
                        // for (int i = 0; i < 8; i++) {
                        //     printf("%u ", c->token[i]);
                        // }
                        // printf("\n");
                        // printf("Sent block2 due to not receiving an ACK with out=%d messageId=%u tkl=%d blockNumber=%d\n", out, c->messageId, c->tkl, c->blockNumber);
                        heap_insert(&clientQueueCoap, (struct baseClient *)c);
                        continue;
                    } else {
                        // Disconnect client
                        long long timeTrapped = c->base.timeConnected - (ACK_TIMEOUT * ((0b1 << MAX_RETRANSMIT) - 1));
                        char msg[256];
                        snprintf(msg, sizeof(msg), "%s disconnect %s %lld\n",
                            SERVER_ID, c->base.ipaddr, timeTrapped);
                        printf("%s", msg);
                        sendMetric(msg);
                        deleteClient(c);
                        continue;
                    }
                } 
                
                if (c->receivedGet) {
                    int out = sendCoapBlockResponse(c->messageId, c->token, c->tkl, &c->blockNumber, &c->clientAddr, c->addrLen);
                    c->interactionDepth += 1;
                    emitCoapSendEvent(c->sessionId, "block2", out, 0, c->interactionDepth);
                    c->blockNumber += 1;
                    c->receivedAck = false;
                } else if (c->receivedRst) {
                    int out = sendPing(c->messageId, &c->clientAddr, c->addrLen);
                    c->interactionDepth += 1;
                    emitCoapSendEvent(c->sessionId, "ping", out, 0, c->interactionDepth);
                    c->receivedRst = false;
                } 
                
                c->base.timeConnected += delay;
                c->messageId += 1;
                c->base.sendNext = now + delay;
                heap_insert(&clientQueueCoap, (struct baseClient *)c);
            } else {
                timeout = clientQueueCoap.heapArray[0]->sendNext - now;
                break;
            }
        }

        int pollResult = poll(&pollFd, 1, timeout);
        now = currentTimeMs();
        if (pollResult < 0) {
            fprintf(stderr, "Poll error with error %s", strerror(errno));
            continue;
        }

        if (pollFd.revents & POLLIN) {
            struct sockaddr_in clientAddr;
            socklen_t addrLen = sizeof(clientAddr);
            char buffer[1024];

            int len = recvfrom(sockFd, buffer, MAX_BUF_LEN, 0, (struct sockaddr *)&clientAddr, &addrLen);
            long long requestStartMs = currentTimeMs();
            if(len < 4) {
                // Too short or something went wrong
                if (len > 0) {
                    char eventId[SESSION_EVENT_ID_LEN];
                    char fields[256];
                    makeCoapEventId(eventId, sizeof(eventId), requestStartMs);
                    snprintf(fields, sizeof(fields),
                        "\"transport\":\"udp\",\"bytes_received\":%d,\"malformed_reason\":\"too_short\",\"handling_duration_ms\":0",
                        len);
                    emitCoapAction(eventId, "malformed_request", fields);
                }
                continue;
            }

            uint8_t version = (buffer[0] >> 6) & 0b11;
            uint8_t type = (buffer[0] >> 4) & 0b11;
            uint8_t code = buffer[1];
            uint8_t class = (code >> 5) & 0b111;
            uint8_t detail = code & 0b11111;
            uint8_t tkl = buffer[0] & 0b1111;
            uint16_t msgId = (buffer[2] << 8) | buffer[3];
            uint8_t token[8] = {0};

            printf("Incoming request from %s:%d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));

            // Header fields
            printf("Header:\n");
            printf("  Version : %u\n", version);
            printf("  Type    : %u\n", type);
            printf("  TKL     : %u\n", tkl);
            printf("  Code    : 0x%02X (Class: %u, Detail: %u)\n", code, class, detail);
            printf("  Msg ID  : %u\n", msgId);
            
            // Token (if any)
            printf("  Token   : ");
            for (int i = 0; i < tkl; i++) {
                printf("%02X ", buffer[4 + i]);
            }
            if (tkl == 0) {
                printf("(none)");
            }
            printf("\n");

            if (tkl > 8 || len < 4 + tkl) {
                // Malformed request. Send 4.00 Bad Request
                char eventId[SESSION_EVENT_ID_LEN];
                char fields[256];
                makeCoapEventId(eventId, sizeof(eventId), requestStartMs);
                snprintf(fields, sizeof(fields),
                    "\"transport\":\"udp\",\"bytes_received\":%d,\"coap_type\":\"%s\",\"coap_method\":\"%s\",\"message_id\":%u,\"token_length\":%u,\"malformed_reason\":\"invalid_token_length\",\"handling_duration_ms\":0",
                    len, coapTypeName(type), coapMethodName(class, detail), msgId, tkl);
                emitCoapAction(eventId, "malformed_request", fields);

                uint8_t response[4];
                uint8_t resp_type = (type == TYPE_CONFIRMABLE) ? TYPE_ACK : TYPE_NON_CONFIRMABLE;
            
                response[0] = (0b01 << 6) | (resp_type << 4) | 0; // Ver=1, Type=ACK/NON, TKL=0
                response[1] = (0b100 << 5) | 0b0;                 // Code 4.00 (Bad Request)
                response[2] = msgId >> 8;
                response[3] = msgId & 0b11111111;
                int resp_len = 4;

                int out = sendto(sockFd, response, resp_len, 0, (struct sockaddr *)&clientAddr, addrLen);
                emitCoapSendEvent(eventId, "bad_request", out, currentTimeMs() - requestStartMs, 0);
                continue;
            } 
            else if (version != 1){
                // Must be silently ignored
                char eventId[SESSION_EVENT_ID_LEN];
                char fields[256];
                makeCoapEventId(eventId, sizeof(eventId), requestStartMs);
                snprintf(fields, sizeof(fields),
                    "\"transport\":\"udp\",\"bytes_received\":%d,\"coap_version\":%u,\"malformed_reason\":\"unsupported_version\",\"handling_duration_ms\":0",
                    len, version);
                emitCoapAction(eventId, "malformed_request", fields);
                continue;
            } else if (tkl > 0) {
                memcpy(token, &buffer[4], tkl);
            }

            // TODO: Ignore extended methods (send "method not allowed" response)
            // TODO: Handle requests while the client is still receiving blocks. 
            struct coapClient* client = findExistingClient(&clientAddr);
            if(client == NULL) {
                client = malloc(sizeof(struct coapClient));
                if (!client) {
                    fprintf(stderr, "Out of memory");
                    continue;
                }

                client->clientAddr = clientAddr;
                client->addrLen = addrLen;
                client->base.sendNext = now + delay;
                client->base.timeConnected = 0;
                client->blockNumber = 0;
                client->tkl = tkl;
                client->interactionDepth = 0;
                client->retransmits = 0;
                client->messageId = 1;
                client->receivedAck = true;
                client->receivedRst = true;
                client->receivedGet = false;
                memcpy(client->token, token, 8);
                snprintf(client->base.ipaddr, INET_ADDRSTRLEN, "%s", inet_ntoa(clientAddr.sin_addr));
                makeCoapEventId(client->sessionId, sizeof(client->sessionId), requestStartMs);
                heap_insert(&clientQueueCoap, (struct baseClient*)client);
                addClient(client);

                char msg[256];
                snprintf(msg, sizeof(msg), "%s connect %s\n",
                    SERVER_ID, client->base.ipaddr);
                printf("%s", msg);
                sendMetric(msg);
            }

            client->interactionDepth += 1;
            char fields[256];
            snprintf(fields, sizeof(fields),
                "\"transport\":\"udp\",\"bytes_received\":%d,\"coap_type\":\"%s\",\"coap_method\":\"%s\",\"message_id\":%u,\"token_present\":%s,\"token_length\":%u,\"handling_duration_ms\":0,\"interaction_depth\":%u",
                len,
                coapTypeName(type),
                coapMethodName(class, detail),
                msgId,
                tkl > 0 ? "true" : "false",
                tkl,
                client->interactionDepth);
            emitCoapAction(client->sessionId, "request_received", fields);
            
            if (type == TYPE_RST) {
                client->receivedRst = true;
            }
            else if (type == TYPE_ACK) {
                client->receivedAck = true;
                client->retransmits = 0;
            }
            else if (class == CLASS_REQUEST && detail == DETAIL_GET) {
                printf("GET request from %s of type %d with tkl=%d and msgId1=%u\n", inet_ntoa(clientAddr.sin_addr), type, tkl, msgId);
                client->receivedGet = true;
            } 

            // If a CON (Confirmable) request, first send seperate ACK response. 
            // The response does not need to be confirmable. (5.2.2 and 5.2.3)
            if (type == TYPE_CONFIRMABLE) {
                uint8_t ack[4];
                ack[0] = (0b01 << 6) | (0b10 << 4) | 0;   // Version = 1, Type = ACK (2), TKL = 0
                ack[1] = 0;                               // Code = 0.00 (empty ACK)
                ack[2] = buffer[2];                       // Same Message ID MSB
                ack[3] = buffer[3];                       // Same Message ID LSB

                int out = sendto(sockFd, ack, sizeof(ack), 0, (struct sockaddr *)&clientAddr, addrLen);
                printf("ACK sendto: %d with messageId=%u\n", out, msgId);
                client->interactionDepth += 1;
                emitCoapSendEvent(client->sessionId, "ack", out, currentTimeMs() - requestStartMs, client->interactionDepth);
            }
        }
    }

    close(sockFd);
    return 0;
}
