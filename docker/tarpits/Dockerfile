FROM gcc:12.5.0-bookworm@sha256:01cfb27075399638ccdffa855970683ad298a3fad61012d7ab62523abbff5d20 AS c-builder

WORKDIR /src
COPY servers/ ./servers/
COPY shared/ ./shared/
COPY makefile .

RUN make telnet_pit upnp_pit mqtt_pit coap_pit

# Final image
FROM debian:bookworm-slim@sha256:63a496b5d3b99214b39f5ed70eb71a61e590a77979c79cbee4faf991f8c0783e

COPY --from=c-builder /src/bin/* /usr/local/bin/
COPY run.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/run.sh

ENTRYPOINT ["/usr/local/bin/run.sh"]
