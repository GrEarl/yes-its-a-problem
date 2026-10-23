FROM alpine:3.21
RUN apk add --no-cache pdns-recursor || true
RUN (pdns_recursor --version) 2>&1 | head -3 || true
EXPOSE 53/udp 53/tcp
