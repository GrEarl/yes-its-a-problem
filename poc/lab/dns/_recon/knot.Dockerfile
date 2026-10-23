FROM alpine:3.21
RUN apk add --no-cache knot-resolver || true
RUN (kresd -V || kresd --version || kresctl --version) 2>&1 | head -5 || true
RUN apk info knot-resolver 2>/dev/null | head -2 || true
EXPOSE 53/udp 53/tcp
