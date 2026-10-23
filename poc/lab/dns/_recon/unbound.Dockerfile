FROM alpine:3.21
RUN apk add --no-cache unbound
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["unbound", "-d", "-c", "/etc/unbound/unbound.conf"]
