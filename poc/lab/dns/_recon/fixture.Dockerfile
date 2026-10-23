FROM alpine:3.21
RUN apk add --no-cache python3
RUN mkdir -p /recon /vendor
COPY lab/dns/_recon/*.py /recon/
COPY vendor/dnslib /vendor/dnslib
ENTRYPOINT ["python3", "/recon/fixture_server.py"]
