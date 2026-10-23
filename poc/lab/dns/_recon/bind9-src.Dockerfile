FROM ubuntu:24.04
ARG VERSION=9.18.38
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      build-essential libuv1-dev libssl-dev libnghttp2-dev libxml2-utils \
      libcap-dev zlib1g-dev wget ca-certificates pkg-config perl \
    && rm -rf /var/lib/apt/lists/*
RUN cd /tmp && wget -q https://downloads.isc.org/isc/bind9/$VERSION/bind-$VERSION.tar.xz \
    && tar xf bind-$VERSION.tar.xz && cd bind-$VERSION \
    && ./configure --prefix=/usr/local --sysconfdir=/etc/bind --localstatedir=/var \
    && make -j$(nproc) && make install \
    && echo /usr/local/lib > /etc/ld.so.conf.d/local.conf && ldconfig \
    && useradd -r -s /usr/sbin/nologin bind \
    && mkdir -p /etc/bind /var/cache/bind /var/run/named /var/log/bind \
    && chown -R bind:bind /var/cache/bind /var/run/named /var/log/bind \
    && cd /tmp && rm -rf bind-$VERSION*
EXPOSE 53/udp 53/tcp
USER root
ENTRYPOINT ["/usr/local/sbin/named", "-g", "-u", "bind", "-c", "/etc/bind/named.conf"]
