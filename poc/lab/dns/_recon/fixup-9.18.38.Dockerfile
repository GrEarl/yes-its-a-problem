FROM lab-recon/bind9:9.18.38
RUN echo /usr/local/lib > /etc/ld.so.conf.d/local.conf && ldconfig
