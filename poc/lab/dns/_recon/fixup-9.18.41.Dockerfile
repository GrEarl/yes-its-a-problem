FROM lab-recon/bind9:9.18.41
RUN echo /usr/local/lib > /etc/ld.so.conf.d/local.conf && ldconfig
