# Disposable PID1/systemd acceptance image. Never install/disable systemd
# or strongSwan on the control-plane host.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd dbus charon-systemd strongswan-swanctl iproute2 iputils-ping \
 && systemctl disable strongswan.service \
 && test "$(systemctl is-enabled strongswan.service)" = disabled \
 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd", "--system", "--log-level=warning"]
