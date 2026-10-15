# Fresh disposable PID1-systemd host for proving the REAL first-install
# strongSwan maintainer hooks and transaction-owned vendor normalization.
# Do not install strongSwan here: the product PREPARE must do so.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd dbus iproute2 iptables kmod ca-certificates
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd", "--system", "--log-level=warning"]
