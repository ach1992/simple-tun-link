# Build on the test runner, never install/enable services on an STL host.
# Runtime always uses --network none and fresh disposable network namespaces.
ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iptables iputils-ping wireguard-tools ca-certificates \
      charon-systemd strongswan-swanctl libstrongswan-standard-plugins \
    && rm -rf /var/lib/apt/lists/*
