# Disposable, disconnected Ubuntu strongSwan proof image only.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      charon-systemd strongswan-swanctl iproute2 iputils-ping \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /proof
CMD ["/bin/bash"]
