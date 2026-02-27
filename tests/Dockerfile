FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    bash curl wget git python3 python3-pip \
    ufw apparmor apparmor-utils \
    systemd dbus \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /laia
COPY . .
RUN chmod +x tests/*.sh scripts/*.sh config/**/*.sh 2>/dev/null || true

CMD ["bash", "tests/run-all.sh"]
