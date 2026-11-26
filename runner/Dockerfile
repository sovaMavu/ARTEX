# syntax=docker/dockerfile:1.7
#
# Pinned Kali rolling manifest.  Do not replace this with :latest.  The digest
# is the multi-arch manifest published 2026-11-08; update it deliberately and
# re-run the parser golden tests after every base-image bump.
ARG KALI_IMAGE=kalilinux/kali-rolling@sha256:6ec743d9fc5cd397451eeddeff3869bcfab5de9bd5dec5b1f34cbfbd80313073
FROM ${KALI_IMAGE}

LABEL org.opencontainers.image.title="artex-kali-runner" \
      org.opencontainers.image.description="Typed non-web capability runner for ARTEX (Phase 1 network pack)" \
      org.opencontainers.image.source="https://github.com/Autumn-27/artex" \
      org.opencontainers.image.licenses="Proprietary"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp \
    PYTHONPATH=/app

# Tool packages are installed in one layer.  No runtime installs are allowed.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsutils \
        enum4linux-ng \
        ldap-utils \
        nmap \
        onesixtyone \
        python3 \
        python3-pip \
        python3-venv \
        samba-common-bin \
        smbmap \
        snmp \
        ssh-audit \
        testssl.sh \
 && rm -rf /var/lib/apt/lists/* \
 && for tool in nmap dig testssl.sh snmpwalk enum4linux-ng ldapsearch ssh-audit; do \
        command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }; \
    done

COPY requirements.lock /tmp/requirements.lock
RUN python3 -m venv /opt/runner \
 && /opt/runner/bin/pip install --upgrade pip \
 && /opt/runner/bin/pip install -r /tmp/requirements.lock \
 && rm -f /tmp/requirements.lock

WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
COPY runner /app/runner
RUN /opt/runner/bin/pip install --no-deps /app \
 && mkdir -p /scopes /artifacts \
 && groupadd --gid 10001 runner \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin runner \
 && chown -R runner:runner /artifacts /opt/runner /app

USER 10001:10001
EXPOSE 8899

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["curl", "-fsS", "http://127.0.0.1:8899/healthz"]

ENTRYPOINT ["/opt/runner/bin/python", "-m", "runner"]
