# meshircd has no runtime dependencies, so the image is just Python plus
# the source. No build stage, no wheels to compile, nothing to pin.
FROM python:3.13-slim

LABEL org.opencontainers.image.title="meshircd" \
      org.opencontainers.image.description="A small IRC server, Python standard library only" \
      org.opencontainers.image.licenses="MIT"

# Non-root from the start. The UID is fixed so a bind-mounted state
# directory has predictable ownership on the host.
RUN useradd --system --uid 10001 --create-home --home-dir /var/lib/meshircd meshircd

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir --no-compile . && rm -rf /root/.cache

# Config is read-only; state is the only thing that needs to be writable.
RUN mkdir -p /etc/meshircd /var/lib/meshircd \
 && chown -R meshircd:meshircd /var/lib/meshircd \
 && chmod 0700 /var/lib/meshircd

USER meshircd
WORKDIR /var/lib/meshircd

ENV IRCD_CONFIG=/etc/meshircd/ircd.toml \
    IRCD_STORAGE_PATH=/var/lib/meshircd/meshircd.db \
    PYTHONUNBUFFERED=1

EXPOSE 6667 6697
VOLUME ["/var/lib/meshircd"]

# Validates the config and resolves every listener without binding, which
# is a genuine readiness signal rather than a liveness placeholder.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["meshircd", "--check-config"]

ENTRYPOINT ["meshircd"]
