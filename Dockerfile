FROM debian:bookworm-slim

ARG CLAUDE_CODE_CHANNEL=stable

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        bash ca-certificates curl python3 python3-cryptography \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 reviewer \
    && mkdir -p /app /data /opt/claude-installer \
    && chown -R reviewer:reviewer /app /data /opt/claude-installer

USER reviewer
WORKDIR /opt/claude-installer
RUN curl -fsSL https://claude.ai/install.sh | bash -s "${CLAUDE_CODE_CHANNEL}"

ENV PATH="/home/reviewer/.local/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DISABLE_AUTOUPDATER=1 \
    CLAUDE_CODE_SKIP_PROMPT_HISTORY=1

WORKDIR /app
COPY --chown=reviewer:reviewer . /app

VOLUME ["/data"]
ENTRYPOINT ["python3", "-m", "security_review"]
CMD ["app"]
