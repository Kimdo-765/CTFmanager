FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git ca-certificates gnupg lsb-release \
    file binutils \
    libgmp-dev libmpfr-dev libmpc-dev \
    # Archive tools the agent often calls from Bash (zips inside source
    # uploads, nested archives, prebuilt CTF distributions, etc.). The
    # Python zipfile fallback in api/storage.py only handles the initial
    # upload — anything the agent unpacks itself needs the CLI.
    unzip zip p7zip-full xz-utils bzip2 tar \
    # Light editing / inspection helpers commonly used by the agent.
    less jq xxd \
 && rm -rf /var/lib/apt/lists/*

# Node.js (required by claude-agent-sdk to run the bundled `claude` CLI)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/* \
 && npm install -g @anthropic-ai/claude-code

# Docker CLI (so worker can spawn sibling containers via the mounted socket)
RUN install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg \
        -o /etc/apt/keyrings/docker.asc \
 && chmod a+r /etc/apt/keyrings/docker.asc \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
        > /etc/apt/sources.list.d/docker.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends docker-ce-cli \
 && rm -rf /var/lib/apt/lists/*

COPY worker/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY worker /app/worker

# Expose ghiant as a Bash command so the agent can invoke decompilation
# on demand instead of forcing it as a pre-step.
RUN ln -sf /app/worker/ghiant_cli.py /usr/local/bin/ghiant \
 && chmod +x /app/worker/ghiant_cli.py

ENV PYTHONPATH=/app

CMD ["python", "-m", "worker.runner"]
