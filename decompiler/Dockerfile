FROM eclipse-temurin:21-jdk-jammy

ARG GHIDRA_VERSION=12.0.4
ARG GHIDRA_BUILD_DATE=20260303
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD_DATE}.zip

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip curl unzip ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/ghidra.zip "${GHIDRA_URL}" \
 && unzip -q /tmp/ghidra.zip -d /opt \
 && mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra \
 && rm /tmp/ghidra.zip

COPY decompiler/ghiant /opt/ghiant

# Default working dir is mounted as /job by the orchestrator (worker)
WORKDIR /job

ENTRYPOINT ["python3", "/opt/ghiant/ghidra_decompile.py", "/opt/ghidra"]
