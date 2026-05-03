FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libgmp-dev libmpfr-dev libmpc-dev \
    binutils file curl \
    bash less vim-tiny nano \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    pwntools==4.13.0 \
    pycryptodome==3.21.0 \
    gmpy2==2.2.1 \
    sympy==1.13.3 \
    z3-solver==4.13.4.0 \
    ecdsa==0.19.0 \
    requests==2.32.3 \
    httpx==0.27.2

WORKDIR /work
# Default to bash so the web terminal works; orchestrators set their
# own command (`python3 /work/exploit.py ...` or `sage ...`) via
# `command=[...]` and that takes precedence.
CMD ["bash"]
