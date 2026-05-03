FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        binwalk foremost \
        libimage-exiftool-perl \
        steghide outguess \
        pngcheck \
        qpdf poppler-utils \
        imagemagick \
        p7zip-full unzip xxd \
        ruby ruby-dev build-essential \
        file ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN gem install --no-document zsteg

COPY misc/*.py /opt/misc/

WORKDIR /job
ENTRYPOINT ["python3", "/opt/misc/analyze.py"]
