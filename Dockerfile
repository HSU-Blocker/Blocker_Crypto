# Blocker Manufacturer Backend Dockerfile
FROM --platform=linux/amd64 python:3.9-slim

# 필수 패키지 설치
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    libgmp-dev \
    libssl-dev \
    wget \
    flex \
    bison \
    && rm -rf /var/lib/apt/lists/*

# go-ipfs 설치 (ipfs CLI 사용을 위해)
RUN wget https://dist.ipfs.tech/go-ipfs/v0.7.0/go-ipfs_v0.7.0_linux-amd64.tar.gz && \
    tar -xvzf go-ipfs_v0.7.0_linux-amd64.tar.gz && \
    cd go-ipfs && \
    bash install.sh && \
    cd .. && \
    rm -rf go-ipfs go-ipfs_v0.7.0_linux-amd64.tar.gz

WORKDIR /app

# PBC 라이브러리 설치
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
    tar -xvf pbc-0.5.14.tar.gz && \
    cd pbc-0.5.14 && \
    ./configure && \
    make && \
    make install && \
    ldconfig && \
    cd .. && \
    rm -rf pbc-0.5.14 pbc-0.5.14.tar.gz

# requirements.txt 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# charm-crypto 설치
RUN git clone https://github.com/JHUISI/charm.git /tmp/charm && \
    cd /tmp/charm && \
    ./configure.sh && \
    make && \
    make install && \
    cd /app && \
    rm -rf /tmp/charm

# 프로젝트 전체 복사
COPY . .

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
