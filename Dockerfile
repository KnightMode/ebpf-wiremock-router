# =============================================================
# Stage 1: Build the eBPF router (compile BPF C + Go binary)
# =============================================================
FROM golang:1.22-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
RUN go install github.com/cilium/ebpf/cmd/bpf2go@v0.17.3

COPY . .

# Detect arch for eBPF compilation
ARG TARGETARCH
RUN ARCH=$(echo ${TARGETARCH:-$(dpkg --print-architecture)} | sed 's/amd64/x86/' | sed 's/arm64/arm64/') && \
    clang -O2 -g -target bpf \
    -D__TARGET_ARCH_${ARCH} \
    -I bpf \
    -c bpf/redirect.c \
    -o bpf/redirect.o

# Generate Go bindings via bpf2go — target must match runtime arch
RUN BPF2GO_TARGET=$(dpkg --print-architecture | sed 's/amd64/amd64/' | sed 's/arm64/arm64/') && \
    go generate ./...

# Build the final binary
RUN CGO_ENABLED=0 go build -o ebpf-wiremock-router .


# =============================================================
# Stage 2: Runtime — eBPF router + Java tests
# =============================================================
FROM eclipse-temurin:21-jdk-jammy

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    jq \
    maven \
    && rm -rf /var/lib/apt/lists/*

# eBPF router binary
COPY --from=builder /build/ebpf-wiremock-router /usr/local/bin/ebpf-wiremock-router

WORKDIR /app

# WireMock config (for eBPF router to derive routes)
COPY wiremock.yaml ./

# Java project — download dependencies first for caching
COPY java/pom.xml ./java/pom.xml
RUN cd /app/java && mvn dependency:resolve -q

# Java source
COPY java/ ./java/

# Entrypoint script
COPY scripts/run-tests.sh ./run-tests.sh
RUN chmod +x run-tests.sh

ENTRYPOINT ["/app/run-tests.sh"]
