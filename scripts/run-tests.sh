#!/bin/bash
set -euo pipefail

echo "============================================"
echo "  eBPF WireMock Router — Integration Test"
echo "============================================"
echo ""

WIREMOCK_YAML="${WIREMOCK_YAML:-/app/wiremock.yaml}"
METADATA_ADDR="${METADATA_ADDR:-:9667}"
VERBOSE="${VERBOSE:-false}"

# -----------------------------------------------
# 1. Wait for WireMock (running in sibling container, shared network)
# -----------------------------------------------
echo "[1/4] Waiting for WireMock..."

PORTS=$(grep -E '^\s+port:\s+[0-9]+' "$WIREMOCK_YAML" | awk '{print $2}')

for PORT in $PORTS; do
    for i in $(seq 1 60); do
        if curl -sf "http://localhost:${PORT}/__admin/mappings" > /dev/null 2>&1; then
            echo "       ✓ WireMock port ${PORT} is ready"
            break
        fi
        if [ "$i" -eq 60 ]; then
            echo "       ✗ WireMock port ${PORT} not reachable after 30s"
            exit 1
        fi
        sleep 0.5
    done
done

# -----------------------------------------------
# 2. Start the eBPF router
# -----------------------------------------------
echo "[2/4] Starting eBPF router..."

VERBOSE_FLAG=""
if [ "$VERBOSE" = "true" ]; then
    VERBOSE_FLAG="-verbose"
fi

ebpf-wiremock-router \
    -wiremock "$WIREMOCK_YAML" \
    -metadata-addr "$METADATA_ADDR" \
    $VERBOSE_FLAG \
    &>/tmp/ebpf-router.log &
ROUTER_PID=$!

sleep 2
if ! kill -0 "$ROUTER_PID" 2>/dev/null; then
    echo "       ✗ eBPF router failed to start:"
    cat /tmp/ebpf-router.log
    exit 1
fi
echo "       ✓ eBPF router started (PID: ${ROUTER_PID})"
cat /tmp/ebpf-router.log

# -----------------------------------------------
# 3. Run Java integration tests
# -----------------------------------------------
echo ""
echo "[3/4] Running Java integration tests..."
echo ""

cd /app/java
mvn test 2>&1
TEST_EXIT=${PIPESTATUS[0]:-$?}

echo ""

# -----------------------------------------------
# 4. Collect report
# -----------------------------------------------
echo "[4/4] Test dependency report..."
echo ""

sleep 1

echo "=== Test → Service Dependency Summary ==="
curl -sf "http://localhost:9667/api/summary" | jq . 2>/dev/null || echo "(no metadata captured)"

echo ""
echo "=== Full Report ==="
curl -sf "http://localhost:9667/api/report" | jq . 2>/dev/null || echo "(no data)"

# Print eBPF router log
echo ""
echo "=== eBPF Router Log ==="
cat /tmp/ebpf-router.log
echo "=== End eBPF Router Log ==="

# Cleanup
echo ""
echo "Shutting down..."
kill "$ROUTER_PID" 2>/dev/null || true
sleep 1
cat /tmp/ebpf-router.log | tail -5

exit "${TEST_EXIT:-0}"
