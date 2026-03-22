package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go redirect bpf/redirect.c -- -I bpf

const defaultProxyPort = 16789

func main() {
	wiremockYaml := flag.String("wiremock", "wiremock.yaml", "path to wiremock.yaml")
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup", "cgroup v2 mount path to attach to")
	metadataAddr := flag.String("metadata-addr", ":9667", "address for the metadata API server")
	proxyPort := flag.Int("proxy-port", defaultProxyPort, "port for the transparent proxy")
	verbose := flag.Bool("verbose", false, "enable verbose logging")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `ebpf-wiremock-router — transparent eBPF traffic redirection to WireMock

Intercepts ALL outgoing TCP connections via eBPF cgroup/connect4, redirects
them to a local transparent proxy that routes by HTTP Host header (or TLS SNI)
to the correct WireMock port. Unknown hosts are passed through to the real
destination. No DNS resolution or /etc/hosts hacks needed.

Usage:
  sudo ./ebpf-wiremock-router -wiremock /path/to/wiremock.yaml

Flags:
`)
		flag.PrintDefaults()
	}

	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("ebpf-wiremock-router starting...")

	// Parse wiremock.yaml and build host → WireMock port routing table
	wmCfg, err := LoadWireMockConfig(*wiremockYaml)
	if err != nil {
		log.Fatalf("failed to load wiremock.yaml: %v", err)
	}
	log.Printf("loaded wiremock.yaml with %d services from %s", len(wmCfg.Services), *wiremockYaml)

	routes := BuildHostRoutes(wmCfg)
	if len(routes) == 0 {
		log.Fatalf("no routing rules derived from wiremock.yaml")
	}
	for host, port := range routes {
		log.Printf("  route: %s → WireMock :%d", host, port)
	}

	// Ensure all service hostnames are resolvable so the app's connect()
	// syscall fires (which the eBPF hook intercepts). For unresolvable
	// hostnames, inject dummy IPs into /etc/hosts. The actual IP doesn't
	// matter — eBPF redirects ALL non-loopback connects to the proxy,
	// and the proxy routes by Host header.
	if err := ensureHostsResolvable(routes); err != nil {
		log.Printf("WARNING: failed to inject /etc/hosts entries: %v", err)
	}

	// Remove memlock limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock rlimit: %v", err)
	}

	// Load compiled eBPF objects
	var objs redirectObjects
	if err := loadRedirectObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Start the metadata correlator and HTTP API
	correlator := NewMetadataCorrelator(routes)
	metaSrv := StartMetadataServer(correlator, *metadataAddr)

	// Start the transparent proxy BEFORE attaching eBPF
	proxy := NewTransparentProxy(*proxyPort, routes, correlator)
	if err := proxy.Start(); err != nil {
		log.Fatalf("failed to start proxy: %v", err)
	}
	defer proxy.Close()

	// Write our PID into the proxy_pid_map so the eBPF program
	// skips connections from this process (and the proxy goroutines)
	myPID := uint32(os.Getpid())
	if err := objs.ProxyPidMap.Put(uint32(0), myPID); err != nil {
		log.Fatalf("failed to set proxy PID in BPF map: %v", err)
	}
	if *verbose {
		log.Printf("proxy PID %d written to BPF map", myPID)
	}

	// Write the proxy port into proxy_port_map (in ctx->user_port format)
	portForBPF := uint32(portToNetBytes(uint16(*proxyPort)))
	if err := objs.ProxyPortMap.Put(uint32(0), portForBPF); err != nil {
		log.Fatalf("failed to set proxy port in BPF map: %v", err)
	}

	// Attach eBPF program to the target cgroup
	cgroupDir, err := os.Open(*cgroupPath)
	if err != nil {
		log.Fatalf("failed to open cgroup %s: %v", *cgroupPath, err)
	}
	defer cgroupDir.Close()

	lnk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupDir.Name(),
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.Connect4Redirect,
	})
	if err != nil {
		log.Fatalf("failed to attach eBPF program to cgroup: %v", err)
	}
	defer lnk.Close()

	log.Printf("eBPF attached to cgroup %s — ALL outgoing TCP redirected to proxy :%d",
		*cgroupPath, *proxyPort)
	log.Println("traffic interception is ACTIVE — press Ctrl+C to stop")
	printRouteSummary(routes)

	// Wait for interrupt
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("shutting down...")
	metaSrv.Shutdown(context.Background())
	printStats(objs.StatsMap)
	printFinalReport(correlator)
}

// portToNetBytes converts a host port number to the uint16 representation
// matching how the kernel stores ctx->user_port on little-endian.
func portToNetBytes(port uint16) uint16 {
	b := [2]byte{}
	binary.BigEndian.PutUint16(b[:], port)
	return binary.LittleEndian.Uint16(b[:])
}

// ensureHostsResolvable checks if each service hostname resolves via DNS.
// For unresolvable hosts (e.g., service-a.example.com), it injects a dummy
// IP from 198.18.0.0/15 into /etc/hosts. The actual IP is irrelevant —
// eBPF intercepts ALL outgoing connects and redirects to the proxy.
func ensureHostsResolvable(routes map[string]int) error {
	var entries []string
	dummyIP := uint32(0xC6120001) // 198.18.0.1

	for host := range routes {
		if _, err := net.LookupIP(host); err != nil {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, dummyIP)
			dummyIP++
			entry := fmt.Sprintf("%s\t%s", ip.String(), host)
			entries = append(entries, entry)
			log.Printf("  %s unresolvable → injecting %s into /etc/hosts", host, ip)
		}
	}

	if len(entries) == 0 {
		return nil
	}

	f, err := os.OpenFile("/etc/hosts", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	f.WriteString("\n# ebpf-wiremock-router: dummy IPs for unresolvable service hosts\n")
	for _, e := range entries {
		f.WriteString(e + "\n")
	}
	return nil
}

func printRouteSummary(routes map[string]int) {
	fmt.Println()
	fmt.Println("Active routes (derived from wiremock.yaml originals):")
	fmt.Println("  ┌──────────────────────────────────────────────────────────┐")
	for host, port := range routes {
		fmt.Printf("  │  %-40s → WireMock :%d  │\n", host, port)
	}
	fmt.Println("  └──────────────────────────────────────────────────────────┘")
	fmt.Printf("  All other hosts → pass-through to real destination\n")
	fmt.Println()
}

func printStats(m *ebpf.Map) {
	var totalKey, redirKey uint32 = 0, 1
	var totalVals, redirVals []uint64

	if err := m.Lookup(totalKey, &totalVals); err != nil {
		log.Printf("failed to read total stats: %v", err)
		return
	}
	if err := m.Lookup(redirKey, &redirVals); err != nil {
		log.Printf("failed to read redirect stats: %v", err)
		return
	}

	var total, redirected uint64
	for _, v := range totalVals {
		total += v
	}
	for _, v := range redirVals {
		redirected += v
	}

	log.Printf("stats: %d total outgoing connects, %d redirected to proxy", total, redirected)
}

func printFinalReport(mc *MetadataCorrelator) {
	summary := mc.GetSummary()
	if len(summary) == 0 {
		log.Println("no test metadata captured (was the JUnit extension active?)")
		return
	}

	fmt.Println()
	fmt.Println("=== Test → Service Dependency Report ===")
	fmt.Println()
	for test, services := range summary {
		fmt.Printf("  %s\n", test)
		for _, svc := range services {
			fmt.Printf("    → %s\n", svc)
		}
		fmt.Println()
	}
}
