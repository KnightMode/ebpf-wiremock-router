package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// TransparentProxy accepts connections redirected by eBPF and routes them
// to the correct WireMock port based on the HTTP Host header or TLS SNI.
// Unknown hosts are passed through to the real destination.
type TransparentProxy struct {
	listenPort int
	routes     map[string]int // hostname → WireMock port
	correlator *MetadataCorrelator
	listener   net.Listener
}

func NewTransparentProxy(port int, routes map[string]int, correlator *MetadataCorrelator) *TransparentProxy {
	return &TransparentProxy{
		listenPort: port,
		routes:     routes,
		correlator: correlator,
	}
}

func (p *TransparentProxy) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p.listenPort))
	if err != nil {
		return fmt.Errorf("proxy listen: %w", err)
	}
	p.listener = ln

	log.Printf("transparent proxy listening on 127.0.0.1:%d", p.listenPort)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(conn)
		}
	}()

	return nil
}

func (p *TransparentProxy) Close() {
	if p.listener != nil {
		p.listener.Close()
	}
}

func (p *TransparentProxy) handleConn(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReaderSize(conn, 16384)

	// Peek at first byte to detect TLS (0x16) vs plain HTTP
	first, err := br.Peek(1)
	if err != nil {
		return
	}

	var host string
	var isTLS bool

	if first[0] == 0x16 {
		// TLS ClientHello — extract Server Name Indication (SNI)
		isTLS = true
		// Peek at what's already buffered (the initial read filled the buffer
		// with whatever the client sent; don't block waiting for more)
		n := br.Buffered()
		if n < 5 {
			n = 5
		}
		data, _ := br.Peek(n)
		host = extractSNI(data)
	} else {
		// Plain HTTP — extract Host header from what's already buffered
		n := br.Buffered()
		data, _ := br.Peek(n)
		host = extractHTTPHost(data)
	}

	if host == "" {
		log.Printf("[proxy] could not extract host, dropping connection")
		return
	}

	// Strip port from host if present (e.g., "example.com:8080" → "example.com")
	hostname := host
	hostPort := ""
	if h, p, err := net.SplitHostPort(host); err == nil {
		hostname = h
		hostPort = p
	}

	// Look up route: hostname → WireMock port
	var backend string
	var ruleName string

	if wmPort, ok := p.routes[hostname]; ok {
		// Known service → route to WireMock
		backend = fmt.Sprintf("127.0.0.1:%d", wmPort)
		ruleName = hostname
		log.Printf("[proxy] %s → WireMock :%d", hostname, wmPort)
	} else {
		// Unknown service → pass through to real destination
		port := "80"
		if isTLS {
			port = "443"
		}
		if hostPort != "" {
			port = hostPort
		}
		backend = net.JoinHostPort(hostname, port)
		log.Printf("[proxy] %s → pass-through to %s", hostname, backend)
	}

	// Record the connection for test metadata correlation
	if p.correlator != nil && ruleName != "" {
		p.correlator.RecordConnection(CapturedConnection{
			Timestamp:   time.Now(),
			Host:        hostname,
			RuleName:    ruleName,
			WiremockPort: p.routes[hostname],
		})
	}

	// Connect to backend
	backendConn, err := net.DialTimeout("tcp", backend, 5*time.Second)
	if err != nil {
		log.Printf("[proxy] failed to connect to %s: %v", backend, err)
		return
	}
	defer backendConn.Close()

	// Relay data bidirectionally (br contains any buffered/peeked data)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(backendConn, br) // forwards buffered + remaining data from client
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, backendConn) // forwards response to client
	}()

	wg.Wait()
}

// extractHTTPHost finds the Host header value in raw HTTP request bytes.
func extractHTTPHost(data []byte) string {
	s := string(data)
	lines := strings.Split(s, "\r\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "host:") {
			return strings.TrimSpace(line[5:])
		}
		if line == "" {
			break // end of headers
		}
	}
	return ""
}

// extractSNI parses a TLS ClientHello and extracts the SNI hostname.
func extractSNI(data []byte) string {
	// TLS record: type(1) + version(2) + length(2)
	if len(data) < 5 || data[0] != 0x16 {
		return ""
	}
	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen {
		// Not enough data, work with what we have
		if len(data) < 43 {
			return ""
		}
	}

	pos := 5 // skip TLS record header

	// Handshake header: type(1) + length(3)
	if pos+4 > len(data) || data[pos] != 0x01 { // ClientHello
		return ""
	}
	pos += 4 // skip handshake header

	// ClientHello: version(2) + random(32)
	pos += 2 + 32
	if pos >= len(data) {
		return ""
	}

	// Session ID
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(data) {
		return ""
	}

	// Cipher suites
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen
	if pos+1 > len(data) {
		return ""
	}

	// Compression methods
	compMethodsLen := int(data[pos])
	pos += 1 + compMethodsLen
	if pos+2 > len(data) {
		return ""
	}

	// Extensions length
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	endOfExtensions := pos + extensionsLen

	// Walk extensions looking for SNI (type 0x0000)
	for pos+4 <= len(data) && pos < endOfExtensions {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if extType == 0 && pos+extLen <= len(data) {
			// SNI extension: list_length(2) + name_type(1) + name_length(2) + name
			if extLen < 5 {
				break
			}
			nameType := data[pos+2]
			if nameType != 0 { // 0 = hostname
				break
			}
			nameLen := int(data[pos+3])<<8 | int(data[pos+4])
			if pos+5+nameLen > len(data) {
				break
			}
			return string(data[pos+5 : pos+5+nameLen])
		}

		pos += extLen
	}

	return ""
}
