package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"
)

// TestEvent is sent by the JUnit extension at test start/end
type TestEvent struct {
	Event        string `json:"event"`
	TestClass    string `json:"test_class"`
	TestMethod   string `json:"test_method"`
	DisplayName  string `json:"display_name,omitempty"`
	Passed       *bool  `json:"passed,omitempty"`
	PID          int    `json:"pid"`
	JavaThreadID int64  `json:"java_thread_id,omitempty"`
	Timestamp    int64  `json:"timestamp"`
}

// CapturedConnection represents a proxied connection attributed to a service
type CapturedConnection struct {
	Timestamp    time.Time `json:"timestamp"`
	Host         string    `json:"host"`
	WiremockPort int       `json:"wiremock_port"`
	RuleName     string    `json:"rule_name"`
}

// TestDependency is the output: a test and all the services it called
type TestDependency struct {
	TestClass   string               `json:"test_class"`
	TestMethod  string               `json:"test_method"`
	Passed      *bool                `json:"passed,omitempty"`
	StartTime   time.Time            `json:"start_time"`
	EndTime     time.Time            `json:"end_time"`
	Connections []CapturedConnection `json:"connections"`
}

// MetadataCorrelator tracks active tests and correlates connections with test metadata
type MetadataCorrelator struct {
	mu          sync.RWMutex
	activeTests map[int]*activeTest
	completed   []TestDependency
	routes      map[string]int
}

type activeTest struct {
	event       TestEvent
	startTime   time.Time
	connections []CapturedConnection
}

func NewMetadataCorrelator(routes map[string]int) *MetadataCorrelator {
	return &MetadataCorrelator{
		activeTests: make(map[int]*activeTest),
		routes:      routes,
	}
}

// RecordConnection is called by the transparent proxy when a connection
// is routed to a WireMock service. Uses time-based correlation to
// attribute the connection to the currently active test.
func (mc *MetadataCorrelator) RecordConnection(conn CapturedConnection) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	// Attribute to any active test (tests run sequentially)
	for _, at := range mc.activeTests {
		at.connections = append(at.connections, conn)
	}

	log.Printf("[capture] %s → WireMock :%d (rule: %s)",
		conn.Host, conn.WiremockPort, conn.RuleName)
}

// HandleTestEvent processes test start/end events from the JUnit extension
func (mc *MetadataCorrelator) HandleTestEvent(event TestEvent) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	switch event.Event {
	case "test_start":
		mc.activeTests[event.PID] = &activeTest{
			event:     event,
			startTime: time.Now(),
		}
		log.Printf("[test-start] %s.%s (PID=%d)", event.TestClass, event.TestMethod, event.PID)

	case "test_end":
		at, ok := mc.activeTests[event.PID]
		if !ok {
			log.Printf("[test-end] WARNING: no active test found for PID=%d", event.PID)
			return
		}

		dep := TestDependency{
			TestClass:   event.TestClass,
			TestMethod:  event.TestMethod,
			Passed:      event.Passed,
			StartTime:   at.startTime,
			EndTime:     time.Now(),
			Connections: at.connections,
		}
		mc.completed = append(mc.completed, dep)
		delete(mc.activeTests, event.PID)

		log.Printf("[test-end] %s.%s — %d service calls captured",
			event.TestClass, event.TestMethod, len(at.connections))
	}
}

// GetReport returns the full dependency report
func (mc *MetadataCorrelator) GetReport() []TestDependency {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	result := make([]TestDependency, len(mc.completed))
	copy(result, mc.completed)
	return result
}

// GetSummary returns a condensed view: test → list of service names
func (mc *MetadataCorrelator) GetSummary() map[string][]string {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	summary := make(map[string][]string)
	for _, dep := range mc.completed {
		key := dep.TestClass + "." + dep.TestMethod
		seen := make(map[string]bool)
		for _, conn := range dep.Connections {
			name := conn.RuleName
			if name == "" {
				name = fmt.Sprintf("%s:%d", conn.Host, conn.WiremockPort)
			}
			if !seen[name] {
				seen[name] = true
				summary[key] = append(summary[key], name)
			}
		}
		sort.Strings(summary[key])
	}
	return summary
}

// StartMetadataServer runs the HTTP API that the JUnit extension talks to
func StartMetadataServer(mc *MetadataCorrelator, addr string) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/test-event", func(w http.ResponseWriter, r *http.Request) {
		var event TestEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mc.HandleTestEvent(event)
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("GET /api/report", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mc.GetReport())
	})

	mux.HandleFunc("GET /api/summary", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mc.GetSummary())
	})

	mux.HandleFunc("GET /api/connections", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		report := mc.GetReport()
		var all []CapturedConnection
		for _, dep := range report {
			all = append(all, dep.Connections...)
		}
		json.NewEncoder(w).Encode(all)
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		log.Printf("metadata API listening on %s", addr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("metadata server error: %v", err)
		}
	}()

	return srv
}
