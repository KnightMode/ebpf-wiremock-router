package main

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// WireMockConfig represents the wiremock.yaml structure
type WireMockConfig struct {
	Services map[string]WireMockService `yaml:"services"`
}

type WireMockService struct {
	Port      int               `yaml:"port"`
	Originals map[string]string `yaml:"originals,omitempty"`
}

// LoadWireMockConfig parses wiremock.yaml and returns the config
func LoadWireMockConfig(path string) (*WireMockConfig, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving path: %w", err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("reading wiremock.yaml: %w", err)
	}

	var cfg WireMockConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing wiremock.yaml: %w", err)
	}

	if len(cfg.Services) == 0 {
		return nil, fmt.Errorf("no services defined in wiremock.yaml")
	}

	return &cfg, nil
}

// BuildHostRoutes extracts hostname → WireMock port mappings from wiremock.yaml.
// The transparent proxy uses these to route intercepted connections.
//
// For each service with an `originals` URL, it extracts the hostname.
// For example:
//
//	originals:
//	  default: https://api.example.com
//	port: 8080
//
// Produces: "api.example.com" → 8080
//
// The proxy matches the HTTP Host header (or TLS SNI) against these hostnames.
// Any hostname not in this map is passed through to the real destination.
func BuildHostRoutes(wmCfg *WireMockConfig) map[string]int {
	routes := make(map[string]int)

	for svcKey, svc := range wmCfg.Services {
		if len(svc.Originals) == 0 {
			log.Printf("WARNING: service %q has no originals — skipping", svcKey)
			continue
		}

		for _, originURL := range svc.Originals {
			parsed, err := url.Parse(originURL)
			if err != nil {
				log.Printf("WARNING: service %q has invalid originals URL %q: %v", svcKey, originURL, err)
				continue
			}
			host := parsed.Hostname()
			if host != "" {
				routes[host] = svc.Port
			}
		}
	}

	return routes
}
