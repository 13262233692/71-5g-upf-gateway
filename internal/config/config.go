package config

import (
	"flag"
	"os"
	"time"
)

type Config struct {
	N3Interface   string
	N6Interface   string
	N3Address     string
	N6Address     string
	NodeID        string
	LogLevel      string
	StatsInterval time.Duration
}

func Load() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.N3Interface, "n3-iface", getEnv("UPF_N3_IFACE", "eth0"),
		"N3 interface name (GTP-U tunnel from gNB)")
	flag.StringVar(&cfg.N6Interface, "n6-iface", getEnv("UPF_N6_IFACE", "eth1"),
		"N6 interface name (DN/Internet)")
	flag.StringVar(&cfg.N3Address, "n3-addr", getEnv("UPF_N3_ADDR", "192.168.1.1/24"),
		"N3 interface IP address")
	flag.StringVar(&cfg.N6Address, "n6-addr", getEnv("UPF_N6_ADDR", "10.0.0.1/24"),
		"N6 interface IP address")
	flag.StringVar(&cfg.NodeID, "node-id", getEnv("UPF_NODE_ID", "upf-001"),
		"UPF node identifier")
	flag.StringVar(&cfg.LogLevel, "log-level", getEnv("UPF_LOG_LEVEL", "info"),
		"Log level (debug, info, warn, error)")
	flag.DurationVar(&cfg.StatsInterval, "stats-interval", getEnvDuration("UPF_STATS_INTERVAL", 10*time.Second),
		"Statistics reporting interval")

	flag.Parse()

	return cfg
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value, exists := os.LookupEnv(key); exists {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}
