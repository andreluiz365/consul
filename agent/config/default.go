package config

import "time"

func pBool(v bool) *bool                       { return &v }
func pInt(v int) *int                          { return &v }
func pString(v string) *string                 { return &v }
func pDuration(v time.Duration) *time.Duration { return &v }

// defaultConfig is the default configuration file.
var defaultConfig = Config{
	Bootstrap:           pBool(false),
	CheckUpdateInterval: pString("5m"),
	Datacenter:          pString("dc1"),
	BindAddr:            pString("0.0.0.0"),
	Ports: Ports{
		DNS: pInt(8600),
	},
}

// defaultRuntimeConfig is the default runtime configuration which must
// be identical from merging the defaultFile into a configuration.
var defaultRuntimeConfig = RuntimeConfig{
	Bootstrap:           false,
	CheckUpdateInterval: 5 * time.Minute,
	Datacenter:          "dc1",
	BindAddrs:           []string{"0.0.0.0"},
	DNSPort:             8600,
	DNSAddrsTCP:         []string{":8600"},
	DNSAddrsUDP:         []string{":8600"},
}
