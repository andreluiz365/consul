package config

import (
	"fmt"
	"net"
	"reflect"
	"strconv"
	"time"

	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/types"
)

// RuntimeConfig specifies the configuration the consul agent actually
// uses. Is is derived from one or more Config structures which can come
// from files, flags and/or environment variables.
type RuntimeConfig struct {
	// simple values

	ACLAgentMasterToken string
	ACLAgentToken       string
	ACLDatacenter       string
	ACLDefaultPolicy    string
	ACLDisabledTTL      time.Duration // todo(fs): configure me!
	ACLDownPolicy       string
	ACLEnforceVersion8  bool
	ACLMasterToken      string
	ACLReplicationToken string
	ACLTTL              time.Duration
	ACLToken            string

	AutopilotCleanupDeadServers      bool
	AutopilotDisableUpgradeMigration bool
	AutopilotLastContactThreshold    time.Duration
	AutopilotMaxTrailingLogs         uint64
	AutopilotRedundancyZoneTag       string
	AutopilotServerStabilizationTime time.Duration
	AutopilotUpgradeVersionTag       string

	DNSAllowStale         bool
	DNSDisableCompression bool
	DNSDomain             string
	DNSEnableTruncate     bool
	DNSMaxStale           time.Duration
	DNSNodeTTL            time.Duration
	DNSOnlyPassing        bool
	DNSRecursorTimeout    time.Duration
	DNSServiceTTL         map[string]time.Duration
	DNSUDPAnswerLimit     int
	DNSRecursors          []string

	HTTPBlockEndpoints  []string
	HTTPResponseHeaders map[string]string

	PerformanceRaftMultiplier int

	TelemetryCirconusAPIApp                     string
	TelemetryCirconusAPIToken                   string
	TelemetryCirconusAPIURL                     string
	TelemetryCirconusBrokerID                   string
	TelemetryCirconusBrokerSelectTag            string
	TelemetryCirconusCheckDisplayName           string
	TelemetryCirconusCheckForceMetricActivation string
	TelemetryCirconusCheckID                    string
	TelemetryCirconusCheckInstanceID            string
	TelemetryCirconusCheckSearchTag             string
	TelemetryCirconusCheckTags                  string
	TelemetryCirconusSubmissionInterval         string
	TelemetryCirconusSubmissionURL              string
	TelemetryDisableHostname                    bool
	TelemetryDogStatsdAddr                      string
	TelemetryDogStatsdTags                      []string
	TelemetryFilterDefault                      bool
	TelemetryPrefixFilter                       []string
	TelemetryStatsdAddr                         string
	TelemetryStatsiteAddr                       string
	TelemetryStatsitePrefix                     string

	Bootstrap                   bool
	BootstrapExpect             int
	CAFile                      string
	CAPath                      string
	CertFile                    string
	CheckUpdateInterval         time.Duration
	Checks                      []*structs.CheckDefinition
	Datacenter                  string
	DataDir                     string
	DevMode                     bool
	DisableAnonymousSignature   bool
	DisableCoordinates          bool
	DisableHostNodeID           bool
	DisableKeyringFile          bool
	DisableRemoteExec           bool
	DisableUpdateCheck          bool
	EnableACLReplication        bool
	EnableDebug                 bool
	EnableScriptChecks          bool
	EnableSyslog                bool
	EnableUI                    bool
	EncryptKey                  string
	EncryptVerifyIncoming       bool
	EncryptVerifyOutgoing       bool
	KeyFile                     string
	LeaveOnTerm                 bool
	LogLevel                    string
	NodeID                      string
	NodeMeta                    map[string]string
	NodeName                    string
	NonVotingServer             bool
	PidFile                     string
	RPCProtocol                 int
	RaftProtocol                int
	ReconnectTimeoutLAN         time.Duration
	ReconnectTimeoutWAN         time.Duration
	RejoinAfterLeave            bool
	RetryJoinIntervalLAN        time.Duration
	RetryJoinIntervalWAN        time.Duration
	RetryJoinLAN                []string
	RetryJoinMaxAttemptsLAN     int
	RetryJoinMaxAttemptsWAN     int
	RetryJoinWAN                []string
	ServerMode                  bool
	ServerName                  string
	SessionTTLMin               time.Duration
	SkipLeaveOnInt              bool
	SyslogFacility              string
	TLSCipherSuites             []uint16
	TLSMinVersion               string
	TLSPreferServerCipherSuites bool
	TaggedAddresses             map[string]string

	TranslateWANAddrs    bool
	UIDir                string
	UnixSocketUser       string
	UnixSocketGroup      string
	UnixSocketMode       string
	VerifyIncoming       bool
	VerifyIncomingHTTPS  bool
	VerifyIncomingRPC    bool
	VerifyOutgoing       bool
	VerifyServerHostname bool

	// address values

	BindAddrs         []string
	ClientAddr        string
	StartJoinAddrsLAN []string
	StartJoinAddrsWAN []string

	// server endpoint values

	DNSPort     int
	DNSAddrsTCP []string
	DNSAddrsUDP []string

	HTTPPort  int
	HTTPAddrs []string

	HTTPSPort  int
	HTTPSAddrs []string
}

// NewRuntimeConfig creates the runtime configuration from a configuration
// file. It performs all the necessary syntactic and semantic validation
// so that the resulting runtime configuration is usable.
func NewRuntimeConfig(f Config) (RuntimeConfig, error) {
	return (&builder{f: f}).build()
}

type builder struct {
	f     Config
	err   error
	warns []error
}

func (b *builder) build() (RuntimeConfig, error) {
	f := b.f

	autopilotMaxTrailingLogs := b.intVal(f.Autopilot.MaxTrailingLogs)
	if autopilotMaxTrailingLogs < 0 {
		return RuntimeConfig{}, fmt.Errorf("config: autopilot.max_trailing_logs < 0")
	}

	var dnsRecursors []string
	if f.DNSRecursor != nil {
		dnsRecursors = append(dnsRecursors, b.stringVal(f.DNSRecursor))
	}
	dnsRecursors = append(dnsRecursors, f.DNSRecursors...)

	var dnsServiceTTL = map[string]time.Duration{}
	for k, v := range f.DNS.ServiceTTL {
		dnsServiceTTL[k] = b.durationVal(&v)
	}

	// Checks and Services
	var checks []*structs.CheckDefinition
	if f.Check != nil {
		checks = append(checks, b.checkVal(f.Check))
	}
	for _, check := range f.Checks {
		checks = append(checks, b.checkVal(&check))
	}

	// if no bind address is given but ports are specified then we bail.
	// this only affects tests since in prod this gets merged with the
	// default config which always has a bind address.
	if f.BindAddr == nil && !reflect.DeepEqual(f.Ports, Ports{}) {
		return RuntimeConfig{}, fmt.Errorf("no bind address specified")
	}

	var bindAddrs []string
	if f.BindAddr != nil {
		bindAddrs = []string{b.addrVal(f.BindAddr)}
	}

	addrs := func(hosts []string, port int) (addrs []string) {
		if port > 0 {
			for _, h := range hosts {
				addrs = append(addrs, b.joinHostPort(h, port))
			}
		}
		return
	}

	// todo(fs): take magic value for "disabled" into account, e.g. 0 or -1
	dnsPort := b.intVal(f.Ports.DNS)
	if dnsPort < 0 {
		dnsPort = 0
	}
	dnsAddrsTCP := addrs(bindAddrs, dnsPort)
	dnsAddrsUDP := addrs(bindAddrs, dnsPort)

	httpPort := b.intVal(f.Ports.HTTP)
	if httpPort < 0 {
		httpPort = 0
	}
	httpAddrs := addrs(bindAddrs, httpPort)

	httpsPort := b.intVal(f.Ports.HTTPS)
	if httpsPort < 0 {
		httpsPort = 0
	}
	httpsAddrs := addrs(bindAddrs, httpsPort)

	// missing complex stuff
	if f.AdvertiseAddrLAN != nil ||
		f.AdvertiseAddrWAN != nil ||
		!reflect.DeepEqual(Addresses{}, f.Addresses) ||
		!reflect.DeepEqual(AdvertiseAddrsConfig{}, f.AdvertiseAddrs) ||
		f.AEInterval != nil ||
		f.ACLDisabledTTL != nil ||
		f.CheckDeregisterIntervalMin != nil ||
		f.CheckReapInterval != nil ||
		f.SerfBindAddrLAN != nil ||
		f.SerfBindAddrWAN != nil ||
		f.TLSCipherSuites != nil ||
		f.Watches != nil {
		panic("add me")
	}

	c := RuntimeConfig{
		// ACL
		ACLAgentMasterToken:  b.stringVal(f.ACLAgentMasterToken),
		ACLAgentToken:        b.stringVal(f.ACLAgentToken),
		ACLDatacenter:        b.stringVal(f.ACLDatacenter),
		ACLDefaultPolicy:     b.stringVal(f.ACLDefaultPolicy),
		ACLDownPolicy:        b.stringVal(f.ACLDownPolicy),
		ACLEnforceVersion8:   b.boolVal(f.ACLEnforceVersion8),
		ACLMasterToken:       b.stringVal(f.ACLMasterToken),
		ACLReplicationToken:  b.stringVal(f.ACLReplicationToken),
		ACLTTL:               b.durationVal(f.ACLTTL),
		ACLToken:             b.stringVal(f.ACLToken),
		EnableACLReplication: b.boolVal(f.EnableACLReplication),

		// Autopilot
		AutopilotCleanupDeadServers:      b.boolVal(f.Autopilot.CleanupDeadServers),
		AutopilotDisableUpgradeMigration: b.boolVal(f.Autopilot.DisableUpgradeMigration),
		AutopilotLastContactThreshold:    b.durationVal(f.Autopilot.LastContactThreshold),
		AutopilotMaxTrailingLogs:         uint64(autopilotMaxTrailingLogs),
		AutopilotRedundancyZoneTag:       b.stringVal(f.Autopilot.RedundancyZoneTag),
		AutopilotServerStabilizationTime: b.durationVal(f.Autopilot.ServerStabilizationTime),
		AutopilotUpgradeVersionTag:       b.stringVal(f.Autopilot.UpgradeVersionTag),

		// DNS
		DNSAddrsTCP:           dnsAddrsTCP,
		DNSAddrsUDP:           dnsAddrsUDP,
		DNSAllowStale:         b.boolVal(f.DNS.AllowStale),
		DNSDisableCompression: b.boolVal(f.DNS.DisableCompression),
		DNSDomain:             b.stringVal(f.DNSDomain),
		DNSEnableTruncate:     b.boolVal(f.DNS.EnableTruncate),
		DNSMaxStale:           b.durationVal(f.DNS.MaxStale),
		DNSNodeTTL:            b.durationVal(f.DNS.NodeTTL),
		DNSOnlyPassing:        b.boolVal(f.DNS.OnlyPassing),
		DNSPort:               dnsPort,
		DNSRecursorTimeout:    b.durationVal(f.DNS.RecursorTimeout),
		DNSRecursors:          dnsRecursors,
		DNSServiceTTL:         dnsServiceTTL,
		DNSUDPAnswerLimit:     b.intVal(f.DNS.UDPAnswerLimit),

		// HTTP
		HTTPPort:            httpPort,
		HTTPSPort:           httpsPort,
		HTTPAddrs:           httpAddrs,
		HTTPSAddrs:          httpsAddrs,
		HTTPBlockEndpoints:  f.HTTPConfig.BlockEndpoints,
		HTTPResponseHeaders: f.HTTPConfig.ResponseHeaders,

		// Performance
		PerformanceRaftMultiplier: b.intVal(f.Performance.RaftMultiplier),

		// Telemetry
		TelemetryCirconusAPIApp:                     b.stringVal(f.Telemetry.CirconusAPIApp),
		TelemetryCirconusAPIToken:                   b.stringVal(f.Telemetry.CirconusAPIToken),
		TelemetryCirconusAPIURL:                     b.stringVal(f.Telemetry.CirconusAPIURL),
		TelemetryCirconusBrokerID:                   b.stringVal(f.Telemetry.CirconusBrokerID),
		TelemetryCirconusBrokerSelectTag:            b.stringVal(f.Telemetry.CirconusBrokerSelectTag),
		TelemetryCirconusCheckDisplayName:           b.stringVal(f.Telemetry.CirconusCheckDisplayName),
		TelemetryCirconusCheckForceMetricActivation: b.stringVal(f.Telemetry.CirconusCheckForceMetricActivation),
		TelemetryCirconusCheckID:                    b.stringVal(f.Telemetry.CirconusCheckID),
		TelemetryCirconusCheckInstanceID:            b.stringVal(f.Telemetry.CirconusCheckInstanceID),
		TelemetryCirconusCheckSearchTag:             b.stringVal(f.Telemetry.CirconusCheckSearchTag),
		TelemetryCirconusCheckTags:                  b.stringVal(f.Telemetry.CirconusCheckTags),
		TelemetryCirconusSubmissionInterval:         b.stringVal(f.Telemetry.CirconusSubmissionInterval),
		TelemetryCirconusSubmissionURL:              b.stringVal(f.Telemetry.CirconusSubmissionURL),
		TelemetryDisableHostname:                    b.boolVal(f.Telemetry.DisableHostname),
		TelemetryDogStatsdAddr:                      b.stringVal(f.Telemetry.DogStatsdAddr),
		TelemetryDogStatsdTags:                      f.Telemetry.DogStatsdTags,
		TelemetryFilterDefault:                      b.boolVal(f.Telemetry.FilterDefault),
		TelemetryPrefixFilter:                       f.Telemetry.PrefixFilter,
		TelemetryStatsdAddr:                         b.stringVal(f.Telemetry.StatsdAddr),
		TelemetryStatsiteAddr:                       b.stringVal(f.Telemetry.StatsiteAddr),
		TelemetryStatsitePrefix:                     b.stringVal(f.Telemetry.StatsitePrefix),

		// RetryJoinAzure

		// RetryJoinEC2

		// RetryJoinGCE

		// UnixSocket

		// Agent
		BindAddrs:                   bindAddrs,
		Bootstrap:                   b.boolVal(f.Bootstrap),
		BootstrapExpect:             b.intVal(f.BootstrapExpect),
		CAFile:                      b.stringVal(f.CAFile),
		CAPath:                      b.stringVal(f.CAPath),
		CertFile:                    b.stringVal(f.CertFile),
		CheckUpdateInterval:         b.durationVal(f.CheckUpdateInterval),
		Checks:                      checks,
		ClientAddr:                  b.stringVal(f.ClientAddr),
		DataDir:                     b.stringVal(f.DataDir),
		Datacenter:                  b.stringVal(f.Datacenter),
		DevMode:                     b.boolVal(f.DevMode),
		DisableAnonymousSignature:   b.boolVal(f.DisableAnonymousSignature),
		DisableCoordinates:          b.boolVal(f.DisableCoordinates),
		DisableHostNodeID:           b.boolVal(f.DisableHostNodeID),
		DisableKeyringFile:          b.boolVal(f.DisableKeyringFile),
		DisableRemoteExec:           b.boolVal(f.DisableRemoteExec),
		DisableUpdateCheck:          b.boolVal(f.DisableUpdateCheck),
		EnableDebug:                 b.boolVal(f.EnableDebug),
		EnableScriptChecks:          b.boolVal(f.EnableScriptChecks),
		EnableSyslog:                b.boolVal(f.EnableSyslog),
		EnableUI:                    b.boolVal(f.EnableUI),
		EncryptKey:                  b.stringVal(f.EncryptKey),
		EncryptVerifyIncoming:       b.boolVal(f.EncryptVerifyIncoming),
		EncryptVerifyOutgoing:       b.boolVal(f.EncryptVerifyOutgoing),
		KeyFile:                     b.stringVal(f.KeyFile),
		LeaveOnTerm:                 b.boolVal(f.LeaveOnTerm),
		LogLevel:                    b.stringVal(f.LogLevel),
		NodeID:                      b.stringVal(f.NodeID),
		NodeMeta:                    f.NodeMeta,
		NodeName:                    b.stringVal(f.NodeName),
		NonVotingServer:             b.boolVal(f.NonVotingServer),
		PidFile:                     b.stringVal(f.PidFile),
		RPCProtocol:                 b.intVal(f.RPCProtocol),
		RaftProtocol:                b.intVal(f.RaftProtocol),
		ReconnectTimeoutLAN:         b.durationVal(f.ReconnectTimeoutLAN),
		ReconnectTimeoutWAN:         b.durationVal(f.ReconnectTimeoutWAN),
		RejoinAfterLeave:            b.boolVal(f.RejoinAfterLeave),
		RetryJoinIntervalLAN:        b.durationVal(f.RetryJoinIntervalLAN),
		RetryJoinIntervalWAN:        b.durationVal(f.RetryJoinIntervalWAN),
		RetryJoinLAN:                f.RetryJoinLAN,
		RetryJoinMaxAttemptsLAN:     b.intVal(f.RetryJoinMaxAttemptsLAN),
		RetryJoinMaxAttemptsWAN:     b.intVal(f.RetryJoinMaxAttemptsWAN),
		RetryJoinWAN:                f.RetryJoinWAN,
		ServerMode:                  b.boolVal(f.ServerMode),
		ServerName:                  b.stringVal(f.ServerName),
		SessionTTLMin:               b.durationVal(f.SessionTTLMin),
		SkipLeaveOnInt:              b.boolVal(f.SkipLeaveOnInt),
		StartJoinAddrsLAN:           f.StartJoinAddrsLAN,
		StartJoinAddrsWAN:           f.StartJoinAddrsWAN,
		SyslogFacility:              b.stringVal(f.SyslogFacility),
		TLSMinVersion:               b.stringVal(f.TLSMinVersion),
		TLSPreferServerCipherSuites: b.boolVal(f.TLSPreferServerCipherSuites),
		TaggedAddresses:             f.TaggedAddresses,

		TranslateWANAddrs:    b.boolVal(f.TranslateWANAddrs),
		UIDir:                b.stringVal(f.UIDir),
		UnixSocketUser:       b.stringVal(f.UnixSocket.User),
		UnixSocketGroup:      b.stringVal(f.UnixSocket.Group),
		UnixSocketMode:       b.stringVal(f.UnixSocket.Mode),
		VerifyIncoming:       b.boolVal(f.VerifyIncoming),
		VerifyIncomingHTTPS:  b.boolVal(f.VerifyIncomingHTTPS),
		VerifyIncomingRPC:    b.boolVal(f.VerifyIncomingRPC),
		VerifyOutgoing:       b.boolVal(f.VerifyOutgoing),
		VerifyServerHostname: b.boolVal(f.VerifyServerHostname),
	}

	return c, b.err
}

func (b *builder) warn(msg string, args ...interface{}) {
	b.warns = append(b.warns, fmt.Errorf(msg, args...))
}

func (b *builder) checkVal(v *CheckDefinition) *structs.CheckDefinition {
	if b.err != nil || v == nil {
		return nil
	}

	serviceID := v.ServiceID
	if v.AliasServiceID != nil {
		b.warn("config: 'serviceid' is deprecated in check definitions. Please use 'service_id' instead")
		serviceID = v.AliasServiceID
	}

	dockerContainerID := v.DockerContainerID
	if v.AliasDockerContainerID != nil {
		b.warn("config: 'dockercontainerid' is deprecated in check definitions. Please use 'docker_container_id' instead")
		dockerContainerID = v.AliasDockerContainerID
	}

	tlsSkipVerify := v.TLSSkipVerify
	if v.AliasTLSSkipVerify != nil {
		b.warn("config: 'tlsskipverify' is deprecated in check definitions. Please use 'tls_skip_verify' instead")
		tlsSkipVerify = v.AliasTLSSkipVerify
	}

	deregisterCriticalServiceAfter := v.DeregisterCriticalServiceAfter
	if v.AliasDeregisterCriticalServiceAfter != nil {
		b.warn("config: 'deregistercriticalserviceafter' is deprecated in check definitions. Please use 'deregister_critical_service_after' instead")
		deregisterCriticalServiceAfter = v.AliasDeregisterCriticalServiceAfter
	}

	return &structs.CheckDefinition{
		ID:                types.CheckID(b.stringVal(v.ID)),
		Name:              b.stringVal(v.Name),
		Notes:             b.stringVal(v.Notes),
		ServiceID:         b.stringVal(serviceID),
		Token:             b.stringVal(v.Token),
		Status:            b.stringVal(v.Status),
		Script:            b.stringVal(v.Script),
		HTTP:              b.stringVal(v.HTTP),
		Header:            v.Header,
		Method:            b.stringVal(v.Method),
		TCP:               b.stringVal(v.TCP),
		Interval:          b.durationVal(v.Interval),
		DockerContainerID: b.stringVal(dockerContainerID),
		Shell:             b.stringVal(v.Shell),
		TLSSkipVerify:     b.boolVal(tlsSkipVerify),
		Timeout:           b.durationVal(v.Timeout),
		TTL:               b.durationVal(v.TTL),
		DeregisterCriticalServiceAfter: b.durationVal(deregisterCriticalServiceAfter),
	}
}

func (b *builder) boolVal(v *bool) bool {
	if b.err != nil || v == nil {
		return false
	}
	return *v
}

func (b *builder) durationVal(v *string) (d time.Duration) {
	if b.err != nil || v == nil {
		return 0
	}
	d, b.err = time.ParseDuration(*v)
	return
}

func (b *builder) intVal(v *int) int {
	if b.err != nil || v == nil {
		return 0
	}
	return *v
}

func (b *builder) uint64Val(v *uint64) uint64 {
	if b.err != nil || v == nil {
		return 0
	}
	return *v
}

func (b *builder) stringVal(v *string) string {
	if b.err != nil || v == nil {
		return ""
	}
	return *v
}

func (b *builder) addrVal(v *string) string {
	addr := b.stringVal(v)
	if addr == "" {
		return "0.0.0.0"
	}
	return addr
}

func (b *builder) joinHostPort(host string, port int) string {
	if host == "0.0.0.0" {
		host = ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}
