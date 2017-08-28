package config

import (
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/types"
	"github.com/pascaldekloe/goe/verify"
)

// TestRuntimeConfig tests whether a combination of command line flags and
// config files creates the correct runtime configuration. The tests do
// not use the default configuration as basis as this would provide a
// lot of redundancy in the test results.
//
// The tests are grouped and within the groups are ordered alphabetically.
func TestRuntimeConfig(t *testing.T) {
	tests := []struct {
		desc             string
		def              Config
		json, hcl, flags []string
		rtcfg            RuntimeConfig
		err              error
	}{
		{
			desc:  "default config",
			def:   defaultConfig,
			rtcfg: defaultRuntimeConfig,
		},

		// cmd line flags
		{
			desc:  "-bind",
			flags: []string{`-bind`, `1.2.3.4`},
			rtcfg: RuntimeConfig{BindAddrs: []string{"1.2.3.4"}},
		},
		{
			desc:  "-bootstrap",
			flags: []string{`-bootstrap`},
			rtcfg: RuntimeConfig{Bootstrap: true},
		},
		{
			desc:  "-datacenter",
			flags: []string{`-datacenter`, `a`},
			rtcfg: RuntimeConfig{Datacenter: "a"},
		},
		{
			desc:  "-dns-port",
			flags: []string{`-dns-port`, `123`, `-bind`, `0.0.0.0`},
			rtcfg: RuntimeConfig{
				BindAddrs:   []string{"0.0.0.0"},
				DNSPort:     123,
				DNSAddrsUDP: []string{":123"},
				DNSAddrsTCP: []string{":123"},
			},
		},
		{
			desc:  "-join",
			flags: []string{`-join`, `a`, `-join`, `b`},
			rtcfg: RuntimeConfig{StartJoinAddrsLAN: []string{"a", "b"}},
		},
		{
			desc:  "-node-meta",
			flags: []string{`-node-meta`, `a:b`, `-node-meta`, `c:d`},
			rtcfg: RuntimeConfig{NodeMeta: map[string]string{"a": "b", "c": "d"}},
		},

		// cfg files
		{
			desc: "check alias fields",
			json: []string{`{"check":{ "service_id":"d", "serviceid":"dd", "docker_container_id":"k", "dockercontainerid":"kk", "tls_skip_verify":true, "tlsskipverify":false, "deregister_critical_service_after":"5s", "deregistercriticalserviceafter": "10s" }}`},
			hcl:  []string{`check = { service_id="d" serviceid="dd" docker_container_id="k" dockercontainerid="kk" tls_skip_verify=true tlsskipverify=false deregister_critical_service_after="5s" deregistercriticalserviceafter="10s"}`},
			rtcfg: RuntimeConfig{Checks: []*structs.CheckDefinition{
				{
					ServiceID:                      "dd",
					DockerContainerID:              "kk",
					TLSSkipVerify:                  false,
					DeregisterCriticalServiceAfter: 10 * time.Second,
				},
			}},
		},
		{
			desc: "check",
			json: []string{`{"check":{ "id":"a", "name":"b", "notes":"c", "service_id":"d", "token":"e", "status":"f", "script":"g", "http":"h", "header":{"x":["y"]}, "method":"i", "tcp":"j", "interval":"5s", "docker_container_id":"k", "shell":"l", "tls_skip_verify":true, "timeout":"5s", "ttl":"5s", "deregister_critical_service_after":"5s" }}`},
			hcl:  []string{`check = { id="a" name="b" notes="c" service_id="d" token="e" status="f" script="g" http="h" header={x=["y"]} method="i" tcp="j" interval="5s" docker_container_id="k" shell="l" tls_skip_verify=true timeout="5s" ttl="5s" deregister_critical_service_after="5s" }`},
			rtcfg: RuntimeConfig{Checks: []*structs.CheckDefinition{
				{
					ID:                types.CheckID("a"),
					Name:              "b",
					Notes:             "c",
					ServiceID:         "d",
					Token:             "e",
					Status:            "f",
					Script:            "g",
					HTTP:              "h",
					Header:            map[string][]string{"x": []string{"y"}},
					Method:            "i",
					TCP:               "j",
					Interval:          5 * time.Second,
					DockerContainerID: "k",
					Shell:             "l",
					TLSSkipVerify:     true,
					Timeout:           5 * time.Second,
					TTL:               5 * time.Second,
					DeregisterCriticalServiceAfter: 5 * time.Second,
				},
			}},
		},
		{
			desc: "checks",
			json: []string{`{"checks":[{ "id":"a", "name":"b", "notes":"c", "service_id":"d", "token":"e", "status":"f", "script":"g", "http":"h", "header":{"x":["y"]}, "method":"i", "tcp":"j", "interval":"5s", "docker_container_id":"k", "shell":"l", "tls_skip_verify":true, "timeout":"5s", "ttl":"5s", "deregister_critical_service_after":"5s" }]}`},
			hcl:  []string{`checks = [{ id="a" name="b" notes="c" service_id="d" token="e" status="f" script="g" http="h" header={x=["y"]} method="i" tcp="j" interval="5s" docker_container_id="k" shell="l" tls_skip_verify=true timeout="5s" ttl="5s" deregister_critical_service_after="5s" }]`},
			rtcfg: RuntimeConfig{Checks: []*structs.CheckDefinition{
				{
					ID:                types.CheckID("a"),
					Name:              "b",
					Notes:             "c",
					ServiceID:         "d",
					Token:             "e",
					Status:            "f",
					Script:            "g",
					HTTP:              "h",
					Header:            map[string][]string{"x": []string{"y"}},
					Method:            "i",
					TCP:               "j",
					Interval:          5 * time.Second,
					DockerContainerID: "k",
					Shell:             "l",
					TLSSkipVerify:     true,
					Timeout:           5 * time.Second,
					TTL:               5 * time.Second,
					DeregisterCriticalServiceAfter: 5 * time.Second,
				},
			}},
		},
		{
			desc: "ports == 0",
			json: []string{`{ "bind_addr":"0.0.0.0", "ports":{} }`},
			hcl:  []string{` bind_addr = "0.0.0.0" ports {}`},
			rtcfg: RuntimeConfig{
				BindAddrs: []string{"0.0.0.0"},
			},
		},
		{
			desc: "ports < 0",
			json: []string{`{ "bind_addr":"0.0.0.0", "ports":{ "dns":-1, "http":-2, "https":-3 } }`},
			hcl:  []string{` bind_addr = "0.0.0.0" ports { dns = -1 http = -2 https = -3 }`},
			rtcfg: RuntimeConfig{
				BindAddrs: []string{"0.0.0.0"},
			},
		},
		{
			desc:  "retry_join",
			json:  []string{`{"retry_join":["a"]}`, `{"retry_join":["b"]}`},
			hcl:   []string{`retry_join = ["a"]`, `retry_join = ["b"]`},
			rtcfg: RuntimeConfig{RetryJoinLAN: []string{"a", "b"}},
		},
		{
			desc:  "retry_join_wan",
			json:  []string{`{"retry_join_wan":["a"]}`, `{"retry_join_wan":["b"]}`},
			hcl:   []string{`retry_join_wan = ["a"]`, `retry_join_wan = ["b"]`},
			rtcfg: RuntimeConfig{RetryJoinWAN: []string{"a", "b"}},
		},
		{
			desc:  "retry_max",
			json:  []string{`{"retry_max":1}`},
			hcl:   []string{`retry_max=1`},
			rtcfg: RuntimeConfig{RetryJoinMaxAttemptsLAN: 1},
		},
		{
			desc:  "retry_max_wan",
			json:  []string{`{"retry_max_wan":1}`},
			hcl:   []string{`retry_max_wan=1`},
			rtcfg: RuntimeConfig{RetryJoinMaxAttemptsWAN: 1},
		},
		{
			desc:  "server",
			json:  []string{`{"server":true}`},
			hcl:   []string{`server=true`},
			rtcfg: RuntimeConfig{ServerMode: true},
		},
		{
			desc:  "server_name",
			json:  []string{`{"server_name":"a"}`},
			hcl:   []string{`server_name="a"`},
			rtcfg: RuntimeConfig{ServerName: "a"},
		},
		{
			desc:  "session_ttl_min",
			json:  []string{`{"session_ttl_min":"5s"}`},
			hcl:   []string{`session_ttl_min="5s"`},
			rtcfg: RuntimeConfig{SessionTTLMin: 5 * time.Second},
		},
		{
			desc:  "skip_leave_on_interrupt",
			json:  []string{`{"skip_leave_on_interrupt":true}`},
			hcl:   []string{`skip_leave_on_interrupt=true`},
			rtcfg: RuntimeConfig{SkipLeaveOnInt: true},
		},
		{
			desc:  "start_join",
			json:  []string{`{"start_join":["a"]}`, `{"start_join":["b"]}`},
			hcl:   []string{`start_join = ["a"]`, `start_join = ["b"]`},
			rtcfg: RuntimeConfig{StartJoinAddrsLAN: []string{"a", "b"}},
		},
		{
			desc:  "start_join_wan",
			json:  []string{`{"start_join_wan":["a"]}`, `{"start_join_wan":["b"]}`},
			hcl:   []string{`start_join_wan = ["a"]`, `start_join_wan = ["b"]`},
			rtcfg: RuntimeConfig{StartJoinAddrsWAN: []string{"a", "b"}},
		},
		{
			desc:  "recursor",
			json:  []string{`{"recursor":"a"}`},
			hcl:   []string{`recursor = "a"`},
			rtcfg: RuntimeConfig{DNSRecursors: []string{"a"}},
		},
		{
			desc:  "recursors",
			json:  []string{`{"recursors":["a","b"]}`},
			hcl:   []string{`recursors = ["a","b"]`},
			rtcfg: RuntimeConfig{DNSRecursors: []string{"a", "b"}},
		},
		{
			desc:  "recursor and recursors",
			json:  []string{`{"recursor":"a", "recursors":["b","c"]}`},
			hcl:   []string{`recursor="a" recursors=["b","c"]`},
			rtcfg: RuntimeConfig{DNSRecursors: []string{"a", "b", "c"}},
		},
		{
			desc:  "syslog_facility",
			json:  []string{`{"syslog_facility":"a"}`},
			hcl:   []string{`syslog_facility = "a"`},
			rtcfg: RuntimeConfig{SyslogFacility: "a"},
		},
		// {
		// 	desc:  "tls_cipher_suites",
		// 	json:  []string{`{"tls_cipher_suites":"a"}`},
		// 	hcl:   []string{`tls_cipher_suites = "a"`},
		// 	rtcfg: RuntimeConfig{TLSCipherSuites: []uint16{1}},
		// },
		{
			desc:  "tls_min_version",
			json:  []string{`{"tls_min_version":"a"}`},
			hcl:   []string{`tls_min_version = "a"`},
			rtcfg: RuntimeConfig{TLSMinVersion: "a"},
		},
		{
			desc:  "tls_prefer_server_cipher_suites",
			json:  []string{`{"tls_prefer_server_cipher_suites":true}`},
			hcl:   []string{`tls_prefer_server_cipher_suites = true`},
			rtcfg: RuntimeConfig{TLSPreferServerCipherSuites: true},
		},
		{
			desc:  "tagged_addresses",
			json:  []string{`{"tagged_addresses":{"a":"b"}}`},
			hcl:   []string{`tagged_addresses={a = "b"}`},
			rtcfg: RuntimeConfig{TaggedAddresses: map[string]string{"a": "b"}},
		},
		{
			desc:  "translate_wan_addrs",
			json:  []string{`{"translate_wan_addrs":true}`},
			hcl:   []string{`translate_wan_addrs=true`},
			rtcfg: RuntimeConfig{TranslateWANAddrs: true},
		},
		{
			desc:  "ui_dir",
			json:  []string{`{"ui_dir":"a"}`},
			hcl:   []string{`ui_dir="a"`},
			rtcfg: RuntimeConfig{UIDir: "a"},
		},
		{
			desc:  "unix_sockets.user",
			json:  []string{`{"unix_sockets":{"user":"a"}}`},
			hcl:   []string{`unix_sockets={user="a"}`},
			rtcfg: RuntimeConfig{UnixSocketUser: "a"},
		},
		{
			desc:  "unix_sockets.group",
			json:  []string{`{"unix_sockets":{"group":"a"}}`},
			hcl:   []string{`unix_sockets={group="a"}`},
			rtcfg: RuntimeConfig{UnixSocketGroup: "a"},
		},
		{
			desc:  "unix_sockets.mode",
			json:  []string{`{"unix_sockets":{"mode":"a"}}`},
			hcl:   []string{`unix_sockets={mode="a"}`},
			rtcfg: RuntimeConfig{UnixSocketMode: "a"},
		},
		// precedence rules
		{
			desc:  "precedence: bool val",
			json:  []string{`{"bootstrap":true}`, `{"bootstrap":false}`},
			hcl:   []string{`bootstrap = true`, `bootstrap = false`},
			rtcfg: RuntimeConfig{Bootstrap: false},
		},
		{
			desc:  "precedence: flag before file",
			json:  []string{`{"bootstrap":true}`},
			hcl:   []string{`bootstrap = true`},
			flags: []string{`-bootstrap=false`},
			rtcfg: RuntimeConfig{Bootstrap: false},
		},

		// full config
		// random-int() { echo $RANDOM }
		// random-string() { base64 /dev/urandom | tr -d '/+' | fold -w ${1:-32} | head -n 1 }
		// random-string 8
		{
			desc: "full config",
			json: []string{`{
				"acl_agent_master_token": "furuQD0b",
				"acl_agent_token": "cOshLOQ2",
				"acl_datacenter": "M3uRCk3Z",
				"acl_default_policy": "ArK3WIfE",
				"acl_down_policy": "vZXMfMP0",
				"acl_enforce_version_8": true,
				"acl_master_token": "C1Q1oIwh",
				"acl_replication_token": "LMmgy5dO",
				"acl_ttl": "18060s",
				"acl_token": "O1El0wan",
				"autopilot": {
					"cleanup_dead_servers": true,
					"disable_upgrade_migration": true,
					"last_contact_threshold": "12705s",
					"max_trailing_logs": 17849,
					"redundancy_zone_tag": "3IsufDJf",
					"server_stabilization_time": "23057s",
					"upgrade_version_tag": "W9pDwFAL"
				},
				"bind_addr": "6rFPKyh6",
				"bootstrap": true,
				"bootstrap_expect": 28094,
				"ca_file": "erA7T0PM",
				"ca_path": "mQEN1Mfp",
				"cert_file": "7s4QAzDk",
				"check_update_interval": "16507s",
				"client_addr": "e15dFavQ",
				"dns_config": {
					"allow_stale": true,
					"disable_compression": true,
					"enable_truncate": true,
					"max_stale": "29685s",
					"node_ttl": "7084s",
					"only_passing": true,
					"recursor_timeout": "4427s",
					"service_ttl": {
						"*": "32030s"
					},
					"udp_answer_limit": 29909
				},
				"domain": "7W1xXSqd",
				"datacenter": "rzo029wG",
				"data_dir": "oTOOIoV9",
				"dev": true,
				"disable_anonymous_signature": true,
				"disable_coordinates": true,
				"disable_host_node_id": true,
				"disable_keyring_file": true,
				"disable_remote_exec": true,
				"disable_update_check": true,
				"enable_acl_replication": true,
				"enable_debug": true,
				"enable_script_checks": true,
				"enable_syslog": true,
				"enable_ui": true,
				"encrypt": "A4wELWqH",
				"encrypt_verify_incoming": true,
				"encrypt_verify_outgoing": true,
				"http_config": {
					"block_endpoints": ["RBvAFcGD", "fWOWFznh"],
					"response_headers": {"M6TKa9NP":"xjuxjOzQ", "JRCrHZed":"rl0mTx81"}
				},
				"key_file": "IEkkwgIA",
				"leave_on_terminate": true,
				"log_level": "k1zo9Spt",
				"node_id": "AsUIlw99",
				"node_meta": {
					"5mgGQMBk": "mJLtVMSG"
				},
				"node_name": "otlLxGaI",
				"non_voting_server": true,
				"performance": {
					"raft_multiplier": 22057
				},
				"pid_file": "43xN80Km",
				"ports": {
					"dns": 7001,
					"http": 7999,
					"https": 15127
				},
				"protocol": 30793,
				"raft_protocol": 19016,
				"reconnect_timeout": "23739s",
				"reconnect_timeout_wan": "26694s",
				"rejoin_after_leave": true,
				"retry_interval": "8067s",
				"retry_interval_wan": "28866s",
				"telemetry": {
					"circonus_api_app": "p4QOTe9j",
					"circonus_api_token": "E3j35V23",
					"circonus_api_url": "mEMjHpGg",
					"circonus_broker_id": "BHlxUhed",
					"circonus_broker_select_tag": "13xy1gHm",
					"circonus_check_display_name": "DRSlQR6n",
					"circonus_check_force_metric_activation": "Ua5FGVYf",
					"circonus_check_id": "kGorutad",
					"circonus_check_instance_id": "rwoOL6R4",
					"circonus_check_search_tag": "ovT4hT4f",
					"circonus_check_tags": "prvO4uBl",
					"circonus_submission_interval": "DolzaflP",
					"circonus_submission_url": "gTcbS93G",
					"disable_hostname": true,
					"dogstatsd_addr": "0wSndumK",
					"dogstatsd_tags": ["3N81zSUB","Xtj8AnXZ"],
					"filter_default": true,
					"prefix_filter": ["oJotS8XJ","cazlEhGn"],
					"statsd_address": "drce87cy",
					"statsite_address": "HpFwKB8R",
					"statsite_prefix": "ftO6DySn"
				},
				"verify_incoming": true,
				"verify_incoming_https": true,
				"verify_incoming_rpc": true,
				"verify_outgoing": true,
				"verify_server_hostname": true
			}`},
			hcl: []string{`
				acl_agent_master_token = "furuQD0b"
				acl_agent_token = "cOshLOQ2"
				acl_datacenter = "M3uRCk3Z"
				acl_default_policy = "ArK3WIfE"
				acl_down_policy = "vZXMfMP0"
				acl_enforce_version_8 = true
				acl_master_token = "C1Q1oIwh"
				acl_replication_token = "LMmgy5dO"
				acl_ttl = "18060s"
				acl_token = "O1El0wan"
				autopilot = {
					cleanup_dead_servers = true
					disable_upgrade_migration = true
					last_contact_threshold = "12705s"
					max_trailing_logs = 17849
					redundancy_zone_tag = "3IsufDJf"
					server_stabilization_time = "23057s"
					upgrade_version_tag = "W9pDwFAL"
				}
				bind_addr = "6rFPKyh6"
				bootstrap = true
				bootstrap_expect = 28094
				ca_file = "erA7T0PM"
				ca_path = "mQEN1Mfp"
				cert_file = "7s4QAzDk"
				check_update_interval = "16507s"
				client_addr = "e15dFavQ"
				dns_config {
					allow_stale = true
					disable_compression = true
					enable_truncate = true
					max_stale = "29685s"
					node_ttl = "7084s"
					only_passing = true
					recursor_timeout = "4427s"
					service_ttl = {
						"*" = "32030s"
					}
					udp_answer_limit = 29909
				}
				domain = "7W1xXSqd"
				datacenter = "rzo029wG"
				data_dir = "oTOOIoV9"
				dev = true
				disable_anonymous_signature = true
				disable_coordinates = true
				disable_host_node_id = true
				disable_keyring_file = true
				disable_remote_exec = true
				disable_update_check = true
				enable_acl_replication = true
				enable_debug = true
				enable_script_checks = true
				enable_syslog = true
				enable_ui = true
				encrypt = "A4wELWqH"
				encrypt_verify_incoming = true
				encrypt_verify_outgoing = true
				http_config {
					block_endpoints = ["RBvAFcGD", "fWOWFznh"]
					response_headers = {
						"M6TKa9NP" = "xjuxjOzQ"
						"JRCrHZed" = "rl0mTx81"
					}
				}
				key_file = "IEkkwgIA"
				leave_on_terminate = true
				log_level = "k1zo9Spt"
				node_id = "AsUIlw99"
				node_meta {
					"5mgGQMBk" = "mJLtVMSG"
				}
				node_name = "otlLxGaI"
				non_voting_server = true
				performance {
					raft_multiplier = 22057
				}
				pid_file = "43xN80Km"
				ports {
					dns = 7001,
					http = 7999,
					https = 15127
				}
				protocol = 30793
				raft_protocol = 19016
				reconnect_timeout = "23739s"
				reconnect_timeout_wan = "26694s"
				rejoin_after_leave = true
				retry_interval = "8067s"
				retry_interval_wan = "28866s"
				telemetry {
					circonus_api_app = "p4QOTe9j"
					circonus_api_token = "E3j35V23"
					circonus_api_url = "mEMjHpGg"
					circonus_broker_id = "BHlxUhed"
					circonus_broker_select_tag = "13xy1gHm"
					circonus_check_display_name = "DRSlQR6n"
					circonus_check_force_metric_activation = "Ua5FGVYf"
					circonus_check_id = "kGorutad"
					circonus_check_instance_id = "rwoOL6R4"
					circonus_check_search_tag = "ovT4hT4f"
					circonus_check_tags = "prvO4uBl"
					circonus_submission_interval = "DolzaflP"
					circonus_submission_url = "gTcbS93G"
					disable_hostname = true
					dogstatsd_addr = "0wSndumK"
					dogstatsd_tags = ["3N81zSUB","Xtj8AnXZ"]
					filter_default = true
					prefix_filter = ["oJotS8XJ","cazlEhGn"]
					statsd_address = "drce87cy"
					statsite_address = "HpFwKB8R"
					statsite_prefix = "ftO6DySn"
				}
				verify_incoming = true
				verify_incoming_https = true
				verify_incoming_rpc = true
				verify_outgoing = true
				verify_server_hostname = true
			`},
			rtcfg: RuntimeConfig{
				ACLAgentMasterToken:                         "furuQD0b",
				ACLAgentToken:                               "cOshLOQ2",
				ACLDatacenter:                               "M3uRCk3Z",
				ACLDefaultPolicy:                            "ArK3WIfE",
				ACLDownPolicy:                               "vZXMfMP0",
				ACLEnforceVersion8:                          true,
				ACLMasterToken:                              "C1Q1oIwh",
				ACLReplicationToken:                         "LMmgy5dO",
				ACLTTL:                                      18060 * time.Second,
				ACLToken:                                    "O1El0wan",
				AutopilotCleanupDeadServers:                 true,
				AutopilotDisableUpgradeMigration:            true,
				AutopilotLastContactThreshold:               12705 * time.Second,
				AutopilotMaxTrailingLogs:                    17849,
				AutopilotRedundancyZoneTag:                  "3IsufDJf",
				AutopilotServerStabilizationTime:            23057 * time.Second,
				AutopilotUpgradeVersionTag:                  "W9pDwFAL",
				BindAddrs:                                   []string{"6rFPKyh6"},
				Bootstrap:                                   true,
				BootstrapExpect:                             28094,
				CAFile:                                      "erA7T0PM",
				CAPath:                                      "mQEN1Mfp",
				CertFile:                                    "7s4QAzDk",
				CheckUpdateInterval:                         16507 * time.Second,
				ClientAddr:                                  "e15dFavQ",
				DNSAllowStale:                               true,
				DNSDisableCompression:                       true,
				DNSEnableTruncate:                           true,
				DNSMaxStale:                                 29685 * time.Second,
				DNSNodeTTL:                                  7084 * time.Second,
				DNSOnlyPassing:                              true,
				DNSRecursorTimeout:                          4427 * time.Second,
				DNSServiceTTL:                               map[string]time.Duration{"*": 32030 * time.Second},
				DNSUDPAnswerLimit:                           29909,
				DNSDomain:                                   "7W1xXSqd",
				Datacenter:                                  "rzo029wG",
				DataDir:                                     "oTOOIoV9",
				DevMode:                                     true,
				DisableAnonymousSignature:                   true,
				DisableCoordinates:                          true,
				DisableHostNodeID:                           true,
				DisableKeyringFile:                          true,
				DisableRemoteExec:                           true,
				DisableUpdateCheck:                          true,
				EnableACLReplication:                        true,
				EnableDebug:                                 true,
				EnableScriptChecks:                          true,
				EnableSyslog:                                true,
				EnableUI:                                    true,
				EncryptKey:                                  "A4wELWqH",
				EncryptVerifyIncoming:                       true,
				EncryptVerifyOutgoing:                       true,
				HTTPBlockEndpoints:                          []string{"RBvAFcGD", "fWOWFznh"},
				HTTPResponseHeaders:                         map[string]string{"M6TKa9NP": "xjuxjOzQ", "JRCrHZed": "rl0mTx81"},
				KeyFile:                                     "IEkkwgIA",
				LeaveOnTerm:                                 true,
				LogLevel:                                    "k1zo9Spt",
				NodeID:                                      "AsUIlw99",
				NodeMeta:                                    map[string]string{"5mgGQMBk": "mJLtVMSG"},
				NodeName:                                    "otlLxGaI",
				NonVotingServer:                             true,
				PerformanceRaftMultiplier:                   22057,
				PidFile:                                     "43xN80Km",
				DNSPort:                                     7001,
				HTTPPort:                                    7999,
				HTTPSPort:                                   15127,
				DNSAddrsTCP:                                 []string{"6rFPKyh6:7001"},
				DNSAddrsUDP:                                 []string{"6rFPKyh6:7001"},
				HTTPAddrs:                                   []string{"6rFPKyh6:7999"},
				HTTPSAddrs:                                  []string{"6rFPKyh6:15127"},
				RPCProtocol:                                 30793,
				RaftProtocol:                                19016,
				ReconnectTimeoutLAN:                         23739 * time.Second,
				ReconnectTimeoutWAN:                         26694 * time.Second,
				RejoinAfterLeave:                            true,
				RetryJoinIntervalLAN:                        8067 * time.Second,
				RetryJoinIntervalWAN:                        28866 * time.Second,
				TelemetryCirconusAPIApp:                     "p4QOTe9j",
				TelemetryCirconusAPIToken:                   "E3j35V23",
				TelemetryCirconusAPIURL:                     "mEMjHpGg",
				TelemetryCirconusBrokerID:                   "BHlxUhed",
				TelemetryCirconusBrokerSelectTag:            "13xy1gHm",
				TelemetryCirconusCheckDisplayName:           "DRSlQR6n",
				TelemetryCirconusCheckForceMetricActivation: "Ua5FGVYf",
				TelemetryCirconusCheckID:                    "kGorutad",
				TelemetryCirconusCheckInstanceID:            "rwoOL6R4",
				TelemetryCirconusCheckSearchTag:             "ovT4hT4f",
				TelemetryCirconusCheckTags:                  "prvO4uBl",
				TelemetryCirconusSubmissionInterval:         "DolzaflP",
				TelemetryCirconusSubmissionURL:              "gTcbS93G",
				TelemetryDisableHostname:                    true,
				TelemetryDogStatsdAddr:                      "0wSndumK",
				TelemetryDogStatsdTags:                      []string{"3N81zSUB", "Xtj8AnXZ"},
				TelemetryFilterDefault:                      true,
				TelemetryPrefixFilter:                       []string{"oJotS8XJ", "cazlEhGn"},
				TelemetryStatsdAddr:                         "drce87cy",
				TelemetryStatsiteAddr:                       "HpFwKB8R",
				TelemetryStatsitePrefix:                     "ftO6DySn",
				VerifyIncoming:                              true,
				VerifyIncomingHTTPS:                         true,
				VerifyIncomingRPC:                           true,
				VerifyOutgoing:                              true,
				VerifyServerHostname:                        true,
			},
		},
	}

	for _, tt := range tests {
		for _, format := range []string{"json", "hcl"} {
			if len(tt.json) != len(tt.hcl) {
				t.Fatal("JSON and HCL test case out of sync")
			}

			files := tt.json
			if format == "hcl" {
				files = tt.hcl
			}

			// ugly hack to skip second run for flag-only tests
			if len(files) == 0 && format == "hcl" {
				continue
			}

			var desc []string
			if len(files) > 0 {
				desc = append(desc, format)
			}
			if tt.desc != "" {
				desc = append(desc, tt.desc)
			}

			t.Run(strings.Join(desc, ":"), func(t *testing.T) {
				// start with default config
				cfgs := []Config{tt.def}

				// add files in order
				for _, s := range files {
					f, err := ParseFile(s, format)
					if err != nil {
						t.Fatalf("ParseFile failed for %q: %s", s, err)
					}
					cfgs = append(cfgs, f)
				}

				// add flags
				flags, err := ParseFlags(tt.flags)
				if err != nil {
					t.Fatalf("ParseFlags failed: %s", err)
				}
				cfgs = append(cfgs, flags.Config)

				// merge files and build config
				rtcfg, err := NewRuntimeConfig(Merge(cfgs))
				if err != nil {
					t.Fatalf("NewConfig failed: %s", err)
				}

				if !verify.Values(t, "", rtcfg, tt.rtcfg) {
					t.FailNow()
				}
			})
		}
	}
}
