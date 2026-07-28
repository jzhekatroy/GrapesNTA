package main

import (
	"flag"
	"os"
	"strconv"
	"strings"
	"time"

	"xdpflowd/internal/flowingest"
)

type config struct {
	SFlowEnabled bool
	SFlowListen  string
	SFlowSourceID string

	CHDSN              string
	CHTable            string
	CHBatchSize        int
	CHFlushInterval    time.Duration
	CHQueueSize        int
	CHSpoolMode        flowingest.SpoolMode
	CHSpoolDir         string
	CHSpoolSegSize     int64
	CHSpoolMaxBytes    int64
	CHSpoolFrameMaxRows int
	CHSpoolFsyncEvery  time.Duration
	CHSpoolShutdownDrain time.Duration
	CHSpoolStallThreshold time.Duration
	CHWriters          int

	ClassifierEnabled bool
	ClassifierRefresh time.Duration
	ClassifierBGPTable string
	ClassifierIPASNTable string
	ClassifierL3PrefixesView string
	ClassifierL2VLANsView string
	ClassifierDirectionSettingsView string
	ClassifierInterfaceRolesView string

	UDPReadBuffer int
	UDPReaders    int
	UDPWorkers    int
	UDPQueueSize  int
	Interval      time.Duration
	HealthInterval time.Duration
	CHHealthTable string
	CollectorID   string
}

func loadConfig() config {
	sflowEnabled := flag.Bool("sflow-enabled", envBool("FC_SFLOW_ENABLED", true), "enable sFlow v5 UDP listener")
	sflowListen := flag.String("sflow-listen", envString("FC_SFLOW_LISTEN", "0.0.0.0:6343"), "sFlow v5 UDP listen address")
	sflowSourceID := flag.String("sflow-source-id", envString("FC_SFLOW_SOURCE_ID", "sflow-default"), "source_id written to flows_raw")

	chDSN := flag.String("ch-dsn", envString("FC_CH_DSN", ""), "ClickHouse DSN")
	chTable := flag.String("ch-table", envString("FC_CH_TABLE", "default.flows_raw"), "target flows_raw table")
	chBatchSize := flag.Int("ch-batch-size", envInt("FC_CH_BATCH_SIZE", 5000), "ClickHouse batch size")
	chFlush := flag.Duration("ch-flush-interval", envDuration("FC_CH_FLUSH_INTERVAL", time.Second), "ClickHouse flush interval")
	chQueue := flag.Int("ch-queue-size", envInt("FC_CH_QUEUE_SIZE", 64), "ClickHouse queue depth")
	chSpoolModeFlag := flag.String("ch-spool-mode", envString("FC_CH_SPOOL_MODE", "required"), "spool mode: off|on|required")
	chSpoolDir := flag.String("ch-spool-dir", envString("FC_CH_SPOOL_DIR", "/var/lib/flowcollectord/ch-spool"), "spool directory")
	chSpoolSegSize := flag.Int64("ch-spool-segment-size", envInt64("FC_CH_SPOOL_SEGMENT_SIZE", 256*1024*1024), "spool segment size")
	chSpoolMaxBytes := flag.Int64("ch-spool-max-bytes", envInt64("FC_CH_SPOOL_MAX_BYTES", 0), "max total spool bytes")
	chSpoolFrameMax := flag.Int("ch-spool-frame-max-records", envInt("FC_CH_SPOOL_FRAME_MAX_RECORDS", 50_000), "max rows per spool frame")
	chSpoolFsync := flag.Duration("ch-spool-fsync-interval", envDuration("FC_CH_SPOOL_FSYNC_INTERVAL", time.Second), "spool fsync interval")
	chSpoolShutdownDrain := flag.Duration("ch-spool-shutdown-drain", envDuration("FC_CH_SPOOL_SHUTDOWN_DRAIN", 300*time.Second), "shutdown drain timeout")
	chSpoolStallThreshold := flag.Duration("ch-spool-stall-threshold", envDuration("FC_CH_SPOOL_STALL_THRESHOLD", 60*time.Second), "drainer stall threshold")
	chWriters := flag.Int("ch-writers", envInt("FC_CH_WRITERS", 4), "parallel spool writers")

	classifierEnabled := flag.Bool("classifier", envBool("FC_CLASSIFIER", true), "enable traffic classifier")
	classifierRefresh := flag.Duration("classifier-refresh", envDuration("FC_CLASSIFIER_REFRESH", time.Minute), "classifier refresh interval")
	classifierBGP := flag.String("classifier-bgp-table", envString("FC_CLASSIFIER_BGP_TABLE", "default.bgp_prefix_origin_current"), "BGP origin table")
	classifierIPASN := flag.String("classifier-ip-asn-table", envString("FC_CLASSIFIER_IP_ASN_TABLE", ""), "optional fallback IP prefix -> ASN table (e.g. default.ip_asn_prefixes_current)")
	classifierL3 := flag.String("classifier-l3-prefixes-view", envString("FC_CLASSIFIER_L3_PREFIXES_VIEW", "default.net_l3_prefixes_enabled"), "L3 prefixes view")
	classifierL2 := flag.String("classifier-l2-vlans-view", envString("FC_CLASSIFIER_L2_VLANS_VIEW", "default.net_l2_vlans_enabled"), "L2 VLANs view")
	classifierDirectionSettings := flag.String("classifier-direction-settings-view", envString("FC_CLASSIFIER_DIRECTION_SETTINGS_VIEW", "default.net_direction_settings_current"), "direction mode settings view (empty = always derive direction from prefixes)")
	classifierInterfaceRoles := flag.String("classifier-interface-roles-view", envString("FC_CLASSIFIER_INTERFACE_ROLES_VIEW", "default.net_interface_roles_effective_current"), "effective port sides view for direction mode ports (empty = disabled)")

	udpReadBuffer := flag.Int("udp-read-buffer", envInt("FC_UDP_READ_BUFFER", 64*1024*1024), "kernel UDP socket receive buffer bytes (SO_RCVBUF, per reader)")
	udpReaders := flag.Int("udp-readers", envInt("FC_UDP_READERS", 1), "parallel sFlow UDP sockets using SO_REUSEPORT")
	udpWorkers := flag.Int("udp-workers", envInt("FC_UDP_WORKERS", 8), "sFlow parser worker count")
	udpQueueSize := flag.Int("udp-queue-size", envInt("FC_UDP_QUEUE_SIZE", 65536), "sFlow datagram queue depth")
	interval := flag.Duration("interval", envDuration("FC_INTERVAL", 5*time.Second), "metrics log interval")
	healthInterval := flag.Duration("health-interval", envDuration("FC_HEALTH_INTERVAL", time.Minute), "health log interval")
	chHealthTable := flag.String("ch-health-table", envString("FC_CH_HEALTH_TABLE", flowingest.DefaultHealthTable), "ClickHouse table for health snapshots (empty = disabled)")
	collectorID := flag.String("collector-id", envString("FC_COLLECTOR_ID", ""), "collector_id for health snapshots")

	flag.Parse()

	spoolMode, err := flowingest.ParseSpoolMode(*chSpoolModeFlag)
	if err != nil {
		panic(err)
	}

	return config{
		SFlowEnabled: *sflowEnabled,
		SFlowListen:  strings.TrimSpace(*sflowListen),
		SFlowSourceID: strings.TrimSpace(*sflowSourceID),
		CHDSN: strings.TrimSpace(*chDSN),
		CHTable: strings.TrimSpace(*chTable),
		CHBatchSize: *chBatchSize,
		CHFlushInterval: *chFlush,
		CHQueueSize: *chQueue,
		CHSpoolMode: spoolMode,
		CHSpoolDir: strings.TrimSpace(*chSpoolDir),
		CHSpoolSegSize: *chSpoolSegSize,
		CHSpoolMaxBytes: *chSpoolMaxBytes,
		CHSpoolFrameMaxRows: *chSpoolFrameMax,
		CHSpoolFsyncEvery: *chSpoolFsync,
		CHSpoolShutdownDrain: *chSpoolShutdownDrain,
		CHSpoolStallThreshold: *chSpoolStallThreshold,
		CHWriters: *chWriters,
		ClassifierEnabled: *classifierEnabled,
		ClassifierRefresh: *classifierRefresh,
		ClassifierBGPTable: strings.TrimSpace(*classifierBGP),
		ClassifierIPASNTable: strings.TrimSpace(*classifierIPASN),
		ClassifierL3PrefixesView: strings.TrimSpace(*classifierL3),
		ClassifierL2VLANsView: strings.TrimSpace(*classifierL2),
		ClassifierDirectionSettingsView: strings.TrimSpace(*classifierDirectionSettings),
		ClassifierInterfaceRolesView: strings.TrimSpace(*classifierInterfaceRoles),
		UDPReadBuffer: *udpReadBuffer,
		UDPReaders: *udpReaders,
		UDPWorkers: *udpWorkers,
		UDPQueueSize: *udpQueueSize,
		Interval: *interval,
		HealthInterval: *healthInterval,
		CHHealthTable: strings.TrimSpace(*chHealthTable),
		CollectorID: strings.TrimSpace(*collectorID),
	}
}

func envString(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envInt64(key string, def int64) int64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
