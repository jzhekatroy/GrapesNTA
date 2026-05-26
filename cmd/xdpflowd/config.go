package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// xdpflowdConfig is intentionally flat: keys mirror CLI flags so production
// wrappers can move from long env/argv lines to one reviewed file.
type xdpflowdConfig struct {
	BPF              *string `yaml:"bpf"`
	Iface            *string `yaml:"iface"`
	Mode             *string `yaml:"mode"`
	XDPAction        *string `yaml:"xdp_action"`
	DNSPassthrough   *bool   `yaml:"dns_passthrough"`
	Top              *int    `yaml:"top"`
	TopInterval      *string `yaml:"top_interval"`
	Interval         *string `yaml:"interval"`
	JSONOut          *string `yaml:"json_out"`
	JSONInterval     *string `yaml:"json_interval"`
	JSONIncludeFlows *bool   `yaml:"json_include_flows"`
	Once             *bool   `yaml:"once"`

	NFDst              *string `yaml:"nf_dst"`
	NFActive           *string `yaml:"nf_active"`
	NFIdle             *string `yaml:"nf_idle"`
	NFTemplateInterval *string `yaml:"nf_template_interval"`
	NFScan             *string `yaml:"nf_scan"`
	NFSourceID         *int    `yaml:"nf_source_id"`
	HeavyExport        *bool   `yaml:"heavy_export"`

	CHDSN                *string `yaml:"ch_dsn"`
	CHTable              *string `yaml:"ch_table"`
	CHBatchSize          *int    `yaml:"ch_batch_size"`
	CHFlushInterval      *string `yaml:"ch_flush_interval"`
	CHQueueSize          *int    `yaml:"ch_queue_size"`
	CHSamplerAddr        *string `yaml:"ch_sampler_addr"`
	CHSpoolMode          *string `yaml:"ch_spool_mode"`
	CHSpoolDir           *string `yaml:"ch_spool_dir"`
	CHSpoolSegmentSize   *int64  `yaml:"ch_spool_segment_size"`
	CHSpoolMaxBytes      *int64  `yaml:"ch_spool_max_bytes"`
	CHSpoolFrameMaxRows  *int    `yaml:"ch_spool_frame_max_records"`
	CHSpoolFsyncInterval *string `yaml:"ch_spool_fsync_interval"`
	CHSpoolShutdownDrain *string `yaml:"ch_spool_shutdown_drain"`
	CHWriters            *int    `yaml:"ch_writers"`

	Classifier             *bool   `yaml:"classifier"`
	ClassifierRefresh      *string `yaml:"classifier_refresh"`
	ClassifierBGPTable     *string `yaml:"classifier_bgp_table"`
	ClassifierL3PrefixesView *string `yaml:"classifier_l3_prefixes_view"`
	ClassifierL2VLANsView  *string `yaml:"classifier_l2_vlans_view"`
}

func loadXDPFlowdConfig(path string) (*xdpflowdConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg xdpflowdConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func applyXDPFlowdConfig(fs *flag.FlagSet, cfg *xdpflowdConfig) error {
	if cfg == nil {
		return nil
	}
	wasSet := map[string]bool{}
	fs.Visit(func(f *flag.Flag) {
		wasSet[f.Name] = true
	})
	setIfUnset := func(name, value string) error {
		if wasSet[name] {
			return nil
		}
		if err := fs.Set(name, value); err != nil {
			return fmt.Errorf("config %s: %w", name, err)
		}
		return nil
	}
	setString := func(name string, v *string) error {
		if v == nil {
			return nil
		}
		return setIfUnset(name, *v)
	}
	setBool := func(name string, v *bool) error {
		if v == nil {
			return nil
		}
		return setIfUnset(name, strconv.FormatBool(*v))
	}
	setInt := func(name string, v *int) error {
		if v == nil {
			return nil
		}
		return setIfUnset(name, strconv.Itoa(*v))
	}
	setInt64 := func(name string, v *int64) error {
		if v == nil {
			return nil
		}
		return setIfUnset(name, strconv.FormatInt(*v, 10))
	}

	for _, apply := range []func() error{
		func() error { return setString("bpf", cfg.BPF) },
		func() error { return setString("iface", cfg.Iface) },
		func() error { return setString("mode", cfg.Mode) },
		func() error { return setString("xdp-action", cfg.XDPAction) },
		func() error { return setBool("dns-passthrough", cfg.DNSPassthrough) },
		func() error { return setInt("top", cfg.Top) },
		func() error { return setString("top-interval", cfg.TopInterval) },
		func() error { return setString("interval", cfg.Interval) },
		func() error { return setString("json-out", cfg.JSONOut) },
		func() error { return setString("json-interval", cfg.JSONInterval) },
		func() error { return setBool("json-include-flows", cfg.JSONIncludeFlows) },
		func() error { return setBool("once", cfg.Once) },
		func() error { return setString("nf-dst", cfg.NFDst) },
		func() error { return setString("nf-active", cfg.NFActive) },
		func() error { return setString("nf-idle", cfg.NFIdle) },
		func() error { return setString("nf-template-interval", cfg.NFTemplateInterval) },
		func() error { return setString("nf-scan", cfg.NFScan) },
		func() error { return setInt("nf-source-id", cfg.NFSourceID) },
		func() error { return setBool("heavy-export", cfg.HeavyExport) },
		func() error { return setString("ch-dsn", cfg.CHDSN) },
		func() error { return setString("ch-table", cfg.CHTable) },
		func() error { return setInt("ch-batch-size", cfg.CHBatchSize) },
		func() error { return setString("ch-flush-interval", cfg.CHFlushInterval) },
		func() error { return setInt("ch-queue-size", cfg.CHQueueSize) },
		func() error { return setString("ch-sampler-addr", cfg.CHSamplerAddr) },
		func() error { return setString("ch-spool-mode", cfg.CHSpoolMode) },
		func() error { return setString("ch-spool-dir", cfg.CHSpoolDir) },
		func() error { return setInt64("ch-spool-segment-size", cfg.CHSpoolSegmentSize) },
		func() error { return setInt64("ch-spool-max-bytes", cfg.CHSpoolMaxBytes) },
		func() error { return setInt("ch-spool-frame-max-records", cfg.CHSpoolFrameMaxRows) },
		func() error { return setString("ch-spool-fsync-interval", cfg.CHSpoolFsyncInterval) },
		func() error { return setString("ch-spool-shutdown-drain", cfg.CHSpoolShutdownDrain) },
		func() error { return setInt("ch-writers", cfg.CHWriters) },
		func() error { return setBool("classifier", cfg.Classifier) },
		func() error { return setString("classifier-refresh", cfg.ClassifierRefresh) },
		func() error { return setString("classifier-bgp-table", cfg.ClassifierBGPTable) },
		func() error { return setString("classifier-l3-prefixes-view", cfg.ClassifierL3PrefixesView) },
		func() error { return setString("classifier-l2-vlans-view", cfg.ClassifierL2VLANsView) },
	} {
		if err := apply(); err != nil {
			return err
		}
	}
	return nil
}
