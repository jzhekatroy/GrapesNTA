//go:build linux

package main

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// rawShedController pauses raw dns_log enqueue when answers writer lag is high.
type rawShedController struct {
	log *slog.Logger

	enabled              bool
	shedThreshold        uint64
	recoverThreshold     uint64
	recoverCooldown      time.Duration
	rawConfiguredEnabled bool

	mu               sync.Mutex
	active           bool
	lowLagSince      time.Time
	rawShedDueLag    atomic.Uint64
	lastShedWarn     time.Time
	lastRecoverWarn  time.Time
}

func newRawShedController(log *slog.Logger, enabled bool, rawConfiguredEnabled bool, shedThreshold, recoverThreshold uint64, recoverCooldown time.Duration) *rawShedController {
	if recoverThreshold == 0 && shedThreshold > 0 {
		recoverThreshold = shedThreshold / 2
	}
	if recoverCooldown <= 0 {
		recoverCooldown = 2 * time.Minute
	}
	return &rawShedController{
		log:                  log,
		enabled:              enabled && rawConfiguredEnabled,
		shedThreshold:        shedThreshold,
		recoverThreshold:     recoverThreshold,
		recoverCooldown:      recoverCooldown,
		rawConfiguredEnabled: rawConfiguredEnabled,
	}
}

func (c *rawShedController) Update(answersLag uint64, answersQueueDepth int) {
	if c == nil || !c.enabled {
		return
	}
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.active {
		if answersLag >= c.shedThreshold {
			c.active = true
			c.lowLagSince = time.Time{}
			if now.Sub(c.lastShedWarn) >= time.Second {
				c.lastShedWarn = now
				c.log.Warn("dnsflowd raw shed to protect answers",
					"answers_writer_lag_rows", answersLag,
					"answers_queue_depth_batches", answersQueueDepth,
					"shed_threshold", c.shedThreshold,
					"raw_shed_due_answers_lag_total", c.rawShedDueLag.Load(),
					"raw_policy", "best_effort_shed_active",
				)
			}
		}
		return
	}

	if answersLag <= c.recoverThreshold {
		if c.lowLagSince.IsZero() {
			c.lowLagSince = now
		} else if now.Sub(c.lowLagSince) >= c.recoverCooldown {
			c.active = false
			c.lowLagSince = time.Time{}
			if now.Sub(c.lastRecoverWarn) >= time.Second {
				c.lastRecoverWarn = now
				c.log.Warn("dnsflowd raw shed recovered",
					"answers_writer_lag_rows", answersLag,
					"recover_threshold", c.recoverThreshold,
					"recover_cooldown", c.recoverCooldown,
					"raw_policy", "best_effort",
				)
			}
		}
	} else {
		c.lowLagSince = time.Time{}
	}
}

func (c *rawShedController) ShouldEnqueueRaw() bool {
	if c == nil || !c.rawConfiguredEnabled {
		return false
	}
	if !c.enabled {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.active
}

func (c *rawShedController) RecordShed(n uint64) {
	if c == nil || n == 0 {
		return
	}
	c.rawShedDueLag.Add(n)
}

func (c *rawShedController) ShedActive() bool {
	if c == nil || !c.enabled {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

func (c *rawShedController) ShedTotal() uint64 {
	if c == nil {
		return 0
	}
	return c.rawShedDueLag.Load()
}

func (c *rawShedController) RawPolicyLabel() string {
	if c == nil || !c.rawConfiguredEnabled {
		return "disabled"
	}
	if c.ShedActive() {
		return "best_effort_shed_active"
	}
	return "best_effort"
}
