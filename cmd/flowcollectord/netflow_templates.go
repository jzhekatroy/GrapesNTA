package main

import (
	"sync"
	"time"
)

type nfTemplateKey struct {
	exporter [16]byte
	domain   uint32
	id       uint16
}

type nfSamplerKey struct {
	exporter [16]byte
	domain   uint32
	sampler  uint32
}

type nfField struct {
	Type   uint16
	Length uint16
}

type nfDataTemplate struct {
	fields    []nfField
	recordLen int
	updated   time.Time
}

type nfOptionTemplate struct {
	scopes    []nfField
	options   []nfField
	recordLen int
	updated   time.Time
}

type nfTemplateStore struct {
	mu  sync.RWMutex
	ttl time.Duration

	data    map[nfTemplateKey]nfDataTemplate
	option  map[nfTemplateKey]nfOptionTemplate
	rates   map[nfSamplerKey]uint64
	rateAt  map[nfSamplerKey]time.Time
}

func newNFTemplateStore(ttl time.Duration) *nfTemplateStore {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &nfTemplateStore{
		ttl:    ttl,
		data:   make(map[nfTemplateKey]nfDataTemplate),
		option: make(map[nfTemplateKey]nfOptionTemplate),
		rates:  make(map[nfSamplerKey]uint64),
		rateAt: make(map[nfSamplerKey]time.Time),
	}
}

func (s *nfTemplateStore) putData(key nfTemplateKey, fields []nfField, now time.Time) {
	recLen := 0
	for _, f := range fields {
		recLen += int(f.Length)
	}
	copied := append([]nfField(nil), fields...)
	s.mu.Lock()
	s.data[key] = nfDataTemplate{fields: copied, recordLen: recLen, updated: now}
	s.mu.Unlock()
}

func (s *nfTemplateStore) putOption(key nfTemplateKey, scopes, options []nfField, now time.Time) {
	recLen := 0
	for _, f := range scopes {
		recLen += int(f.Length)
	}
	for _, f := range options {
		recLen += int(f.Length)
	}
	s.mu.Lock()
	s.option[key] = nfOptionTemplate{
		scopes:    append([]nfField(nil), scopes...),
		options:   append([]nfField(nil), options...),
		recordLen: recLen,
		updated:   now,
	}
	s.mu.Unlock()
}

func (s *nfTemplateStore) putRate(key nfSamplerKey, rate uint64, now time.Time) {
	if rate == 0 {
		return
	}
	s.mu.Lock()
	s.rates[key] = rate
	s.rateAt[key] = now
	s.mu.Unlock()
}

func (s *nfTemplateStore) dataTemplate(key nfTemplateKey, now time.Time) (nfDataTemplate, bool) {
	s.mu.RLock()
	t, ok := s.data[key]
	s.mu.RUnlock()
	if !ok || now.Sub(t.updated) > s.ttl {
		return nfDataTemplate{}, false
	}
	return t, true
}

func (s *nfTemplateStore) optionTemplate(key nfTemplateKey, now time.Time) (nfOptionTemplate, bool) {
	s.mu.RLock()
	t, ok := s.option[key]
	s.mu.RUnlock()
	if !ok || now.Sub(t.updated) > s.ttl {
		return nfOptionTemplate{}, false
	}
	return t, true
}

func (s *nfTemplateStore) rate(exporter [16]byte, domain, sampler uint32, now time.Time) (uint64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	try := func(id uint32) (uint64, bool) {
		k := nfSamplerKey{exporter: exporter, domain: domain, sampler: id}
		rate, ok := s.rates[k]
		if !ok {
			return 0, false
		}
		if now.Sub(s.rateAt[k]) > s.ttl {
			return 0, false
		}
		return rate, true
	}
	if rate, ok := try(sampler); ok {
		return rate, true
	}
	if sampler != 0 {
		return try(0)
	}
	return 0, false
}

func (s *nfTemplateStore) dataCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data)
}
