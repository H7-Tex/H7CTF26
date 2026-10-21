package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type ServiceState struct {
	SHA        string `json:"sha"`
	PrevSHA    string `json:"prev_sha"`
	OrigSHA    string `json:"orig_sha"`
	Digest     string `json:"digest"`
	PrevDigest string `json:"prev_digest"`
	Deploys    int    `json:"deploys"`
	LastTick   int64  `json:"last_tick"`
	ConsecFail int    `json:"consec_fail"`
	PromotedAt int64  `json:"promoted_at"`
	Mode       string `json:"mode"`
}

type State struct {
	Services map[string]*ServiceState `json:"services"`
	path     string
	mu       sync.Mutex
}

func mustLoadState(path string) *State {
	st := &State{
		Services: make(map[string]*ServiceState),
		path:     path,
	}
	data, err := os.ReadFile(path)
	if err == nil {
		if err2 := json.Unmarshal(data, st); err2 != nil {
			log.Printf("warn: corrupt state %s: %v (starting fresh)", path, err2)
			st.Services = make(map[string]*ServiceState)
		}
	}
	return st
}

// svc returns the ServiceState for a service (creates if missing). Caller must NOT hold mu.
func (st *State) svc(name string) *ServiceState {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.svcLocked(name)
}

// svcLocked returns the ServiceState. Caller must hold mu.
func (st *State) svcLocked(name string) *ServiceState {
	if s, ok := st.Services[name]; ok {
		return s
	}
	s := &ServiceState{Mode: "pipeline"}
	st.Services[name] = s
	return s
}

func (st *State) flush() {
	st.mu.Lock()
	defer st.mu.Unlock()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		log.Printf("state marshal: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(st.path), 0755); err != nil {
		log.Printf("state mkdir: %v", err)
		return
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("state write: %v", err)
		return
	}
	os.Rename(tmp, st.path)
}

func (st *State) recordPromote(svc, sha12, digest string, tick int64) {
	st.mu.Lock()
	s := st.svcLocked(svc)
	s.PrevSHA = s.SHA
	s.PrevDigest = s.Digest
	s.SHA = sha12
	s.Digest = digest
	s.Deploys++
	s.LastTick = tick
	s.ConsecFail = 0
	s.PromotedAt = time.Now().Unix()
	st.mu.Unlock()
	st.flush()
}

func (st *State) recordRollback(svc, target, digest string) {
	st.mu.Lock()
	s := st.svcLocked(svc)
	prevSHA := s.PrevSHA
	s.PrevSHA = s.SHA
	s.PrevDigest = s.Digest
	if target == "prev" {
		s.SHA = prevSHA
	} else {
		s.SHA = s.OrigSHA
	}
	s.Digest = digest
	s.ConsecFail = 0
	st.mu.Unlock()
	st.flush()
}

func (st *State) recordOrigSHA(svc, sha12, digest string) {
	st.mu.Lock()
	s := st.svcLocked(svc)
	if s.OrigSHA == "" {
		s.OrigSHA = sha12
		s.SHA = sha12
		s.Digest = digest
	}
	st.mu.Unlock()
	st.flush()
}

func (st *State) setMode(svc, mode string) {
	st.mu.Lock()
	st.svcLocked(svc).Mode = mode
	st.mu.Unlock()
	st.flush()
}
