package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

// GateTask is one checker result.
type GateTask struct {
	Round     int    `json:"round"`
	Method    string `json:"method"`
	Variant   int    `json:"variant"`
	Status    string `json:"status"`
	Message   string `json:"message"`
	LatencyMS int    `json:"latency_ms"`
}

// GateResponse is the full gate API response.
type GateResponse struct {
	OK         bool       `json:"ok"`
	Service    string     `json:"service"`
	DurationMS int        `json:"duration_ms"`
	Verdict    string     `json:"verdict"`
	Tasks      []GateTask `json:"tasks"`
}

// DeployEventResponse is the deploy event response.
type DeployEventResponse struct {
	ID       int `json:"id"`
	FreeLeft int `json:"free_left"`
}

// SLATick is one tick's SLA status.
type SLATick struct {
	Tick        int64  `json:"tick"`
	Status      string `json:"status"`
	Message     string `json:"message"`
	ImageDigest string `json:"image_digest"`
}

type anvilClient struct {
	base  string
	token string
	http  *http.Client
}

func newAnvilClient(cfg *Config) *anvilClient {
	return &anvilClient{
		base:  fmt.Sprintf("%s://%s", cfg.AnvilScheme, cfg.AnvilHost),
		token: cfg.InternalToken,
		http:  &http.Client{Timeout: 150 * time.Second},
	}
}

func (c *anvilClient) do(method, path string, body, out any) (int, error) {
	var br io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		br = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, br)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if out != nil && len(data) > 0 {
		json.Unmarshal(data, out)
	}
	return resp.StatusCode, nil
}

// Gate runs the checker suite against a staging copy.
// For local tests (cfg.GateMock=true) it returns a fake OK.
func (c *anvilClient) gate(cfg *Config, svc, addr string, port int) (*GateResponse, error) {
	if cfg.GateMock {
		return &GateResponse{OK: true, Service: svc, Verdict: "OK", Tasks: []GateTask{
			{Round: 1, Method: "putflag", Variant: 0, Status: "OK"},
			{Round: 1, Method: "getflag", Variant: 0, Status: "OK"},
			{Round: 1, Method: "putnoise", Variant: 0, Status: "OK"},
			{Round: 1, Method: "getnoise", Variant: 0, Status: "OK"},
			{Round: 1, Method: "havoc", Variant: 0, Status: "OK"},
		}}, nil
	}
	var resp GateResponse
	code, err := c.do("POST", "/api/v1/internal/arena/gate", map[string]any{
		"service":   svc,
		"address":   addr,
		"port":      port,
		"rounds":    1,
		"timeout_s": cfg.BuildTimeout,
	}, &resp)
	if err != nil {
		return nil, fmt.Errorf("gate: %w", err)
	}
	if code != 200 {
		return nil, fmt.Errorf("gate: HTTP %d", code)
	}
	return &resp, nil
}

// reportDeploy sends a deploy event to Anvil.
func (c *anvilClient) reportDeploy(cfg *Config, svc, kind, digest string) (*DeployEventResponse, error) {
	return c.reportDeployFull(cfg, svc, kind, digest, 0, 0, 0)
}

// reportDeployFull sends a deploy event with diff stats.
func (c *anvilClient) reportDeployFull(cfg *Config, svc, kind, digest string, diffFiles, diffLines int, diffBytes int64) (*DeployEventResponse, error) {
	if cfg.GateMock || cfg.InternalToken == "" {
		return &DeployEventResponse{FreeLeft: cfg.FreeDeploys}, nil
	}
	payload := map[string]any{
		"team_id":      cfg.TeamID,
		"service":      svc,
		"kind":         kind,
		"image_digest": digest,
		"at":           time.Now().UTC().Format(time.RFC3339),
	}
	if diffFiles > 0 {
		payload["diff_files"] = diffFiles
		payload["diff_lines"] = diffLines
		payload["diff_bytes"] = diffBytes
	}
	var resp DeployEventResponse
	_, err := c.do("POST", "/api/v1/internal/arena/deploys", payload, &resp)
	return &resp, err
}

// slaHistory returns the N most recent SLA ticks for auto-revert.
func (c *anvilClient) slaHistory(cfg *Config, svc string, sinceTick int64) ([]SLATick, error) {
	if cfg.GateMock || cfg.InternalToken == "" {
		return nil, nil
	}
	u, _ := url.Parse(c.base + "/api/v1/internal/arena/sla")
	q := u.Query()
	q.Set("team_id", cfg.TeamID)
	q.Set("service", svc)
	q.Set("since", fmt.Sprint(sinceTick))
	u.RawQuery = q.Encode()
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var ticks []SLATick
	json.NewDecoder(resp.Body).Decode(&ticks)
	return ticks, nil
}

// TickInfo is one game tick from the public arena/tick endpoint.
type TickInfo struct {
	Tick      int64     `json:"tick"`
	StartedAt time.Time `json:"started_at"`
	EndsAt    time.Time `json:"ends_at"`
	HoldFrom  time.Time `json:"hold_from"`
}

// currentTick fetches the current tick from GET /api/v1/arena/tick (public, no auth).
func (c *anvilClient) currentTick() (*TickInfo, error) {
	req, err := http.NewRequest("GET", c.base+"/api/v1/arena/tick", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var t TickInfo
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

// waitForQuietWindow polls the tick API and blocks until the promote window
// (hold_from <= now < ends_at). Returns the confirmed tick number.
// In mock/local mode falls back to the local-clock quiet window.
func (c *anvilClient) waitForQuietWindow(cfg *Config) int64 {
	if cfg.GateMock || cfg.InternalToken == "" {
		waitQuietWindow(cfg)
		return tickNumber(cfg)
	}
	for {
		ti, err := c.currentTick()
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		now := time.Now()
		if now.Before(ti.HoldFrom) {
			time.Sleep(ti.HoldFrom.Sub(now) + time.Duration(rand.Intn(2))*time.Second)
			continue
		}
		if now.Before(ti.EndsAt) {
			return ti.Tick
		}
		// past ends_at — tick rolled over, re-poll
		time.Sleep(2 * time.Second)
	}
}

// boxMode reads the global fallback-A mode from Anvil.
func (c *anvilClient) boxMode(cfg *Config) (string, error) {
	if cfg.GateMock || cfg.InternalToken == "" {
		return "pipeline", nil
	}
	var out struct {
		Mode string `json:"mode"`
	}
	code, err := c.do("GET", "/api/v1/internal/arena/mode", nil, &out)
	if err != nil {
		return "", err
	}
	if code != 200 {
		return "pipeline", nil
	}
	if out.Mode == "" {
		return "pipeline", nil
	}
	return out.Mode, nil
}
