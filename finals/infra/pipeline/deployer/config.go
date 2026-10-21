package main

import (
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Team     int
	TeamID   string // uuid for Anvil API

	// server addresses
	WebhookAddr string // :9000
	APIAddr     string // :9300

	// paths
	StateFile      string
	RepoPath       string // git repo the team pushes to (bare clone on prod)
	ServiceRoot    string // /opt/h7/<service>
	ComposeProject string // "prod"

	// engine timings
	EventStart   time.Time
	TickS        int // 120
	QuietOffsetS int // 110 (promote in last 10s)

	// build
	BuilderName    string // h7cap
	BuildTimeout   int    // 300s
	StagingPortBase int   // 40000
	MaxContextMB   int    // 50

	// gate / Anvil
	AnvilHost     string // 10.60.200.10
	AnvilScheme   string // http
	InternalToken string // game.internal_token
	GateMock      bool   // GATE_MOCK=1 for local tests

	// secrets
	WebhookSecret  string
	DeployKeyPath  string
	OrgBuildKey    string // HMAC key for build secret
	BoxToken       string // for team API auth

	// archive registry
	ArchiveRegistry string // 10.60.202.10:5001
	ArchiveUser     string
	ArchivePass     string

	// pricing
	FreeDeploys int // 3

	// auto-revert
	MaxConsecFail int // 2

	// fallback
	ModeCheckInterval int // seconds, 30
}

func mustLoadConfig() *Config {
	loadEnvFile("/etc/h7/box.env")
	loadEnvFile("/etc/h7/secrets.env")

	cfg := &Config{
		Team:              envInt("TEAM", 0),
		TeamID:            env("TEAM_ID", ""),
		WebhookAddr:       env("H7D_WEBHOOK_ADDR", ":9000"),
		APIAddr:           env("H7D_API_ADDR", ":9300"),
		StateFile:         env("H7D_STATE", "/var/lib/h7d/state.json"),
		RepoPath:          env("H7D_REPO", "/srv/git/services.git"),
		ServiceRoot:       env("H7D_SVC_ROOT", "/opt/h7"),
		ComposeProject:    env("H7D_PROJECT", "prod"),
		TickS:             envInt("TICK_S", 120),
		QuietOffsetS:      envInt("QUIET_OFFSET_S", 110),
		BuilderName:       env("H7D_BUILDER", "h7cap"),
		BuildTimeout:      envInt("BUILD_TIMEOUT_S", 300),
		StagingPortBase:   envInt("STAGING_PORT_BASE", 40000),
		MaxContextMB:      envInt("MAX_CONTEXT_MB", 50),
		AnvilHost:         env("ANVIL_HOST", "10.60.200.10"),
		AnvilScheme:       env("ANVIL_SCHEME", "http"),
		InternalToken:     env("ANVIL_GAME_INTERNAL_TOKEN", ""),
		GateMock:          env("GATE_MOCK", "") == "1",
		WebhookSecret:     env("WEBHOOK_SECRET", ""),
		DeployKeyPath:     env("DEPLOY_KEY_PATH", "/etc/h7/deploy_key"),
		OrgBuildKey:       env("ORG_BUILD_KEY", ""),
		BoxToken:          env("BOX_TOKEN", ""),
		ArchiveRegistry:   env("ARCHIVE_REGISTRY", "10.60.202.10:5001"),
		ArchiveUser:       env("ARCHIVE_USER", ""),
		ArchivePass:       env("ARCHIVE_PASS", ""),
		FreeDeploys:       envInt("FREE_DEPLOYS", 3),
		MaxConsecFail:     envInt("MAX_CONSEC_FAIL", 2),
		ModeCheckInterval: envInt("MODE_CHECK_INTERVAL_S", 30),
	}

	if s := env("EVENT_START", ""); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			log.Fatalf("bad EVENT_START %q: %v", s, err)
		}
		cfg.EventStart = t
	}

	if cfg.Team == 0 {
		log.Printf("warning: TEAM not set, some features disabled")
	}
	return cfg
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return def
}

func loadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // optional
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}
}
