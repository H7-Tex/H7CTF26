package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// pending holds the latest commit SHA waiting to be built per service.
type pending struct {
	mu    sync.Mutex
	items map[string]string
	wake  chan struct{}
}

var pq = &pending{
	items: make(map[string]string),
	wake:  make(chan struct{}, 1),
}

func (p *pending) enqueue(svc, sha string) {
	p.mu.Lock()
	p.items[svc] = sha
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *pending) pop() map[string]string {
	p.mu.Lock()
	out := p.items
	p.items = make(map[string]string)
	p.mu.Unlock()
	return out
}

// buildLock serializes builds (one at a time per box).
var buildLock sync.Mutex

func tickNumber(cfg *Config) int64 {
	if cfg.EventStart.IsZero() || cfg.TickS == 0 {
		return 0
	}
	return int64(time.Since(cfg.EventStart).Seconds()) / int64(cfg.TickS)
}

// waitQuietWindow sleeps until we are in the last QuietOffsetS..TickS seconds of the tick.
func waitQuietWindow(cfg *Config) {
	if cfg.EventStart.IsZero() || cfg.TickS == 0 {
		return
	}
	for {
		offset := int(time.Since(cfg.EventStart).Seconds()) % cfg.TickS
		if offset >= cfg.QuietOffsetS {
			return
		}
		wait := cfg.QuietOffsetS - offset + rand.Intn(2)
		time.Sleep(time.Duration(wait) * time.Second)
	}
}

// buildSecret computes HMAC-SHA256(orgBuildKey, svc:sha12:team) → 32 hex chars.
func buildSecret(cfg *Config, svc, sha12 string) string {
	if cfg.OrgBuildKey == "" {
		return "00000000000000000000000000000000" // dev placeholder
	}
	mac := hmac.New(sha256.New, []byte(cfg.OrgBuildKey))
	mac.Write([]byte(fmt.Sprintf("%s:%s:%d", svc, sha12, cfg.Team)))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// gateYML is the parsed gate.yml for a service.
type gateYML struct {
	Service    string
	Port       int
	FlagStores int
	Patchable  []string
	Secrets    []string
}

func loadGateYML(serviceRoot, svc string) (*gateYML, error) {
	path := filepath.Join(serviceRoot, svc, "gate.yml")
	return parseGateYML(path)
}

// changedServices returns top-level dirs (services) that differ between two commits.
func changedServices(repoPath, fromSHA, toSHA string) ([]string, error) {
	var out string
	var err error
	if fromSHA != "" {
		out, err = run("git", "-C", repoPath, "diff", "--name-only", fromSHA, toSHA)
	} else {
		out, err = run("git", "-C", repoPath, "ls-tree", "--name-only", toSHA)
	}
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "/", 2)
		if len(parts) > 0 && parts[0] != "" && parts[0] != ".h7" {
			seen[parts[0]] = struct{}{}
		}
	}
	var svcs []string
	for s := range seen {
		svcs = append(svcs, s)
	}
	return svcs, nil
}

// diffStats returns (files_changed, lines_added+deleted, bytes_changed) for svc/ between two SHAs.
func diffStats(repoPath, svc, fromSHA, toSHA string) (int, int, int64) {
	if fromSHA == "" {
		return 0, 0, 0
	}
	out, _ := run("git", "-C", repoPath, "diff", "--numstat", fromSHA, toSHA, "--", svc+"/")
	files, lines := 0, 0
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) < 2 {
			continue
		}
		files++
		var a, d int
		fmt.Sscan(parts[0], &a)
		fmt.Sscan(parts[1], &d)
		lines += a + d
	}
	// bytes: rough via git diff --stat
	out2, _ := run("git", "-C", repoPath, "diff", "--stat", fromSHA, toSHA, "--", svc+"/")
	var diffBytes int64
	fmt.Sscan(strings.TrimSpace(out2), &diffBytes) // first token is not bytes; skip precise calc
	return files, lines, 0 // bytes not trivially available; report 0
}

// policyCheck ensures only patchable paths changed and context is within size.
func policyCheck(repoPath, svc, fromSHA, toSHA string, g *gateYML, maxMB int) error {
	if fromSHA == "" {
		return nil
	}
	out, err := run("git", "-C", repoPath, "diff", "--name-only", fromSHA, toSHA, "--", svc+"/")
	if err != nil {
		return fmt.Errorf("diff: %w", err)
	}
	patchable := map[string]struct{}{}
	for _, p := range g.Patchable {
		patchable[svc+"/"+p] = struct{}{}
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := sc.Text()
		if _, ok := patchable[f]; !ok {
			return fmt.Errorf("protected file modified: %s", f)
		}
	}
	// size check
	sizeOut, _ := run("bash", "-c",
		fmt.Sprintf(`git -C %q archive %q -- %q | wc -c`, repoPath, toSHA, svc+"/"))
	var sizeBytes int64
	fmt.Sscan(strings.TrimSpace(sizeOut), &sizeBytes)
	if sizeBytes > int64(maxMB)*1024*1024 {
		return fmt.Errorf("context %d MB > limit %d MB", sizeBytes>>20, maxMB)
	}
	return nil
}

// composeBuildPath reads the build.context or build path for a service from docker-compose.yml.
func composeBuildPath(composeFile, svcName string) string {
	data, _ := os.ReadFile(composeFile)
	sc := bufio.NewScanner(bytes.NewReader(data))
	inSvc := false
	inBuild := false
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == svcName+":" {
			inSvc = true
			continue
		}
		if inSvc {
			if strings.HasPrefix(trimmed, "build:") {
				v := strings.TrimSpace(strings.TrimPrefix(trimmed, "build:"))
				if v != "" && v != "|" {
					return v // inline: build: ./notebook
				}
				inBuild = true
				continue
			}
			if inBuild && strings.HasPrefix(trimmed, "context:") {
				return strings.TrimSpace(strings.TrimPrefix(trimmed, "context:"))
			}
			if inBuild && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				inBuild = false
			}
			// stop if we enter another top-level service
			if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(trimmed, ":") {
				break
			}
		}
	}
	return ""
}

// buildImage builds h7/<svc>:c-<sha12> using the capped BuildKit builder.
func buildImage(cfg *Config, repoPath, svc, sha string, g *gateYML) (string, error) {
	sha12 := sha
	if len(sha12) > 12 {
		sha12 = sha12[:12]
	}
	buildCtx := filepath.Join(os.TempDir(), fmt.Sprintf("h7d-build-%s-%s", svc, sha12))
	if err := os.MkdirAll(buildCtx, 0755); err != nil {
		return "", err
	}
	defer os.RemoveAll(buildCtx)

	// extract service tree: strips the service-name top dir so buildCtx/ = service/
	pr, pw, err := os.Pipe()
	if err != nil {
		return "", err
	}
	archCmd := exec.Command("git", "-C", repoPath, "archive", sha, "--", svc+"/")
	archCmd.Stdout = pw
	archCmd.Stderr = os.Stderr
	tarCmd := exec.Command("tar", "-x", "-C", buildCtx, "--strip-components=1")
	tarCmd.Stdin = pr
	tarCmd.Stdout = os.Stdout
	tarCmd.Stderr = os.Stderr
	if err := archCmd.Start(); err != nil {
		pw.Close()
		return "", fmt.Errorf("git archive start: %w", err)
	}
	pw.Close()
	if err := tarCmd.Run(); err != nil {
		archCmd.Wait()
		return "", fmt.Errorf("tar extract: %w", err)
	}
	archCmd.Wait()

	// find the actual docker build context from docker-compose.yml
	// e.g. "build: ./notebook" means build context = buildCtx/notebook
	composeFile := filepath.Join(buildCtx, "docker-compose.yml")
	buildDir := composeBuildPath(composeFile, g.Service)
	if buildDir == "" {
		buildDir = "." // fallback: build from buildCtx root
	}
	if !filepath.IsAbs(buildDir) {
		buildDir = filepath.Join(buildCtx, buildDir)
	}
	buildDir = filepath.Clean(buildDir)

	// verify Dockerfile exists
	if _, err := os.Stat(filepath.Join(buildDir, "Dockerfile")); err != nil {
		return "", fmt.Errorf("Dockerfile not found in %s: %w", buildDir, err)
	}

	tag := fmt.Sprintf("h7/%s:c-%s", svc, sha12)
	secret := buildSecret(cfg, svc, sha12)

	args := []string{
		"timeout", fmt.Sprint(cfg.BuildTimeout),
		"docker", "buildx", "build",
	}
	if cfg.BuilderName != "" && cfg.BuilderName != "default" {
		args = append(args, "--builder", cfg.BuilderName)
	}
	args = append(args,
		"--load",
		"--provenance=false", // prevents manifest-list that --load can't handle
		"--build-arg", "H7_BUILD_SECRET="+secret,
		"-t", tag,
		buildDir,
	)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("build failed: %w", err)
	}

	digest, _ := run("docker", "inspect", "--format={{.Id}}", tag)
	return strings.TrimSpace(digest), nil
}

// stagingAddr returns the address to expose staging on.
// On a real prod box: 10.60.T.3 (secondary private IP).
// In mock/local mode: 127.0.0.1.
func stagingAddr(cfg *Config) string {
	if cfg.GateMock || cfg.Team == 0 {
		return "127.0.0.1"
	}
	return fmt.Sprintf("10.60.%d.3", cfg.Team)
}

// writeStagingCompose writes a staging docker-compose override to a temp path.
// It binds the service to stagingHost:servicePort.
func writeStagingCompose(cfg *Config, svc, sha12 string, g *gateYML) (string, error) {
	sHost := stagingAddr(cfg)
	sPort := g.Port
	if sPort == 0 {
		sPort = 5000
	}
	// in mock/local mode use a high host port to avoid conflicting with the prod port on 127.0.0.1
	hostPort := sPort
	if cfg.GateMock || cfg.Team == 0 {
		hostPort = cfg.StagingPortBase + sPort
	}

	// read original compose to get volume names
	origCompose := filepath.Join(cfg.ServiceRoot, svc, "docker-compose.yml")
	origData, _ := os.ReadFile(origCompose)

	// extract volume names (simple scan)
	var volumes []string
	sc := bufio.NewScanner(bytes.NewReader(origData))
	inVolumes := false
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "volumes:" && !strings.HasPrefix(line, " ") {
			inVolumes = true
			continue
		}
		if inVolumes {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				inVolumes = false
				continue
			}
			vol := strings.TrimSuffix(strings.TrimSpace(trimmed), ":")
			if vol != "" {
				volumes = append(volumes, fmt.Sprintf("stg-%s-%s", svc, vol))
			}
		}
	}

	// write staging compose override
	var sb strings.Builder
	sb.WriteString("services:\n")
	sb.WriteString(fmt.Sprintf("  %s:\n", g.Service))
	sb.WriteString(fmt.Sprintf("    image: h7/%s:c-%s\n", svc, sha12))
	sb.WriteString(fmt.Sprintf("    ports:\n      - \"%s:%d:%d\"\n", sHost, hostPort, sPort))
	sb.WriteString("    cpus: 0.5\n    mem_limit: 768m\n")
	sb.WriteString("    volumes:\n")
	for _, v := range volumes {
		sb.WriteString(fmt.Sprintf("      - %s:/data\n", v))
	}
	sb.WriteString("    restart: 'no'\n")

	if len(volumes) > 0 {
		sb.WriteString("\nvolumes:\n")
		for _, v := range volumes {
			sb.WriteString(fmt.Sprintf("  %s:\n", v))
		}
	}

	path := filepath.Join(os.TempDir(), fmt.Sprintf("h7d-staging-%s.yml", svc))
	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		return "", err
	}
	return path, nil
}

// stagingCompose spins up staging on the secondary IP (or localhost for local tests).
func stagingCompose(cfg *Config, svc, sha, _ string, g *gateYML) error {
	sha12 := sha
	if len(sha12) > 12 {
		sha12 = sha12[:12]
	}
	project := "stg-" + svc

	stagingFile, err := writeStagingCompose(cfg, svc, sha12, g)
	if err != nil {
		return fmt.Errorf("staging compose: %w", err)
	}

	cmd := exec.Command("docker", "compose",
		"-p", project,
		"-f", stagingFile,
		"up", "-d", "--force-recreate",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Remove(stagingFile)
		return fmt.Errorf("staging up: %w", err)
	}

	// wait up to 30s for health or running
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := run("docker", "compose", "-p", project, "ps", "--format", "{{.State}}")
		if strings.Contains(out, "running") {
			return nil
		}
		if strings.Contains(out, "exited") {
			return fmt.Errorf("staging container exited immediately")
		}
		time.Sleep(2 * time.Second)
	}
	return nil // best-effort: proceed to gate
}

func teardownStaging(svc string) {
	exec.Command("docker", "compose", "-p", "stg-"+svc, "down", "-v", "--remove-orphans").Run()
	os.Remove(filepath.Join(os.TempDir(), fmt.Sprintf("h7d-staging-%s.yml", svc)))
}

func promoteService(cfg *Config, svc, sha string) error {
	sha12 := sha
	if len(sha12) > 12 {
		sha12 = sha12[:12]
	}
	tag := fmt.Sprintf("h7/%s:c-%s", svc, sha12)

	run("docker", "tag", fmt.Sprintf("h7/%s:current", svc), fmt.Sprintf("h7/%s:prev", svc))
	if _, err := run("docker", "tag", tag, fmt.Sprintf("h7/%s:current", svc)); err != nil {
		return fmt.Errorf("retag current: %w", err)
	}

	composeFile := filepath.Join(cfg.ServiceRoot, svc, "docker-compose.yml")
	cmd := exec.Command("docker", "compose",
		"-p", cfg.ComposeProject,
		"-f", composeFile,
		"up", "-d", "--no-deps", svc,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func rollbackService(cfg *Config, svc, target string) (string, error) {
	src := fmt.Sprintf("h7/%s:prev", svc)
	if target == "orig" {
		src = fmt.Sprintf("h7/%s:orig", svc)
	}
	if _, err := run("docker", "image", "inspect", src); err != nil {
		return "", fmt.Errorf("image %s not found: %w", src, err)
	}
	run("docker", "tag", fmt.Sprintf("h7/%s:current", svc), fmt.Sprintf("h7/%s:prev", svc))
	run("docker", "tag", src, fmt.Sprintf("h7/%s:current", svc))

	composeFile := filepath.Join(cfg.ServiceRoot, svc, "docker-compose.yml")
	exec.Command("docker", "compose",
		"-p", cfg.ComposeProject,
		"-f", composeFile,
		"up", "-d", "--no-deps", svc,
	).Run()

	digest, _ := run("docker", "inspect", "--format={{.Id}}", fmt.Sprintf("h7/%s:current", svc))
	return strings.TrimSpace(digest), nil
}

func pushToArchive(cfg *Config, svc, sha12 string) {
	if cfg.ArchiveRegistry == "" || cfg.ArchiveUser == "" {
		return
	}
	src := fmt.Sprintf("h7/%s:c-%s", svc, sha12)
	dst := fmt.Sprintf("%s/%s/%s:%s", cfg.ArchiveRegistry, cfg.ArchiveUser, svc, sha12)
	run("docker", "login", cfg.ArchiveRegistry,
		"-u", cfg.ArchiveUser, "--password-stdin")
	exec.Command("bash", "-c",
		fmt.Sprintf("echo %q | docker login %s -u %s --password-stdin",
			cfg.ArchivePass, cfg.ArchiveRegistry, cfg.ArchiveUser)).Run()
	exec.Command("docker", "tag", src, dst).Run()
	exec.Command("docker", "push", dst).Run()
}

func runDeploy(cfg *Config, anvil *anvilClient, st *State, svc, sha string) {
	buildLock.Lock()
	defer buildLock.Unlock()

	sha12 := sha
	if len(sha12) > 12 {
		sha12 = sha12[:12]
	}
	log.Printf("[%s] pipeline start sha=%s", svc, sha12)

	s := st.svc(svc)
	fromSHA := s.SHA

	// rate limit: at most one promote per service per tick
	tick := tickNumber(cfg)
	if tick > 0 && s.LastTick == tick {
		log.Printf("[%s] already promoted this tick (%d), coalescing", svc, tick)
		return
	}

	g, err := loadGateYML(cfg.ServiceRoot, svc)
	if err != nil {
		log.Printf("[%s] gate.yml missing/invalid: %v - using defaults", svc, err)
		g = &gateYML{Service: svc, Port: 5000}
	}

	if err := policyCheck(cfg.RepoPath, svc, fromSHA, sha, g, cfg.MaxContextMB); err != nil {
		log.Printf("[%s] policy REJECT: %v", svc, err)
		return
	}

	digest, err := buildImage(cfg, cfg.RepoPath, svc, sha, g)
	if err != nil {
		log.Printf("[%s] build FAIL: %v", svc, err)
		return
	}
	log.Printf("[%s] built sha=%s digest=%s", svc, sha12, shortDigest(digest))

	if err := stagingCompose(cfg, svc, sha, digest, g); err != nil {
		log.Printf("[%s] staging FAIL: %v", svc, err)
		teardownStaging(svc)
		return
	}
	defer teardownStaging(svc)

	gateAddr := stagingAddr(cfg)
	gateResp, err := anvil.gate(cfg, g.Service, gateAddr, g.Port)
	if err != nil {
		log.Printf("[%s] gate ERROR: %v", svc, err)
		return
	}
	if !gateResp.OK {
		log.Printf("[%s] gate FAIL verdict=%s", svc, gateResp.Verdict)
		for _, t := range gateResp.Tasks {
			if t.Status != "OK" {
				log.Printf("  [%s] %s/%d: %s %s", svc, t.Method, t.Variant, t.Status, t.Message)
			}
		}
		return
	}
	log.Printf("[%s] gate OK %dms", svc, gateResp.DurationMS)

	waitQuietWindow(cfg)

	if err := promoteService(cfg, svc, sha); err != nil {
		log.Printf("[%s] promote FAIL: %v", svc, err)
		return
	}

	nFiles, nLines, nBytes := diffStats(cfg.RepoPath, svc, fromSHA, sha)
	st.recordPromote(svc, sha12, digest, tick)

	evtResp, _ := anvil.reportDeployFull(cfg, svc, "deploy", digest, nFiles, nLines, nBytes)
	if evtResp != nil {
		log.Printf("[%s] promoted sha=%s free_left=%d", svc, sha12, evtResp.FreeLeft)
	} else {
		log.Printf("[%s] promoted sha=%s", svc, sha12)
	}

	go pushToArchive(cfg, svc, sha12)
}

func runPipelineWorker(cfg *Config, st *State) {
	anvil := newAnvilClient(cfg)
	for {
		select {
		case <-pq.wake:
		case <-time.After(30 * time.Second):
		}
		for svc, sha := range pq.pop() {
			runDeploy(cfg, anvil, st, svc, sha)
		}
	}
}

// runAutoRevert checks live SLA and auto-reverts on 2+ consecutive non-OK ticks.
// ERROR ticks (our fault) are skipped. Only within 5 ticks of last promote.
func runAutoRevert(cfg *Config, st *State) {
	anvil := newAnvilClient(cfg)
	for {
		time.Sleep(time.Duration(cfg.TickS) * time.Second)
		st.mu.Lock()
		var svcs []string
		for svc := range st.Services {
			svcs = append(svcs, svc)
		}
		st.mu.Unlock()

		for _, svc := range svcs {
			s := st.svc(svc)
			if s.LastTick == 0 {
				continue
			}
			ticks, err := anvil.slaHistory(cfg, svc, s.LastTick)
			if err != nil || len(ticks) == 0 {
				continue
			}

			// only look at ticks within 5 of last promote
			horizon := s.LastTick + 5
			consec := 0
			for i := len(ticks) - 1; i >= 0; i-- {
				t := ticks[i]
				if t.Tick <= s.LastTick || t.Tick > horizon {
					continue
				}
				// ERROR = our fault, skip
				if t.Status == "ERROR" {
					continue
				}
				if t.Status == "OK" {
					consec = 0
				} else {
					consec++
				}
			}

			if consec >= cfg.MaxConsecFail {
				log.Printf("[%s] auto-revert: %d consecutive non-OK ticks post-promote", svc, consec)
				digest, err := rollbackService(cfg, svc, "prev")
				if err != nil {
					log.Printf("[%s] auto-revert failed: %v", svc, err)
					continue
				}
				st.recordRollback(svc, "prev", digest)
				anvil.reportDeployFull(cfg, svc, "revert", digest, 0, 0, 0)
			}
		}
	}
}

func runModePoller(cfg *Config, st *State) {
	if cfg.GateMock || cfg.InternalToken == "" {
		return
	}
	anvil := newAnvilClient(cfg)
	for {
		time.Sleep(time.Duration(cfg.ModeCheckInterval) * time.Second)
		mode, err := anvil.boxMode(cfg)
		if err != nil || mode == "pipeline" {
			continue
		}
		if mode == "root" {
			activateFallbackA(cfg, st, anvil)
		}
	}
}

func activateFallbackA(cfg *Config, st *State, anvil *anvilClient) {
	log.Printf("activating fallback A")
	var keysResp struct {
		Keys []string `json:"keys"`
	}
	anvil.do("GET", fmt.Sprintf("/api/v1/teams/keys?team_id=%s", cfg.TeamID), nil, &keysResp)

	authKeys := "/root/.ssh/authorized_keys"
	os.MkdirAll(filepath.Dir(authKeys), 0700)
	existing, _ := os.ReadFile(authKeys)
	var buf strings.Builder
	buf.Write(existing)
	for _, k := range keysResp.Keys {
		if !strings.Contains(string(existing), strings.TrimSpace(k)) {
			buf.WriteString(strings.TrimSpace(k) + "\n")
		}
	}
	os.WriteFile(authKeys, []byte(buf.String()), 0600)

	exec.Command("sed", "-i",
		"s/^#*\\(PermitRootLogin\\).*/PermitRootLogin prohibit-password/",
		"/etc/ssh/sshd_config").Run()
	exec.Command("systemctl", "reload", "sshd").Run()

	st.mu.Lock()
	for _, s := range st.Services {
		s.Mode = "root"
	}
	st.mu.Unlock()
	st.flush()

	for svc := range st.Services {
		anvil.reportDeployFull(cfg, svc, "fallback_a", "", 0, 0, 0)
	}
}

func shortDigest(d string) string {
	if len(d) > 19 {
		return d[:19]
	}
	return d
}

func run(name string, args ...string) (string, error) {
	var buf bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout = &buf
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return strings.TrimSpace(buf.String()), err
}
