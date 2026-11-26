package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

func TestDecodeRunnerToolText(t *testing.T) {
	inner := `{"schema":"artex.runner.v1"}`
	quoted, _ := json.Marshal(inner)
	if got := string(decodeRunnerToolText(quoted)); got != inner {
		t.Fatalf("quoted text=%q", got)
	}
	if got := string(decodeRunnerToolText([]byte(inner))); got != inner {
		t.Fatalf("raw text=%q", got)
	}
	if got := decodeRunnerToolText(nil); got != nil {
		t.Fatalf("nil=%q", got)
	}
}

func TestParseRunnerEnvelopeFull(t *testing.T) {
	raw := `{"schema":"artex.runner.v1","ok":true,"job_id":"01JABC","task_id":42,"tool":"net_nmap","state":"succeeded","result_artifact":{"name":"result.json","path":"42/runner/01JABC/result.json","bytes":10,"sha256":"abc"},"observations":[{"kind":"ip","ip":"192.0.2.1","hostnames":["a.example.com"]},{"kind":"service","ip":"192.0.2.1","port":22,"service":"ssh"}]}`
	env, obs, err := parseRunnerEnvelope([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if env.Schema != runnerEnvelopeSchema || !env.OK || env.TaskID != 42 || env.JobID != "01JABC" {
		t.Fatalf("envelope=%+v", env)
	}
	if env.ResultArtifact == nil || env.ResultArtifact.Path != "42/runner/01JABC/result.json" {
		t.Fatalf("artifact=%+v", env.ResultArtifact)
	}
	if len(obs) != 2 || obs[0].IP != "192.0.2.1" || obs[1].Port != 22 {
		t.Fatalf("observations=%+v", obs)
	}
}

func TestParseRunnerEnvelopeTruncatedKeepsArtifact(t *testing.T) {
	raw := `{"schema":"artex.runner.v1","ok":true,"job_id":"01JABC","task_id":42,"tool":"net_nmap","state":"succeeded","summary":"ok","result_artifact":{"name":"result.json","path":"42/runner/01JABC/result.json","bytes":10,"sha256":"abc"},"artifacts":[],"observations_total":3,"observations":[{"kind":"ip","ip":"192.0.2.1"},{"kind":"service","ip":"192.0.2.1","port":22,"service":"ssh"},{"kind":"service","ip":"192.0.2.1","port":80,"serv`
	env, obs, err := parseRunnerEnvelope([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if env.Schema != runnerEnvelopeSchema || !env.OK || env.TaskID != 42 || env.JobID != "01JABC" {
		t.Fatalf("envelope=%+v", env)
	}
	if env.ResultArtifact == nil || env.ResultArtifact.SHA256 != "abc" {
		t.Fatalf("artifact=%+v", env.ResultArtifact)
	}
	if len(obs) != 2 || obs[1].Service != "ssh" {
		t.Fatalf("complete inline observations=%+v", obs)
	}
}

func TestParseRunnerEnvelopeRejectsNonEnvelope(t *testing.T) {
	if _, _, err := parseRunnerEnvelope([]byte(`"just text"`)); err == nil {
		t.Fatal("non-envelope must fail")
	}
	if _, _, err := parseRunnerEnvelope(nil); err == nil {
		t.Fatal("empty must fail")
	}
}

func TestExtractRunnerObjectHandlesBracesInStrings(t *testing.T) {
	text := []byte(`{"result_artifact":{"path":"42/runner/a}b/result.json","name":"result.json"},"x":1}`)
	obj := extractRunnerObject(text, "result_artifact")
	if obj == nil {
		t.Fatal("object not extracted")
	}
	var ref runnerArtifactRef
	if err := json.Unmarshal(obj, &ref); err != nil {
		t.Fatal(err)
	}
	if ref.Path != "42/runner/a}b/result.json" {
		t.Fatalf("path=%q", ref.Path)
	}
}

func TestReadResultArtifactValidates(t *testing.T) {
	dataDir := t.TempDir()
	job := "01JABC"
	result := runnerResult{
		Schema: runnerResultSchema,
		OK:     true,
		JobID:  job,
		TaskID: 42,
		Tool:   "net_nmap",
		State:  "succeeded",
		Observations: []runnerObservation{
			{Kind: "ip", IP: "192.0.2.1"},
			{Kind: "service", IP: "192.0.2.1", Port: 22, Service: "ssh"},
		},
	}
	raw, _ := json.Marshal(result)
	dir := filepath.Join(dataDir, "tasks", "42", "runner", job)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "result.json")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	ref := &runnerArtifactRef{
		Name:   "result.json",
		Path:   fmt.Sprintf("42/runner/%s/result.json", job),
		Bytes:  int64(len(raw)),
		SHA256: hex.EncodeToString(sum[:]),
	}
	ing := ObservationIngestor{DataDir: dataDir, TaskID: 42}
	got, err := ing.readResultArtifact(&runnerEnvelope{JobID: job, ResultArtifact: ref})
	if err != nil {
		t.Fatal(err)
	}
	if got.TaskID != 42 || len(got.Observations) != 2 {
		t.Fatalf("result=%+v", got)
	}

	for name, mutate := range map[string]func(*runnerArtifactRef){
		"absolute":   func(r *runnerArtifactRef) { r.Path = filepath.Join(dir, "result.json") },
		"traversal":  func(r *runnerArtifactRef) { r.Path = "42/runner/../../etc/passwd" },
		"other task": func(r *runnerArtifactRef) { r.Path = fmt.Sprintf("43/runner/%s/result.json", job) },
		"wrong size": func(r *runnerArtifactRef) { r.Bytes++ },
		"wrong hash": func(r *runnerArtifactRef) { r.SHA256 = strings.Repeat("0", 64) },
	} {
		bad := *ref
		mutate(&bad)
		if _, err := ing.readResultArtifact(&runnerEnvelope{JobID: job, ResultArtifact: &bad}); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestObservationExtraAndHostnames(t *testing.T) {
	obs := runnerObservation{
		Product: "OpenSSH",
		Version: "9.0",
		Proto:   "tcp",
		Extra:   map[string]any{"cpe": []any{"cpe:/a:openbsd:openssh"}},
	}
	extra := observationExtra(obs)
	if extra["product"] != "OpenSSH" || extra["version"] != "9.0" || extra["proto"] != "tcp" {
		t.Fatalf("extra=%v", extra)
	}
	if _, ok := extra["cpe"]; !ok {
		t.Fatalf("observation extra was not merged: %v", extra)
	}

	hosts := boundedHostnames([]string{"A.Example.com.", "a.example.com", "", strings.Repeat("x", 300)})
	if len(hosts) != 1 || hosts[0] != "a.example.com" {
		t.Fatalf("hostnames=%v", hosts)
	}
}

func TestObservationIngestorPersistsAssets(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	tk, err := d.CreateTask("runner ingestion", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID) //nolint:errcheck
	ip := "192.0.2.55"
	defer d.Exec(`DELETE FROM assets WHERE ip=$1`, ip) //nolint:errcheck

	ing := ObservationIngestor{Assets: d.Assets(), DataDir: t.TempDir(), TaskID: tk.ID}
	if err := ing.persist([]runnerObservation{
		{Kind: "ip", IP: ip, Hostnames: []string{"host.example.com"}},
		{Kind: "service", IP: ip, Port: 22, Proto: "tcp", Service: "ssh", Product: "OpenSSH", Version: "9.0"},
		{Kind: "service", IP: ip, Port: 80, Service: "http"},
		{Kind: "service", IP: ip, Port: 22, Service: "ssh"},
	}); err != nil {
		t.Fatal(err)
	}

	var openPorts string
	if err := d.QueryRow(`SELECT open_ports::text FROM assets WHERE type='ip' AND ip=$1`, ip).Scan(&openPorts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(openPorts, `"port": 22`) || !strings.Contains(openPorts, `"port": 80`) {
		t.Fatalf("open_ports=%s", openPorts)
	}
	var extra string
	if err := d.QueryRow(`SELECT extra::text FROM assets WHERE type='service' AND ip=$1 AND port=22`, ip).Scan(&extra); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(extra, "OpenSSH") || !strings.Contains(extra, "9.0") {
		t.Fatalf("extra=%s", extra)
	}
	var services int
	if err := d.QueryRow(`SELECT count(*) FROM assets WHERE type='service' AND ip=$1`, ip).Scan(&services); err != nil {
		t.Fatal(err)
	}
	if services != 2 {
		t.Fatalf("services=%d, want 2 (duplicate ssh deduped)", services)
	}
}

func TestObservationIngestorUsesArtifact(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	tk, err := d.CreateTask("runner artifact ingestion", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID) //nolint:errcheck
	ip := "192.0.2.56"
	defer d.Exec(`DELETE FROM assets WHERE ip=$1`, ip) //nolint:errcheck

	dataDir := t.TempDir()
	job := "01JARTIFACT"
	result := runnerResult{
		Schema: runnerResultSchema,
		OK:     true,
		JobID:  job,
		TaskID: tk.ID,
		Observations: []runnerObservation{
			{Kind: "ip", IP: ip},
			{Kind: "service", IP: ip, Port: 443, Service: "https"},
		},
	}
	raw, _ := json.Marshal(result)
	dir := filepath.Join(dataDir, "tasks", fmt.Sprint(tk.ID), "runner", job)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "result.json"), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	env := runnerEnvelope{
		Schema: runnerEnvelopeSchema,
		OK:     true,
		JobID:  job,
		TaskID: tk.ID,
		Tool:   "net_nmap",
		State:  "succeeded",
		ResultArtifact: &runnerArtifactRef{
			Name:   "result.json",
			Path:   fmt.Sprintf("%d/runner/%s/result.json", tk.ID, job),
			Bytes:  int64(len(raw)),
			SHA256: hex.EncodeToString(sum[:]),
		},
	}
	envRaw, _ := json.Marshal(env)
	quoted, _ := json.Marshal(string(envRaw))
	ing := ObservationIngestor{Assets: d.Assets(), DataDir: dataDir, TaskID: tk.ID}
	if err := ing.Ingest("mcp__kali_runner__net_nmap", quoted); err != nil {
		t.Fatal(err)
	}
	var services int
	if err := d.QueryRow(`SELECT count(*) FROM assets WHERE type='service' AND ip=$1 AND port=443`, ip).Scan(&services); err != nil {
		t.Fatal(err)
	}
	if services != 1 {
		t.Fatalf("services=%d, want 1", services)
	}
}

func TestObservationHooksDelegates(t *testing.T) {
	var posts int
	inner := fakeObservationHooks{post: func() { posts++ }}
	h := WithObservationIngestion(inner, nil, "x", 1)
	if _, ok := h.(observationHooks); ok {
		t.Fatal("nil asset store should return the inner hook unchanged")
	}
	h = WithObservationIngestion(inner, &fakeAssetStoreMarker, "x", 1)
	if _, ok := h.(observationHooks); !ok {
		t.Fatal("wrapper not installed")
	}
	h.PostToolUse(t.Context(), "mcp__kali_runner__net_nmap", nil, []byte(`{}`), false)
	if posts != 1 {
		t.Fatalf("inner PostToolUse calls=%d", posts)
	}
	block, _, _ := h.PreToolUse(t.Context(), "x", nil)
	if block {
		t.Fatal("PreToolUse delegated incorrectly")
	}
}

// fakeObservationHooks is a minimal harness.HookRunner for delegation tests.
type fakeObservationHooks struct {
	post func()
}

func (f fakeObservationHooks) PreToolUse(context.Context, string, []byte) (bool, string, []byte) {
	return false, "", nil
}
func (f fakeObservationHooks) PostToolUse(context.Context, string, []byte, []byte, bool) {
	if f.post != nil {
		f.post()
	}
}
func (f fakeObservationHooks) Stop(context.Context, []llm.Message) (bool, []string, string) {
	return false, nil, ""
}

var fakeAssetStoreMarker db.AssetStore
