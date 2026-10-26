package reverse

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run ONLY inside a private mount AND network namespace with a task-owned file
// bound over the canonical nginx.conf. The harness checks both namespace IDs
// against PID 1; this test refuses to touch the real NAS configuration/network.
func TestNativeNginxEndToEnd(t *testing.T) {
	if os.Getenv("WATCHCOW_R_NATIVE_TEST") != "1" {
		t.Skip("requires isolated fnOS mount+network namespaces")
	}
	for _, kind := range []string{"mnt", "net", "pid"} {
		self, _ := os.Readlink("/proc/self/ns/" + kind)
		init := os.Getenv("WATCHCOW_R_HOST_" + kind)
		if self == "" || self == init {
			t.Fatalf("refusing test outside isolated %s namespace", kind)
		}
	}
	dir := os.Getenv("WATCHCOW_R_NATIVE_DIR")
	if !strings.HasPrefix(dir, "/root/.work/") {
		t.Fatal("test artifacts must be in task workspace")
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/headers":
			_ = json.NewEncoder(w).Encode(map[string]string{"host": r.Host, "proto": r.Header.Get("X-Forwarded-Proto"), "port": r.Header.Get("X-Forwarded-Port"), "forwarded": r.Header.Get("X-Forwarded-For"), "query": r.URL.RawQuery})
		case "/video":
			http.ServeContent(w, r, "video.mp4", time.Unix(0, 0), bytes.NewReader(bytes.Repeat([]byte("0123456789"), 10000)))
		case "/upload":
			h := sha256.New()
			_, _ = io.Copy(h, r.Body)
			fmt.Fprint(w, hex.EncodeToString(h.Sum(nil)))
		case "/ws":
			if r.Header.Get("Upgrade") != "websocket" {
				http.Error(w, "missing upgrade", 400)
				return
			}
			c, b, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer c.Close()
			_, _ = b.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			_ = b.Flush()
			payload := make([]byte, 4)
			_, _ = io.ReadFull(b, payload)
			_, _ = c.Write(payload)
		default:
			fmt.Fprint(w, "backend")
		}
	}))
	defer backend.Close()
	log, err := os.Create(filepath.Join(dir, "process.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.Command("/usr/trim/nginx/sbin/nginx", "-e", filepath.Join(dir, "error.log"), "-g", "error_log "+filepath.Join(dir, "error.log")+" info;")
	cmd.Env = append(os.Environ(), "NGXMODE=dev")
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Run(); err != nil {
		t.Fatalf("start isolated nginx: %v", err)
	}
	// The private PID namespace kills daemonized children when this test exits.

	transport := &http.Transport{DisableKeepAlives: true, Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request := func(scheme, addr, path string) (*http.Response, error) {
		req, _ := http.NewRequest("GET", scheme+"://"+addr+path, nil)
		req.Host = "watchcow-r.test:" + func() string {
			if scheme == "https" {
				return "5667"
			}
			return "5666"
		}()
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		return client.Do(req)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, e := request("http", "127.0.0.1:5666", "/")
		if e == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("isolated nginx did not start: %v\n%s", e, read(t, filepath.Join(dir, "error.log")))
		}
		time.Sleep(50 * time.Millisecond)
	}
	n := NewNative(filepath.Join(dir, "state"))
	n.Extended = true
	r := Route{Key: "test/", AppName: "watchcow.test", Host: "watchcow-r.test", Upstream: backend.URL, Path: "/", Active: true}
	if err := n.Apply([]Route{r}, false, false); err != nil {
		t.Fatal(err)
	}
	// nginx reload is asynchronous. Wait for the new worker generation.
	deadline = time.Now().Add(8 * time.Second)
	for {
		resp, e := request("http", "127.0.0.1:5666", "/headers")
		if e == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if bytes.Contains(b, []byte(`"proto":"http"`)) {
				break
			}
		}
		if time.Now().After(deadline) {
			pidData, _ := os.ReadFile("/run/nginx.pid")
			pid := strings.TrimSpace(string(pidData))
			wait, _ := os.ReadFile("/proc/" + pid + "/wchan")
			stack, _ := os.ReadFile("/proc/" + pid + "/stack")
			t.Fatalf("route did not become active: pid=%s wchan=%s stack=%s", pid, wait, stack)
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, front := range []struct{ scheme, addr string }{{"http", "127.0.0.1:5666"}, {"http", "[::1]:5666"}, {"https", "127.0.0.1:5667"}, {"https", "[::1]:5667"}} {
		resp, e := request(front.scheme, front.addr, "/headers?path=a%20b&x=1")
		if e != nil {
			t.Fatal(e)
		}
		var headers map[string]string
		e = json.NewDecoder(resp.Body).Decode(&headers)
		resp.Body.Close()
		if e != nil || headers["proto"] != front.scheme || headers["forwarded"] == "1.2.3.4" || headers["query"] != "path=a%20b&x=1" {
			t.Fatalf("bad forwarding: %+v %v", headers, e)
		}
	}
	req, _ := http.NewRequest("GET", "http://127.0.0.1:5666/video", nil)
	req.Host = "watchcow-r.test:5666"
	req.Header.Set("Range", "bytes=123-456")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	video, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 206 || len(video) != 334 || resp.Header.Get("Content-Range") != "bytes 123-456/100000" {
		t.Fatal("seek/range failed", resp.Status, len(video))
	}
	payload := bytes.Repeat([]byte("upload-test"), 200000)
	req, _ = http.NewRequest("POST", "http://127.0.0.1:5666/upload", io.NopCloser(bytes.NewReader(payload)))
	req.Host = "watchcow-r.test:5666"
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	sum := sha256.Sum256(payload)
	if string(got) != hex.EncodeToString(sum[:]) {
		t.Fatal("streamed upload changed payload")
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:5666", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(conn, "GET /ws HTTP/1.1\r\nHost: watchcow-r.test:5666\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	var head bytes.Buffer
	one := make([]byte, 1)
	for !strings.HasSuffix(head.String(), "\r\n\r\n") {
		if _, err := io.ReadFull(conn, one); err != nil {
			t.Fatal(err)
		}
		head.Write(one)
	}
	if !strings.Contains(head.String(), "101 Switching Protocols") {
		t.Fatal(head.String())
	}
	_, _ = conn.Write([]byte("ping"))
	pong := make([]byte, 4)
	if _, err := io.ReadFull(conn, pong); err != nil || string(pong) != "ping" {
		t.Fatal("duplex upgrade failed", err)
	}
	conn.Close()
	if err := n.Apply([]Route{r}, true, false); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(8 * time.Second)
	for {
		resp, e := request("http", "127.0.0.1:5666", "/")
		if e == nil {
			resp.Body.Close()
			if resp.StatusCode == 503 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("stop did not produce 503")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := n.Apply(nil, true, true); err != nil {
		t.Fatal(err)
	}
	t.Log("native fnOS Nginx: HTTP/HTTPS, IPv4/IPv6, forwarded origin/query, Range seek, chunked upload, duplex upgrade, disable and owned-include removal passed")
}
