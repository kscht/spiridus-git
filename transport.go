package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const version = "0.1.1"
const maxObject = 50 * 1024 * 1024
const maxResource = 64 * 1024 * 1024
const warning = "Локальные клоны, история, кеш ресурсов и резервные копии не стираются при erase, отзыве ключа или роли. Уже переданные внешнему агенту байты отозвать нельзя."

var errTransport = errors.New("Git: запрос не выполнен; проверьте ключ, доступ к проекту и доступность шлюза")
var objectID = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
var digestID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var slugPattern = regexp.MustCompile(`^/p/([a-z][a-z0-9]*(?:-[a-z0-9]+)*)/?$`)
var projectIDPattern = regexp.MustCompile(`^p-[a-f0-9]{24}$`)

// Только локально настроенный credential helper может исполняться. Данные клона
// не задают команды, окружение трассировок дочерним Git не передаётся.
func gitEnv() []string {
	allowed := map[string]bool{"PATH": true, "HOME": true, "USERPROFILE": true, "APPDATA": true, "LOCALAPPDATA": true, "XDG_CONFIG_HOME": true, "XDG_RUNTIME_DIR": true, "DBUS_SESSION_BUS_ADDRESS": true, "SYSTEMROOT": true, "SystemRoot": true, "TEMP": true, "TMP": true, "TMPDIR": true, "GIT_DIR": true, "GIT_WORK_TREE": true, "GIT_INDEX_FILE": true}
	env := []string{}
	for _, item := range os.Environ() {
		k, _, _ := strings.Cut(item, "=")
		if allowed[k] {
			env = append(env, item)
		}
	}
	return append(env, "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_TRACE=0", "GIT_TRACE_PACKET=0", "GIT_TRACE_CURL=0", "GIT_TRACE2=0", "GIT_TRACE2_EVENT=0", "GIT_TRACE2_PERF=0")
}
func git(input []byte, args ...string) ([]byte, error) {
	all := append([]string{"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "submodule.recurse=false", "-c", "protocol.allow=never"}, args...)
	cmd := exec.Command("git", all...)
	cmd.Env = gitEnv()
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New("Git: локальная операция не выполнена")
	}
	return out, nil
}
func gitCommonDir() (string, error) {
	out, e := git(nil, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if e != nil {
		return "", e
	}
	return strings.TrimSpace(string(out)), nil
}
func validateURL(raw string) (*url.URL, string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return nil, "", errors.New("Нужен адрес https://шлюз/p/slug без ключа, параметров и перенаправлений")
	}
	m := slugPattern.FindStringSubmatch(u.Path)
	if m == nil || len(m[1]) > 80 || projectIDPattern.MatchString(m[1]) {
		return nil, "", errors.New("Нужен путь /p/slug")
	}
	return u, m[1], nil
}

type ref struct {
	Name string `json:"name"`
	OID  string `json:"oid"`
}
type object struct {
	OID  string `json:"oid"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}
type manifest struct {
	Protocol     int    `json:"protocol"`
	Session      string `json:"session"`
	Head         string `json:"head"`
	Refs         []ref  `json:"refs"`
	ObjectFormat string `json:"objectFormat"`
	Total        int    `json:"total"`
	Bytes        int64  `json:"bytes"`
	ExpiresAt    int64  `json:"expiresAt"`
}
type client struct {
	base          string
	credentialURL string
	key           string
	http          *http.Client
	session       *manifest
}

func newClient(raw string) (*client, error) {
	u, slug, e := validateURL(raw)
	if e != nil {
		return nil, e
	}
	return &client{base: u.Scheme + "://" + u.Host + "/api/v1/git/projects/" + slug + "/sessions", credentialURL: strings.TrimSuffix(raw, "/"), http: &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *client) credential() error {
	if c.key != "" {
		return nil
	}
	data, e := git([]byte("url="+c.credentialURL+"\n\n"), "-c", "credential.useHttpPath=true", "credential", "fill")
	if e != nil {
		return errTransport
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, _ := strings.Cut(line, "=")
		if k == "password" {
			c.key = v
		}
	}
	if !regexp.MustCompile(`^sp_[A-Za-z0-9_-]{43}$`).MatchString(c.key) {
		return errTransport
	}
	return nil
}
func (c *client) request(method, path string, payload any) (*http.Response, error) {
	if e := c.credential(); e != nil {
		return nil, e
	}
	var input io.Reader
	if payload != nil {
		data, e := json.Marshal(payload)
		if e != nil {
			return nil, errTransport
		}
		input = bytes.NewReader(data)
	}
	req, e := http.NewRequest(method, c.base+path, input)
	if e != nil {
		return nil, errTransport
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "git-remote-spiridus/"+version)
	r, e := c.http.Do(req)
	if e != nil {
		return nil, errTransport
	}
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		r.Body.Close()
		return nil, errTransport
	}
	return r, nil
}
func decode(r *http.Response, v any) error {
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024+1))
	if e != nil || len(b) > 4*1024*1024 {
		return errTransport
	}
	if json.Unmarshal(b, v) != nil {
		return errTransport
	}
	return nil
}
func (c *client) open(operation string) error {
	r, e := c.request("POST", "", map[string]any{"protocol": 1, "operation": operation})
	if e != nil {
		return e
	}
	var m manifest
	if e = decode(r, &m); e != nil {
		return e
	}
	if m.Protocol != 1 || !regexp.MustCompile(`^gs-[a-f0-9]{32}$`).MatchString(m.Session) || m.Total < 0 || m.Total > 200000 || m.Bytes < 0 || m.Bytes > maxObject || m.ExpiresAt <= time.Now().UnixMilli() {
		return errTransport
	}
	if m.Head != "" {
		if !objectID.MatchString(m.Head) || len(m.Refs) != 1 || m.Refs[0].Name != "refs/heads/main" || m.Refs[0].OID != m.Head {
			return errTransport
		}
	}
	if m.ObjectFormat != "sha1" {
		return errors.New("Git: этот выпуск клиента поддерживает репозитории SHA-1")
	}
	c.session = &m
	return nil
}
func (c *client) close() {
	if c.session != nil {
		if r, e := c.request("DELETE", "/"+c.session.Session, nil); e == nil {
			r.Body.Close()
		}
		c.session = nil
	}
}
func (c *client) prefix() string { return "/" + c.session.Session }
func hashFor(oid string) hash.Hash {
	if len(oid) == 64 {
		return sha256.New()
	}
	return sha1.New()
}
func safeCache(dir string) (string, error) {
	for _, path := range []string{filepath.Join(dir, "spiridus"), filepath.Join(dir, "spiridus", "objects")} {
		info, e := os.Lstat(path)
		if e == nil {
			if !info.IsDir() {
				return "", errors.New("Небезопасный путь кеша")
			}
		} else if os.IsNotExist(e) {
			if e = os.Mkdir(path, 0700); e != nil {
				return "", e
			}
		} else {
			return "", e
		}
	}
	return filepath.Join(dir, "spiridus", "objects"), nil
}
func putCache(dir string, data []byte) (string, error) {
	h := sha256.Sum256(data)
	oid := hex.EncodeToString(h[:])
	p, e := safeCache(dir)
	if e != nil {
		return "", e
	}
	f, e := os.CreateTemp(p, ".resource-")
	if e != nil {
		return "", e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(data); e != nil {
		f.Close()
		return "", e
	}
	if e = f.Close(); e != nil {
		return "", e
	}
	target := filepath.Join(p, oid)
	if info, e := os.Lstat(target); e == nil {
		if !info.Mode().IsRegular() {
			return "", errors.New("Небезопасный объект кеша")
		}
		if _, e = readCache(dir, oid, int64(len(data))); e == nil {
			return oid, nil
		}
		if e = os.Remove(target); e != nil {
			return "", e
		}
	} else if !os.IsNotExist(e) {
		return "", e
	}
	return oid, os.Rename(f.Name(), target)
}

func readCache(dir, oid string, size int64) ([]byte, error) {
	if !digestID.MatchString(oid) || size < 0 || size > maxResource {
		return nil, errTransport
	}
	path := filepath.Join(dir, "spiridus", "objects", oid)
	s, e := os.Lstat(path)
	if e != nil || !s.Mode().IsRegular() || s.Size() != size {
		return nil, errTransport
	}
	b, e := os.ReadFile(path)
	h := sha256.Sum256(b)
	if e != nil || hex.EncodeToString(h[:]) != oid {
		return nil, errTransport
	}
	return b, nil
}
func main() {
	var e error
	args := os.Args[1:]
	switch {
	case len(args) == 1 && args[0] == "--version":
		fmt.Println("git-remote-spiridus " + version)
		return
	case len(args) >= 1 && args[0] == "cleanup":
		e = cleanup(args[1:])
	case len(args) == 2 && args[0] == "--filter":
		e = filter(args[1])
	case len(args) == 2:
		e = remote(args[1])
	default:
		e = errors.New("Используйте git clone spiridus::https://шлюз/p/slug; cleanup [--apply] — добровольная очистка кеша")
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e.Error())
		os.Exit(1)
	}
}
