package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed fixtures/protocol.json
var fixtures []byte

func TestSharedProtocol(t *testing.T) {
	var f struct {
		Protocol          int
		TrustedAttributes string
		Pointers          []struct {
			Text  string
			Valid bool
			OID   string
			Size  int64
		}
	}
	if e := json.Unmarshal(fixtures, &f); e != nil {
		t.Fatal(e)
	}
	if f.Protocol != 1 || f.TrustedAttributes != trustedAttributes {
		t.Fatal("Общий договор фильтра изменился")
	}
	for i, v := range f.Pointers {
		p := parsePointer([]byte(v.Text))
		if (p != nil) != v.Valid {
			t.Fatalf("Указатель %d", i)
		}
		if p != nil && (p.OID != v.OID || p.Size != v.Size || string(pointerBytes(*p)) != v.Text) {
			t.Fatalf("Канонический указатель %d", i)
		}
	}
}
func TestURLs(t *testing.T) {
	for _, s := range []string{"http://localhost/p/x", "https://secret@a/p/x", "https://a/p/x?key=private", "https://a/p/x#fragment", "https://a/%70/x", "https://a/p/../x", "https://a/p/x\n"} {
		if _, e := newClient(s); e == nil {
			t.Fatal("Принят неверный адрес")
		}
	}
	if _, e := newClient("https://gateway.example/p/sample"); e != nil {
		t.Fatal(e)
	}
	for _, n := range []int{64, 65, 80, 81} {
		_, e := newClient("https://gateway.example/p/" + strings.Repeat("s", n))
		if (e == nil) != (n <= 80) {
			t.Fatalf("Неверный допуск slug длиной %d", n)
		}
	}
	for _, slug := range []string{"1project", "sample-", "sample--name", "p-" + strings.Repeat("a", 24)} {
		if _, e := newClient("https://gateway.example/p/" + slug); e == nil {
			t.Fatal("Принят slug вне договора каталога")
		}
	}
}

func TestSmudgeRequiresCheckoutCommit(t *testing.T) {
	c := &client{}
	data := pointerBytes(pointer{strings.Repeat("a", 64), 1})
	for _, commit := range []string{"", "HEAD", strings.Repeat("a", 39), strings.Repeat("a", 40) + "\n"} {
		if _, e := c.smudge(t.TempDir(), "test.bin", commit, data); e == nil {
			t.Fatal("Ресурс без точного коммита checkout принят")
		}
	}
}
func TestPacketFraming(t *testing.T) {
	var encoded bytes.Buffer
	w := bufio.NewWriter(&encoded)
	data := bytes.Repeat([]byte("🙂"), 40000)
	if e := writePackets(w, data); e != nil {
		t.Fatal(e)
	}
	w.Flush()
	decoded, e := packets(bufio.NewReader(&encoded), len(data))
	if e != nil || !bytes.Equal(data, decoded) {
		t.Fatal("Данные pkt-line повреждены")
	}
	for _, s := range []string{"0001", "zzzz", "0008abc"} {
		if _, e := packet(bufio.NewReader(strings.NewReader(s))); e == nil {
			t.Fatal("Принят неполный пакет")
		}
	}
}
func TestRejectCorruptObject(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Spiridus-Object-Type", "blob")
		w.Header().Set("Content-Length", "3")
		io.WriteString(w, "bad")
	}))
	defer server.Close()
	c := &client{base: server.URL, key: "sp_" + strings.Repeat("x", 43), http: server.Client(), session: &manifest{Session: "gs-" + strings.Repeat("a", 32)}}
	dir := t.TempDir()
	oid := strings.Repeat("a", 40)
	if e := c.downloadObject(dir, object{oid, "blob", 3}); e == nil {
		t.Fatal("Принят ложный oid")
	}
	if _, e := os.Stat(filepath.Join(dir, "objects", oid[:2], oid[2:])); !os.IsNotExist(e) {
		t.Fatal("Неверный объект установлен")
	}
}

func TestRedirectDoesNotForwardCredential(t *testing.T) {
	forwarded := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	c, e := newClient(server.URL + "/p/sample")
	if e != nil {
		t.Fatal(e)
	}
	c.key = "sp_" + strings.Repeat("x", 43)
	c.http.Transport = server.Client().Transport
	if _, e = c.request("POST", "", map[string]int{"protocol": 1}); e == nil || forwarded {
		t.Fatal("Перенаправление должно завершиться отказом до передачи ключа")
	}
}
func TestTraceAndCache(t *testing.T) {
	t.Setenv("GIT_TRACE_CURL", "/tmp/forbidden")
	t.Setenv("GIT_TRACE2_EVENT", "/tmp/forbidden")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_VALUE_0", "private")
	if strings.Contains(strings.Join(gitEnv(), "\n"), "forbidden") || strings.Contains(strings.Join(gitEnv(), "\n"), "private") {
		t.Fatal("Унаследован журнал или чужая конфигурация")
	}
	dir := t.TempDir()
	oid, e := putCache(dir, []byte("abc"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = readCache(dir, oid, 4); e == nil {
		t.Fatal("Принят ложный размер")
	}
	os.WriteFile(filepath.Join(dir, "spiridus", "objects", oid), []byte("bad"), 0600)
	if _, e = readCache(dir, oid, 3); e == nil {
		t.Fatal("Принят ложный sha256")
	}
}
