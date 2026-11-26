package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var pointerPattern = regexp.MustCompile(`\Aversion https://git-lfs.github.com/spec/v1\noid sha256:([a-f0-9]{64})\nsize (0|[1-9][0-9]{0,15})\n\z`)

type pointer struct {
	OID  string
	Size int64
}

func parsePointer(data []byte) *pointer {
	m := pointerPattern.FindSubmatch(data)
	if m == nil {
		return nil
	}
	n, e := strconv.ParseInt(string(m[2]), 10, 64)
	if e != nil || n > 9007199254740991 {
		return nil
	}
	return &pointer{string(m[1]), n}
}
func pointerBytes(p pointer) []byte {
	return []byte(fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n", p.OID, p.Size))
}
func packet(in *bufio.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, e := io.ReadFull(in, header); e != nil {
		return nil, e
	}
	n, e := strconv.ParseUint(string(header), 16, 16)
	if e != nil || n != 0 && n < 4 {
		return nil, errors.New("Неверный пакет Git")
	}
	if n == 0 {
		return nil, nil
	}
	data := make([]byte, n-4)
	_, e = io.ReadFull(in, data)
	return data, e
}
func packets(in *bufio.Reader, max int) ([]byte, error) {
	var result []byte
	for {
		p, e := packet(in)
		if e != nil {
			return nil, e
		}
		if p == nil {
			return result, nil
		}
		if len(result)+len(p) > max {
			return nil, errors.New("Превышен размер фильтра")
		}
		result = append(result, p...)
	}
}
func writePackets(out *bufio.Writer, data []byte) error {
	for len(data) > 0 {
		n := len(data)
		if n > 65000 {
			n = 65000
		}
		if _, e := fmt.Fprintf(out, "%04x", n+4); e != nil {
			return e
		}
		if _, e := out.Write(data[:n]); e != nil {
			return e
		}
		data = data[n:]
	}
	_, e := out.WriteString("0000")
	return e
}
func (c *client) smudge(dir, path, commit string, data []byte) ([]byte, error) {
	p := parsePointer(data)
	if p == nil {
		return nil, errors.New("Ресурс не является каноническим указателем")
	}
	if os.Getenv("SPIRIDUS_SKIP_RESOURCES") == "1" {
		fmt.Fprintln(os.Stderr, "Ресурсы пропущены явно: в рабочей копии остаются указатели")
		return data, nil
	}
	if p.Size > maxResource {
		return nil, errors.New("Превышен размер ресурса")
	}
	// treeish приходит от checkout в протоколе фильтра. HEAD в этот момент
	// ещё может указывать на прежний коммит; поиск по oid теряет точную версию.
	if !objectID.MatchString(commit) || len(commit) != 40 {
		return nil, errors.New("Git не передал точный коммит checkout; укажите версию явно")
	}
	if c.session == nil {
		if e := c.open("fetch"); e != nil {
			return nil, e
		}
	}
	r, e := c.request("POST", c.prefix()+"/resource", map[string]any{"path": path, "pointer": string(data), "commit": commit})
	if e != nil {
		return nil, e
	}
	var signed struct {
		URL    string `json:"url"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
		Commit string `json:"commit"`
	}
	if e = decode(r, &signed); e != nil {
		return nil, e
	}
	if signed.SHA256 != p.OID || signed.Size != p.Size || signed.Commit != commit {
		return nil, errTransport
	}
	// Даже кешированный файл требует свежего разрешения на точную версию.
	if cached, e := readCache(dir, p.OID, p.Size); e == nil {
		return cached, nil
	}
	u, e := url.Parse(signed.URL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, errTransport
	}
	// Отдельный запрос без Authorization Spiridus и без cookies/перенаправлений.
	req, e := http.NewRequest("GET", signed.URL, nil)
	if e != nil {
		return nil, errTransport
	}
	response, e := c.http.Do(req)
	if e != nil {
		return nil, errTransport
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.ContentLength >= 0 && response.ContentLength != p.Size {
		return nil, errTransport
	}
	content, e := io.ReadAll(io.LimitReader(response.Body, p.Size+1))
	if e != nil || int64(len(content)) != p.Size {
		return nil, errTransport
	}
	h := sha256.Sum256(content)
	if hex.EncodeToString(h[:]) != p.OID {
		return nil, errTransport
	}
	if _, e = putCache(dir, content); e != nil {
		return nil, errors.New("Не удалось сохранить кеш ресурса")
	}
	return content, nil
}
func filter(endpoint string) error {
	c, e := newClient(endpoint)
	if e != nil {
		return e
	}
	defer c.close()
	dir, e := gitCommonDir()
	if e != nil {
		return e
	}
	in := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	hello, e := packets(in, 1024)
	if e != nil || string(hello) != "git-filter-client\nversion=2\n" {
		return errors.New("Неверное приветствие фильтра")
	}
	if e = writeLines(out, "git-filter-server\n", "version=2\n"); e != nil {
		return e
	}
	if e = out.Flush(); e != nil {
		return e
	}
	caps, e := packets(in, 1024)
	if e != nil || !strings.Contains(string(caps), "capability=clean\n") || !strings.Contains(string(caps), "capability=smudge\n") {
		return errors.New("Недоступный протокол фильтра")
	}
	if e = writeLines(out, "capability=clean\n", "capability=smudge\n"); e != nil {
		return e
	}
	if e = out.Flush(); e != nil {
		return e
	}
	for {
		header, e := packets(in, 8192)
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		var command, path, commit string
		for _, line := range strings.Split(string(header), "\n") {
			k, v, _ := strings.Cut(line, "=")
			if k == "command" {
				command = v
			}
			if k == "pathname" {
				path = v
			}
			if k == "treeish" {
				commit = v
			}
		}
		content, e := packets(in, maxResource)
		if e != nil {
			return e
		}
		var result []byte
		switch command {
		case "smudge":
			result, e = c.smudge(dir, path, commit, content)
		case "clean":
			if parsePointer(content) != nil {
				result = content
			} else {
				var oid string
				oid, e = putCache(dir, content)
				if e == nil {
					result = pointerBytes(pointer{oid, int64(len(content))})
				}
			}
		default:
			e = errors.New("Неподдерживаемая команда фильтра")
		}
		if e != nil {
			fmt.Fprintln(os.Stderr, "Git: содержимое ресурса недоступно; checkout неполон")
			if e = writeLines(out, "status=error\n"); e != nil {
				return e
			}
		} else {
			if e = writeLines(out, "status=success\n"); e != nil {
				return e
			}
			if e = writePackets(out, result); e != nil {
				return e
			}
			if e = writeLines(out); e != nil {
				return e
			}
		}
		if e = out.Flush(); e != nil {
			return e
		}
	}
}
func writeLines(out *bufio.Writer, lines ...string) error {
	for _, line := range lines {
		if _, e := fmt.Fprintf(out, "%04x%s", len(line)+4, line); e != nil {
			return e
		}
	}
	_, e := out.WriteString("0000")
	return e
}
