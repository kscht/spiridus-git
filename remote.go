package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(filepath.ToSlash(s), "'", "'\\''") + "'"
}

// Git кеширует core.hooksPath до запуска remote helper. Локальный шаблон
// с hooks/внешним hooksPath закрываем до fetch; одной правки config недостаточно.
func preflight(dir string) error {
	cmd := exec.Command("git", "config", "--get", "core.hooksPath")
	cmd.Env = gitEnv()
	value, err := cmd.Output()
	if err == nil {
		hooks := strings.TrimSpace(string(value))
		managed := filepath.Join(dir, "spiridus", "no-hooks")
		if hooks != "/dev/null" && hooks != filepath.ToSlash(managed) && hooks != managed {
			return errors.New("Git: локальный hooksPath не принадлежит Spiridus; clone остановлен до checkout")
		}
	}
	entries, e := os.ReadDir(filepath.Join(dir, "hooks"))
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sample") {
			return errors.New("Git: локальный шаблон содержит hooks; используйте пустой шаблон для clone")
		}
	}
	if prior, e := os.ReadFile(filepath.Join(dir, "info", "attributes")); e == nil && string(prior) != trustedAttributes {
		return errors.New("Git: собственные info/attributes сохранены; настройка фильтра остановлена")
	}
	return nil
}
func setupFilter(dir, endpoint string) error {
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	exe, e = filepath.Abs(exe)
	if e != nil {
		return e
	}
	hooks := filepath.Join(dir, "spiridus", "no-hooks")
	if e = os.MkdirAll(hooks, 0700); e != nil {
		return e
	}
	// Только доверенный бинарник; никаких команд/фильтров из .gitattributes проекта.
	configs := [][2]string{{"filter.lfs.process", shellQuote(exe) + " --filter " + shellQuote(endpoint)}, {"filter.lfs.required", "true"}, {"core.hooksPath", filepath.ToSlash(hooks)}, {"core.fsmonitor", "false"}, {"submodule.recurse", "false"}}
	for _, kv := range configs {
		if _, e = git(nil, "config", "--local", kv[0], kv[1]); e != nil {
			return e
		}
	}
	if e = os.MkdirAll(filepath.Join(dir, "info"), 0700); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(dir, "info", "attributes"), []byte(trustedAttributes), 0600)
}

// Приоритет info/attributes закрывает исполняемые драйверы из клона. Исключения
// сверяются общей фикстурой с серверным классификатором, не правилом «всё кроме md».
const trustedAttributes = "* filter=lfs -diff -merge -text\n*.md !filter diff merge text\n.gitattributes !filter diff merge text\n.spiridus.yml !filter diff merge text\n**/.spiridus.yml !filter diff merge text\nspiridus/theme.json !filter diff merge text\nspiridus/theme.public.json !filter diff merge text\n**/spiridus/theme.json !filter diff merge text\n**/spiridus/theme.public.json !filter diff merge text\n"

func (c *client) objects() ([]object, error) {
	var objects []object
	cursor := 0
	seen := map[string]bool{}
	var total int64
	for {
		r, e := c.request("GET", c.prefix()+"/objects?cursor="+strconv.Itoa(cursor), nil)
		if e != nil {
			return nil, e
		}
		var page struct {
			Objects  []object `json:"objects"`
			Next     *int     `json:"next"`
			Complete bool     `json:"complete"`
			Total    int      `json:"total"`
		}
		if e = decode(r, &page); e != nil {
			return nil, e
		}
		if page.Total != c.session.Total || len(page.Objects) > 4096 || len(objects)+len(page.Objects) > c.session.Total {
			return nil, errTransport
		}
		for _, o := range page.Objects {
			if !objectID.MatchString(o.OID) || len(o.OID) != 40 || seen[o.OID] || o.Size < 0 || o.Size > maxObject || (o.Type != "commit" && o.Type != "tree" && o.Type != "blob") {
				return nil, errTransport
			}
			total += o.Size
			if total > c.session.Bytes {
				return nil, errTransport
			}
			seen[o.OID] = true
			objects = append(objects, o)
		}
		cursor += len(page.Objects)
		if page.Complete {
			if page.Next != nil || cursor != c.session.Total || total != c.session.Bytes || c.session.Head != "" && !seen[c.session.Head] {
				return nil, errTransport
			}
			return objects, nil
		}
		if page.Next == nil || *page.Next != cursor || len(page.Objects) == 0 {
			return nil, errTransport
		}
	}
}
func missingObjects(objects []object) (map[string]bool, error) {
	var input bytes.Buffer
	for _, o := range objects {
		fmt.Fprintln(&input, o.OID)
	}
	out, e := git(input.Bytes(), "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)")
	if e != nil {
		return nil, e
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(objects) == 0 {
		return map[string]bool{}, nil
	}
	if len(lines) != len(objects) {
		return nil, errTransport
	}
	missing := map[string]bool{}
	for i, line := range lines {
		o := objects[i]
		if line == o.OID+" missing" {
			missing[o.OID] = true
		} else if line != fmt.Sprintf("%s %s %d", o.OID, o.Type, o.Size) {
			return nil, errTransport
		}
	}
	return missing, nil
}
func (c *client) downloadObject(dir string, o object) error {
	r, e := c.request("GET", c.prefix()+"/objects/"+o.OID, nil)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.ContentLength != o.Size || r.Header.Get("X-Spiridus-Object-Type") != o.Type {
		return errTransport
	}
	path := filepath.Join(dir, "objects", o.OID[:2])
	if e = os.MkdirAll(path, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(path, ".spiridus-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	h := hashFor(o.OID)
	header := []byte(fmt.Sprintf("%s %d\x00", o.Type, o.Size))
	h.Write(header)
	z := zlib.NewWriter(f)
	if _, e = z.Write(header); e != nil {
		f.Close()
		return e
	}
	n, e := io.Copy(io.MultiWriter(z, h), io.LimitReader(r.Body, o.Size+1))
	closeErr := z.Close()
	fileErr := f.Close()
	if e != nil || closeErr != nil || fileErr != nil || n != o.Size || hex.EncodeToString(h.Sum(nil)) != o.OID {
		return errTransport
	}
	// Проверка oid до установки: неверный сервер не загрязняет базу объектов.
	return os.Rename(f.Name(), filepath.Join(path, o.OID[2:]))
}
func remote(endpoint string) error {
	c, e := newClient(endpoint)
	if e != nil {
		return e
	}
	defer c.close()
	dir, e := gitCommonDir()
	if e != nil {
		return e
	}
	if e = preflight(dir); e != nil {
		return e
	}
	if e = setupFilter(dir, endpoint); e != nil {
		return e
	}
	fmt.Fprintln(os.Stderr, warning)
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 4096), 8192)
	for in.Scan() {
		command := in.Text()
		switch {
		case command == "":
			return nil
		case command == "capabilities":
			fmt.Print("fetch\noption\n\n")
		case strings.HasPrefix(command, "option "):
			fmt.Print("unsupported\n")
		case command == "list" || command == "list for-push":
			if command == "list for-push" {
				return errors.New("Git: push появится на этапе 2; сейчас доступно только чтение")
			}
			c.close()
			operation := "clone"
			if _, err := git(nil, "rev-parse", "--verify", "HEAD"); err == nil {
				operation = "fetch"
			}
			if e = c.open(operation); e != nil {
				return e
			}
			if c.session.Head != "" {
				fmt.Printf("%s refs/heads/main\n@refs/heads/main HEAD\n\n", c.session.Head)
			} else {
				fmt.Print("\n")
			}
		case strings.HasPrefix(command, "fetch "):
			if c.session == nil {
				return errTransport
			}
			for {
				parts := strings.Fields(command)
				if len(parts) != 3 || parts[1] != c.session.Head || parts[2] != "refs/heads/main" {
					return errors.New("Git: разрешена только серверная ветка main")
				}
				if !in.Scan() {
					return errTransport
				}
				command = in.Text()
				if command == "" {
					break
				}
			}
			objects, e := c.objects()
			if e != nil {
				return e
			}
			missing, e := missingObjects(objects)
			if e != nil {
				return e
			}
			for _, o := range objects {
				if missing[o.OID] {
					if e = c.downloadObject(dir, o); e != nil {
						return e
					}
				}
			}
			c.close()
			fmt.Print("\n")
		default:
			return errors.New("Git: команда транспорта не поддерживается")
		}
	}
	return in.Err()
}
func cleanup(args []string) error {
	if len(args) > 1 || len(args) == 1 && args[0] != "--apply" {
		return errors.New("Используйте cleanup [--apply]")
	}
	dir, e := gitCommonDir()
	if e != nil {
		return e
	}
	parent, e := os.Lstat(filepath.Join(dir, "spiridus"))
	if e != nil || !parent.IsDir() {
		return errors.New("Необычный каталог кеша: очистка остановлена")
	}
	cache := filepath.Join(dir, "spiridus", "objects")
	info, e := os.Lstat(cache)
	if os.IsNotExist(e) {
		fmt.Println("Кеш ресурсов отсутствует")
		return nil
	}
	if e != nil || !info.IsDir() {
		return errors.New("Необычный кеш: очистка остановлена")
	}
	entries, e := os.ReadDir(cache)
	if e != nil {
		return e
	}
	var size int64
	for _, item := range entries {
		s, e := item.Info()
		if e != nil || !s.Mode().IsRegular() || !digestID.MatchString(item.Name()) {
			return errors.New("Неизвестный файл кеша: очистка остановлена")
		}
		size += s.Size()
	}
	fmt.Printf("Кеш ресурсов: %d объектов, %d байт. Git refs, история и рабочие файлы сохраняются. Это не подтверждает уничтожение всех копий.\n", len(entries), size)
	if len(args) == 1 {
		for _, item := range entries {
			if e = os.Remove(filepath.Join(cache, item.Name())); e != nil {
				return e
			}
		}
		fmt.Println("Кеш ресурсов очищен")
	} else {
		fmt.Println("Для удаления только этого кеша повторите с --apply")
	}
	return nil
}
