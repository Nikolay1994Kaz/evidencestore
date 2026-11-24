package main

// Установка в Docker на две машины (DECISIONS, п. 45): хост хранилища и хосты
// сборщиков. docker init заводит хранилище при первом запуске контейнера
// (deploy/docker/store/entry.sh), docker add-source выпускает сборщику
// сертификат, закрепляет его в конфиге хранилища и отдаёт архив для хоста сборщика:
// сертификаты, collector.json и compose.yaml. Закрытый ключ сборщика есть
// только в архиве — на хосте хранилища он не остаётся.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pki"
	"github.com/Nikolay1994Kaz/evidencestore/internal/store"
	"github.com/Nikolay1994Kaz/evidencestore/internal/version"
)

// dockerImage — образ выпуска в реестре (собирает CI по тегу).
const dockerImage = "ghcr.io/nikolay1994kaz/evidencestore"

// Пути внутри контейнера хранилища: их монтирует deploy/docker/store/compose.yaml.
const (
	dockerConfigDir   = "/etc/evidencestore"
	dockerTSADir      = "/usr/local/share/evidencestore/tsa"
	dockerDataDir     = "/var/lib/evidencestore"
	dockerRootsDir    = "/var/lib/evidencestore-roots"
	dockerBackupDir   = "/backup/keyring"
	dockerMirrorDir   = "/roots-mirror/evidencestore"
	dockerStorePort   = "8443"
	dockerCollectorCA = "ca.crt"
	// dockerConfigName — имя, которое команды оператора берут по умолчанию
	// (-config evidencestore.json): в контейнере рабочий каталог —
	// dockerConfigDir, и `evidencestore status` идёт без -config.
	dockerConfigName = "evidencestore.json"
)

// dockerTSA — службы меток на выбор при первом запуске: url, частота и файлы
// доверия из configs/tsa (в образе — dockerTSADir).
var dockerTSA = map[string]struct {
	url, every, dir string
	trust           []string
}{
	"digicert": {"http://timestamp.digicert.com", "10m", "digicert", []string{"DigiCertTrustedRootG4.crt", "DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crt"}},
	"nca":      {"http://tsp.pki.gov.kz", "1h", "nca-kz", []string{"root_rsa_2020.cer", "nca_rsa_2022.cer"}},
	"local":    {url: "local"},
}

func cmdDocker(args []string) error {
	if len(args) == 0 {
		return errors.New("docker: init or add-source")
	}
	switch args[0] {
	case "init":
		return cmdDockerInit(args[1:])
	case "add-source":
		return cmdDockerAddSource(args[1:], os.Stdout, os.Stderr)
	}
	return fmt.Errorf("docker: unknown command %q: init or add-source", args[0])
}

// dockerPaths — куда docker init кладёт хранилище; в тестах — во временный каталог.
type dockerPaths struct {
	config, tsa, data, roots, backup, mirror string
}

func cmdDockerInit(args []string) error {
	fs := flag.NewFlagSet("docker init", flag.ExitOnError)
	hosts := fs.String("host", "", "the names and addresses collectors reach this host by, comma-separated (the server certificate is issued for them)")
	tsa := fs.String("tsa", "digicert", "time-stamps: digicert, nca (the NCA of Kazakhstan) or local (the demo TSA built into the store, for a trial)")
	fs.Parse(args)
	return dockerInit(dockerPaths{dockerConfigDir, dockerTSADir, dockerDataDir, dockerRootsDir, dockerBackupDir, dockerMirrorDir}, *hosts, *tsa, os.Stdout)
}

func dockerInit(p dockerPaths, hostList, tsaName string, out io.Writer) error {
	var hosts []string
	for h := range strings.SplitSeq(hostList, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return errors.New("docker init: set ES_HOST to the name collectors reach this host by (a DNS name or an IP address; several, comma-separated): the server certificate is issued for it")
	}
	tsa, ok := dockerTSA[tsaName]
	if !ok {
		return fmt.Errorf("docker init: ES_TSA %q: digicert, nca or local", tsaName)
	}
	storePath := filepath.Join(p.config, dockerConfigName)
	if _, err := os.Stat(storePath); err == nil {
		return fmt.Errorf("docker init: %s exists: the store is set up already", storePath)
	}
	if entries, _ := os.ReadDir(p.config); len(entries) > 0 {
		return fmt.Errorf("docker init: %s holds files but no %s: an earlier first start broke off; stop the container, empty ./config, ./data, ./roots and the backup and roots mirror directories, and start again", p.config, dockerConfigName)
	}
	// Резерв ключей и зеркало корней — каталоги на смонтированных дисках:
	// каталог монтирования есть всегда, а свой каталог внутри заводится только
	// здесь. Нет диска при следующем запуске — нет и каталога: хранилище не
	// создаёт его само и не пишет резерв в пустую точку монтирования (P-12), а
	// показывает в status, что копия ждёт (keyring_backup_pending, docs/keys.md).
	for _, d := range []string{p.backup, p.mirror} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return fmt.Errorf("docker init: %w (the backup and roots mirror directories are mounted at %s and %s)", err, filepath.Dir(p.backup), filepath.Dir(p.mirror))
		}
	}
	if err := os.MkdirAll(p.config, 0o755); err != nil {
		return err
	}

	ca, err := pki.NewCA("evidencestore collectors CA (" + hosts[0] + ")")
	if err != nil {
		return err
	}
	if err := ca.Save(filepath.Join(p.config, "ca")); err != nil {
		return err
	}
	srv, err := ca.Server(hosts...)
	if err != nil {
		return err
	}
	if err := srv.Write(p.config, "server"); err != nil {
		return err
	}

	tsaJSON := map[string]any{"url": tsa.url}
	if tsa.url != "local" {
		var trust []string
		for _, f := range tsa.trust {
			data, err := os.ReadFile(filepath.Join(p.tsa, tsa.dir, f))
			if err != nil {
				return fmt.Errorf("docker init: %w", err)
			}
			rel := filepath.Join("tsa", tsa.dir, f)
			if err := os.MkdirAll(filepath.Join(p.config, "tsa", tsa.dir), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(p.config, rel), data, 0o644); err != nil {
				return err
			}
			trust = append(trust, rel)
		}
		tsaJSON = map[string]any{"url": tsa.url, "every": tsa.every, "trust": trust}
	}
	cfgJSON, err := json.MarshalIndent(struct {
		DataDir  string            `json:"data_dir"`
		RootsDir string            `json:"roots_dir"`
		Listen   string            `json:"listen"`
		TLS      map[string]string `json:"tls"`
		TSA      map[string]any    `json:"tsa"`
		Keys     map[string]string `json:"keys"`
		Sources  []any             `json:"sources"`
	}{
		DataDir:  p.data,
		RootsDir: p.roots,
		Listen:   ":" + dockerStorePort,
		TLS:      map[string]string{"cert": "server.crt", "key": "server.key", "client_ca": "ca/ca.crt"},
		TSA:      tsaJSON,
		Keys:     map[string]string{"backup_dir": p.backup, "roots_mirror_dir": p.mirror},
		Sources:  []any{},
	}, "", "  ")
	if err != nil {
		return err
	}
	// Конфиг появляется последним: есть он — установка закончена.
	tmp := storePath + ".new"
	if err := os.WriteFile(tmp, append(cfgJSON, '\n'), 0o644); err != nil {
		return err
	}
	cfg, err := config.Load(tmp)
	if err != nil {
		return fmt.Errorf("docker init: %w", err)
	}
	pub, err := store.Init(cfg)
	if err != nil {
		return fmt.Errorf("docker init: %w", err)
	}
	if err := os.WriteFile(filepath.Join(p.config, "store.pub"), []byte(pub+"\n"), 0o644); err != nil {
		return err
	}
	// Адрес для сборщиков — по первому имени ES_HOST: в сертификате имена и
	// адреса лежат порознь, и какое было первым, по нему не сказать.
	srvURL := "https://" + net.JoinHostPort(hosts[0], dockerStorePort) + "\n"
	if err := os.WriteFile(filepath.Join(p.config, "server.url"), []byte(srvURL), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, storePath); err != nil {
		return err
	}
	fmt.Fprintf(out, "evidencestore set up for %s; time-stamps: %s\n", strings.Join(hosts, ", "), tsaName)
	fmt.Fprintf(out, "store public key (in ./config/store.pub: collectors pin it, auditors pass it to esverify -store-key):\n%s\n", pub)
	if tsa.url == "local" {
		fmt.Fprintln(out, "time-stamps come from the demo TSA built into the store: for a trial only")
	}
	fmt.Fprintln(out, "a collector: docker compose exec -T store add-collector NAME > NAME.tgz   (reads /var/log/auth.log; another log: -file PATH)")
	return nil
}

func cmdDockerAddSource(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("docker add-source", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(dockerConfigDir, dockerConfigName), "the store's config")
	reload := fs.Bool("reload", false, "then restart the store's serve so it accepts the source: SIGHUP to process 1, the container's entry (add-collector passes it)")
	name := fs.String("name", "", "the source's name, as the store and its bundles will call it")
	file := fs.String("file", "/var/log/auth.log", "the log the collector reads, as a path on the collector's host")
	contentType := fs.String("content-type", "text", "what is in the records: text, syslog, …")
	retention := fs.Int("retention-months", 0, "months to keep the source's records before their key is offered for destruction; 0 — forever")
	server := fs.String("server", "", "the store's address as the collector reaches it (default: server.url next to the config, https://<first name of ES_HOST>:"+dockerStorePort+")")
	image := fs.String("image", "", "the collector's image (default: ES_IMAGE, or the image of this release)")
	fs.Parse(args)

	// Имя идёт в имена файлов, в имя проекта compose и в YAML, путь и образ —
	// в YAML: только знаки, которым там нечего значить.
	if !safeName(*name) {
		return fmt.Errorf("docker add-source: -name %q: lowercase letters, digits, '-' and '_', starting with a letter or a digit, at most 63", *name)
	}
	if f, ok := stdout.(*os.File); ok {
		if st, err := f.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
			return fmt.Errorf("docker add-source: standard output is a terminal, and the bundle is a gzip archive: docker compose exec -T store add-collector %s > %s.tgz (with -T, or docker gives it a terminal)", *name, *name)
		}
	}
	if !path.IsAbs(*file) || path.Clean(*file) != *file || path.Dir(*file) == "/" || !onlyChars(*file, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-") {
		return fmt.Errorf("docker add-source: -file %q: an absolute path to a log in a directory, such as /var/log/auth.log (letters, digits, '.', '_', '-')", *file)
	}
	img := *image
	if img == "" {
		img = os.Getenv("ES_IMAGE")
	}
	if img == "" {
		rel := version.Release()
		if rel == "" {
			return errors.New("docker add-source: this build is not a release, so there is no image of it to name: pass -image (or ES_IMAGE)")
		}
		img = dockerImage + ":" + rel
	}
	if !onlyChars(img, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/:@-") {
		return fmt.Errorf("docker add-source: image %q: not an image reference", img)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if _, ok := cfg.Source(*name); ok {
		return fmt.Errorf("docker add-source: source %q is in %s already: pick another name", *name, *cfgPath)
	}
	dir := filepath.Dir(*cfgPath)
	pubRaw, err := os.ReadFile(filepath.Join(dir, "store.pub"))
	if err != nil {
		return fmt.Errorf("docker add-source: %w (docker init writes it next to the config)", err)
	}
	storeKey := strings.TrimSpace(string(pubRaw))
	srvURL := *server
	if srvURL == "" {
		b, err := os.ReadFile(filepath.Join(dir, "server.url"))
		if err != nil {
			return fmt.Errorf("docker add-source: %w (docker init writes it next to the config): pass -server", err)
		}
		srvURL = strings.TrimSpace(string(b))
	}
	if u, err := url.Parse(srvURL); err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || strings.ContainsAny(srvURL, " \t\r\n\"'#") {
		return fmt.Errorf("docker add-source: -server %q: https://host:port", srvURL)
	}
	ca, err := pki.LoadCA(filepath.Join(dir, "ca"))
	if err != nil {
		return fmt.Errorf("docker add-source: %w", err)
	}
	cert, err := ca.Client(*name)
	if err != nil {
		return err
	}
	fp := config.CertFingerprint(cert.Cert.Raw)

	entry := map[string]any{"name": *name, "content_type": *contentType, "cert_sha256": fp}
	if *retention != 0 {
		entry["retention_months"] = *retention
	}
	// Новый конфиг проверяется загрузкой до того, как уйдёт архив, а
	// встаёт на место после: не прошёл — ни сертификата, ни записи.
	tmp, err := appendSource(*cfgPath, entry)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	newCfg, err := config.Load(tmp)
	if err != nil {
		return fmt.Errorf("docker add-source: %w", err)
	}
	if _, ok := newCfg.Source(*name); !ok {
		return fmt.Errorf("docker add-source: source %q not in the new config", *name)
	}

	bundle, err := collectorBundle(bundleSpec{
		name: *name, server: srvURL, storeKey: storeKey, file: *file, image: img,
		ca: ca.Cert, cert: cert,
	})
	if err != nil {
		return err
	}
	if _, err := stdout.Write(bundle); err != nil {
		return fmt.Errorf("docker add-source: writing the bundle: %w (the config is unchanged)", err)
	}
	if err := os.Rename(tmp, *cfgPath); err != nil {
		return fmt.Errorf("docker add-source: the bundle is written, but the config is not: %w; throw the bundle away and run add-source again", err)
	}
	fmt.Fprintf(stderr, "source %s added, its certificate pinned (cert_sha256 %s)\n", *name, fp)
	if *reload {
		// Вход контейнера (entry.sh) по SIGHUP перезапускает serve: тот
		// читает источники при запуске. Сборщик, пришедший в эту секунду,
		// получит отказ и повторит.
		if err := syscall.Kill(1, syscall.SIGHUP); err != nil {
			fmt.Fprintf(stderr, "the store did not restart (%v): docker compose restart store\n", err)
		} else {
			fmt.Fprintln(stderr, "the store restarts to accept it")
		}
	} else {
		fmt.Fprintln(stderr, "restart the store so it accepts the source: docker compose restart store")
	}
	fmt.Fprintf(stderr, "copy %s.tgz to the collector's host (it holds the collector's private key, and only it does) and there:\n", *name)
	fmt.Fprintf(stderr, "  tar -xzf %s.tgz && cd %s && docker compose up -d\n", *name, *name)
	fmt.Fprintf(stderr, "the collector reads %s there and sends it to %s\n", *file, srvURL)
	return nil
}

func safeName(s string) bool {
	return s != "" && len(s) <= 63 && strings.Trim(s[:1], "abcdefghijklmnopqrstuvwxyz0123456789") == "" &&
		onlyChars(s, "abcdefghijklmnopqrstuvwxyz0123456789_-")
}

func onlyChars(s, allowed string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return !strings.ContainsRune(allowed, r) })
}

// appendSource пишет рядом с конфигом его копию с ещё одним источником и
// возвращает её путь. Ключи верхнего уровня и их порядок — как были;
// источники — по одному в строке.
func appendSource(cfgPath string, entry map[string]any) (string, error) {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return "", err
	}
	type field struct {
		key string
		val json.RawMessage
	}
	var fields []field
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return "", fmt.Errorf("%s: not a JSON object", cfgPath)
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return "", fmt.Errorf("%s: %w", cfgPath, err)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return "", fmt.Errorf("%s: %w", cfgPath, err)
		}
		fields = append(fields, field{t.(string), v})
	}
	if _, err := dec.Token(); err != nil {
		return "", fmt.Errorf("%s: %w", cfgPath, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", fmt.Errorf("%s: data after the JSON object", cfgPath)
	}

	add, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	found := false
	for i := range fields {
		if fields[i].key != "sources" {
			continue
		}
		var srcs []json.RawMessage
		if err := json.Unmarshal(fields[i].val, &srcs); err != nil {
			return "", fmt.Errorf("%s: sources: %w", cfgPath, err)
		}
		srcs = append(srcs, add)
		fields[i].val = sourcesJSON(srcs)
		found = true
	}
	if !found {
		fields = append(fields, field{"sources", sourcesJSON([]json.RawMessage{add})})
	}

	var b bytes.Buffer
	b.WriteString("{\n")
	for i, f := range fields {
		k, _ := json.Marshal(f.key)
		fmt.Fprintf(&b, "  %s: ", k)
		if f.key == "sources" {
			b.Write(f.val)
		} else {
			var ind bytes.Buffer
			if err := json.Indent(&ind, f.val, "  ", "  "); err != nil {
				return "", err
			}
			b.Write(ind.Bytes())
		}
		if i < len(fields)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("}\n")

	mode := os.FileMode(0o644)
	if st, err := os.Stat(cfgPath); err == nil {
		mode = st.Mode().Perm()
	}
	tmp := cfgPath + ".new"
	if err := os.WriteFile(tmp, b.Bytes(), mode); err != nil {
		return "", err
	}
	return tmp, nil
}

func sourcesJSON(srcs []json.RawMessage) json.RawMessage {
	if len(srcs) == 0 {
		return json.RawMessage("[]")
	}
	var b bytes.Buffer
	b.WriteString("[\n")
	for i, s := range srcs {
		var c bytes.Buffer
		json.Compact(&c, s)
		b.WriteString("    ")
		b.Write(c.Bytes())
		if i < len(srcs)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("  ]")
	return b.Bytes()
}

type bundleSpec struct {
	name, server, storeKey, file, image string
	ca                                  *x509.Certificate
	cert                                *pki.Issued
}

// collectorBundle — архив для хоста сборщика: каталог NAME с сертификатами,
// ключом, collector.json, compose.yaml и README.txt.
func collectorBundle(s bundleSpec) ([]byte, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(s.cert.Key)
	if err != nil {
		return nil, err
	}
	logDir := path.Dir(s.file)
	collector, err := json.MarshalIndent(map[string]any{
		"server":     s.server,
		"ca":         dockerCollectorCA,
		"cert":       s.name + ".crt",
		"key":        s.name + ".key",
		"store_key":  s.storeKey,
		"spool_dir":  "/spool",
		"file":       "/host" + s.file,
		"from_start": true,
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	compose := fmt.Sprintf(`# The collector of source %[1]s for evidencestore: docker compose up -d here.
# It reads %[2]s of this host and sends every line to %[3]s.
#
#   docker compose logs collector     what it does
#   docker compose down               stop it (its spool stays in the volume)
#
# The spool is the volume "spool": lines wait there until the store has signed
# for them, and it holds the collector's installation id (epoch). Do not remove
# it (docker compose down -v): the store refuses a collector with another epoch
# until the operator binds the new one (evidencestore sources bind).
name: escollect-%[1]s
services:
  collector:
    image: %[4]s
    command: ["escollect", "-config", "/etc/escollect/collector.json"]
    restart: unless-stopped
    # root in the container without capabilities, but DAC_READ_SEARCH: it
    # reads the log (root:adm 0640 on Debian and Ubuntu) and its own key in this
    # directory (0600, whoever unpacked it), and writes only the spool.
    user: "0:0"
    read_only: true
    cap_drop: [ALL]
    cap_add: [DAC_READ_SEARCH]
    security_opt: ["no-new-privileges:true"]
    volumes:
      - .:/etc/escollect:ro
      - %[5]s:/host%[5]s:ro
      - spool:/spool
volumes:
  spool:
`, s.name, s.file, s.server, s.image, logDir)
	readme := fmt.Sprintf(`The collector of source %[1]s for evidencestore.

  tar -xzf %[1]s.tgz && cd %[1]s && docker compose up -d

It reads %[2]s on this host and sends every line to the store at %[3]s,
which must be reachable from here. Another log: change "file" in
collector.json (it is /host + the path on this host) and the directory mounted
in compose.yaml, before the first start.

%[1]s.key is the collector's private key: this archive is its only copy.
Keep the directory to this host's administrators.

Docs: https://github.com/Nikolay1994Kaz/evidencestore/blob/master/docs/install.md#in-docker
`, s.name, s.file, s.server)

	now := time.Now()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: s.name + "/", Mode: 0o755, ModTime: now}); err != nil {
		return nil, err
	}
	for _, f := range []struct {
		name string
		mode int64
		data []byte
	}{
		{dockerCollectorCA, 0o644, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.ca.Raw})},
		{s.name + ".crt", 0o644, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.cert.Cert.Raw})},
		{s.name + ".key", 0o600, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})},
		{"collector.json", 0o644, append(collector, '\n')},
		{"compose.yaml", 0o644, []byte(compose)},
		{"README.txt", 0o644, []byte(readme)},
	} {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: s.name + "/" + f.name, Mode: f.mode, Size: int64(len(f.data)), ModTime: now}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
