package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/cosign"
)

// Путь сокета длиннее предела ловится при проверке конфига, а не
// невнятным «bind: invalid argument» при запуске сервера.
func TestAdminSocketPathLimit(t *testing.T) {
	base := t.TempDir()
	cfg := func(sock string) *Config {
		c := &Config{DataDir: filepath.Join(base, "data"), RootsDir: filepath.Join(base, "roots"), AdminSocket: sock}
		c.Defaults()
		return c
	}
	pad := func(n int) string {
		p := filepath.Join(base, "s")
		return p + strings.Repeat("x", n-len(p))
	}
	if len(filepath.Join(base, "s")) >= MaxSocketPath {
		t.Skipf("временный каталог %s сам длиннее предела", base)
	}

	ok := pad(MaxSocketPath)
	if err := cfg(ok).Validate(); err != nil {
		t.Fatalf("путь ровно %d байт отвергнут: %v", MaxSocketPath, err)
	}
	// Предел настоящий: сокет на таком пути открывается.
	if l, err := net.Listen("unix", ok); err != nil {
		t.Fatalf("ядро не приняло путь %d байт: %v", len(ok), err)
	} else {
		l.Close()
	}

	long := pad(MaxSocketPath + 1)
	err := cfg(long).Validate()
	if err == nil || !strings.Contains(err.Error(), "admin_socket") {
		t.Fatalf("путь %d байт принят: %v", len(long), err)
	}
	if l, err := net.Listen("unix", long); err == nil {
		l.Close()
		t.Fatalf("ядро приняло путь %d байт — предел в конфиге занижен", len(long))
	}
}

// Копия, где лежат и keyring.dat (данные или его резерв), и корень,
// открывает все ключи: такие каталоги не вкладываются друг в друга.
func TestKeyDirsDoNotNest(t *testing.T) {
	base := t.TempDir()
	cfg := func(edit func(*Config)) error {
		c := &Config{
			DataDir:  filepath.Join(base, "data"),
			RootsDir: filepath.Join(base, "roots"),
			Keys:     Keys{BackupDir: filepath.Join(base, "backup"), RootsMirrorDir: filepath.Join(base, "mirror")},
		}
		edit(c)
		c.Defaults()
		return c.Validate()
	}
	if err := cfg(func(*Config) {}); err != nil {
		t.Fatalf("раздельные каталоги отвергнуты: %v", err)
	}
	for name, edit := range map[string]func(*Config){
		"зеркало в данных":      func(c *Config) { c.Keys.RootsMirrorDir = filepath.Join(c.DataDir, "mirror") },
		"зеркало = корни":       func(c *Config) { c.Keys.RootsMirrorDir = c.RootsDir },
		"зеркало в резерве":     func(c *Config) { c.Keys.RootsMirrorDir = filepath.Join(c.Keys.BackupDir, "roots") },
		"резерв внутри зеркала": func(c *Config) { c.Keys.BackupDir = filepath.Join(c.Keys.RootsMirrorDir, "kr") },
		"резерв в корнях":       func(c *Config) { c.Keys.BackupDir = filepath.Join(c.RootsDir, "backup") },
		"корни в резерве":       func(c *Config) { c.RootsDir = filepath.Join(c.Keys.BackupDir, "roots") },
	} {
		if err := cfg(edit); err == nil || !strings.Contains(err.Error(), "opens every key") {
			t.Errorf("%s: принято (%v)", name, err)
		}
	}
	// Соседи с общим префиксом имени — не вложение.
	if err := cfg(func(c *Config) { c.Keys.BackupDir = c.RootsDir + "-backup" }); err != nil {
		t.Fatalf("соседний каталог с общим префиксом принят за вложенный: %v", err)
	}
}

// S-10, K-07, S-09, S-11: опасные значения — ошибка проверки, а не беда
// посреди работы: корни внутри данных (или данные внутри корней, или «..roots»
// внутри data_dir), отрицательные и нулевые сроки, слишком короткое окно
// отмены уничтожения вне стенда, тип содержимого длиннее предела улики,
// срок обещания длиннее proof.MaxPromiseMMD (Q-33) или короче 55 с и двух
// тиков (Q-46).
func TestValidateRejectsDangerousValues(t *testing.T) {
	base := t.TempDir()
	good := func() *Config {
		c := &Config{DataDir: filepath.Join(base, "data"), RootsDir: filepath.Join(base, "roots"),
			Sources: []Source{{Name: "abs-core", ContentType: "syslog", CertSHA256: strings.Repeat("AB", 32)}}}
		c.Defaults()
		return c
	}
	c := good()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Sources[0].CertSHA256 != strings.Repeat("ab", 32) {
		t.Fatalf("отпечаток не приведён к нижнему регистру: %s", c.Sources[0].CertSHA256)
	}
	if c.Sources[0].ExpectContact.D() != DefaultExpectContact {
		t.Fatalf("expect_contact по умолчанию: %v", c.Sources[0].ExpectContact.D())
	}
	for name, spoil := range map[string]func(*Config){
		"корни внутри данных": func(c *Config) { c.RootsDir = filepath.Join(c.DataDir, "roots") },
		"subject_field у журнала гейтвея": func(c *Config) {
			c.Sources[0].ContentType, c.Sources[0].SubjectField = GatewayContentType, "session_id"
		},
		"длинное subject_field":  func(c *Config) { c.Sources[0].SubjectField = strings.Repeat("x", MaxSubjectField+1) },
		"subject_field не UTF-8": func(c *Config) { c.Sources[0].SubjectField = "\xff" },
		"данные внутри корней":   func(c *Config) { c.DataDir = filepath.Join(c.RootsDir, "data") },
		"..roots внутри данных":  func(c *Config) { c.RootsDir = filepath.Join(c.DataDir, "..roots") },
		"min_wait -24h":          func(c *Config) { c.Keys.MinWait = Duration(-24 * time.Hour) },
		"min_wait 1s":            func(c *Config) { c.Keys.MinWait = Duration(time.Second) },
		"tsa.every -1m":          func(c *Config) { c.TSA.Every = Duration(-time.Minute) },
		"replica.every -1m":      func(c *Config) { c.Replica.Every = Duration(-time.Minute) },
		"witness.every -1m":      func(c *Config) { c.Witness.Every = Duration(-time.Minute) },
		"свидетель — сама копия": func(c *Config) {
			c.Replica.URL, c.Witness.URL = "file:///srv/copy", "file:///srv/copy"
			c.Keys.BackupDir = "/srv/keys"
		},
		"копия без резерва ключей": func(c *Config) { c.Replica.URL = "file:///srv/copy" },
		"expect_every -1s":      func(c *Config) { c.Sources[0].ExpectEvery = Duration(-time.Second) },
		"expect_contact 30s":    func(c *Config) { c.Sources[0].ExpectContact = Duration(30 * time.Second) },
		"expect_contact -1m":    func(c *Config) { c.Sources[0].ExpectContact = Duration(-time.Minute) },
		"content_type 256 байт": func(c *Config) { c.Sources[0].ContentType = strings.Repeat("x", 256) },
		"promise_mmd 61s":       func(c *Config) { c.Chain.PromiseMMD = Duration(61 * time.Second) },
		"promise_mmd 56s":       func(c *Config) { c.Chain.PromiseMMD = Duration(56 * time.Second) },
		"tick 3s":               func(c *Config) { c.Chain.Tick = Duration(3 * time.Second) },
	} {
		c := good()
		spoil(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	c = good()
	c.Keys.MinWait, c.Demo = Duration(time.Second), true
	if err := c.Validate(); err != nil {
		t.Fatalf("min_wait 1s на стенде: %v", err)
	}
	// Тик, при котором срока обещания нет вовсе, назван тиком, а не сроком.
	c = good()
	c.Chain.Tick = Duration(3 * time.Second)
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "chain.tick must be at most 2.5s") {
		t.Fatalf("tick 3s: %v", err)
	}
}

func TestValidateCosigners(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cosign.NewSigner("witness.example/w1", priv)
	if err != nil {
		t.Fatal(err)
	}
	key := signer.Verifier().String()
	twice := rekey(t, "witness.example/w1-before")
	bad := map[string][]Cosigner{
		"ftp":        {{URL: "ftp://w.example/", Key: key}},
		"без хоста":  {{URL: "https:///x", Key: key}},
		"с запросом": {{URL: "https://w.example/?a=1", Key: key}},
		"не ключ":    {{URL: "https://w.example/", Key: "witness.example/w1"}},
		"дважды":     {{URL: "https://a.example/", Key: key}, {URL: "https://b.example/", Key: key}},
		// Два текущих ключа одного свидетеля: прежний — в old_keys.
		"имя дважды": {{URL: "https://a.example/", Key: key}, {URL: "https://b.example/", Key: rekey(t, "witness.example/w1")}},
		// Прежний ключ — не ключ, тот же, что текущий, или текущий другого
		// свидетеля; больше предела.
		"прежний не ключ":     {{URL: "https://w.example/", Key: key, OldKeys: []string{"witness.example/w1"}}},
		"прежний = текущий":   {{URL: "https://w.example/", Key: key, OldKeys: []string{key}}},
		"прежний у другого":   {{URL: "https://a.example/", Key: other(t)}, {URL: "https://b.example/", Key: rekey(t, "witness.example/w3"), OldKeys: []string{key}}, {URL: "https://c.example/", Key: key}},
		"прежних больше пяти": {{URL: "https://w.example/", Key: key, OldKeys: []string{rekey(t, "witness.example/w1"), rekey(t, "witness.example/w1"), rekey(t, "witness.example/w1"), rekey(t, "witness.example/w1"), rekey(t, "witness.example/w1")}}},
		// Прежний ключ сам повторяет уже названный: текущий ключ раньше в
		// списке или такой же прежний.
		"прежний = текущий выше": {{URL: "https://a.example/", Key: key}, {URL: "https://b.example/", Key: rekey(t, "witness.example/w3"), OldKeys: []string{key}}},
		"прежний дважды":         {{URL: "https://a.example/", Key: rekey(t, "witness.example/w1"), OldKeys: []string{twice, twice}}},
	}
	// Девять разных свидетелей — больше предела, даже без повторов.
	var nine []Cosigner
	for i := range MaxCosigners + 1 {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		w, err := cosign.NewSigner(fmt.Sprintf("witness.example/n%d", i), priv)
		if err != nil {
			t.Fatal(err)
		}
		nine = append(nine, Cosigner{URL: "https://w.example/", Key: w.Verifier().String()})
	}
	bad["девять"] = nine
	for name, cs := range bad {
		c := Config{Witness: Witness{Cosigners: cs}}
		if errs := c.validateCosigners(); len(errs) == 0 {
			t.Errorf("%s: принято", name)
		}
	}
	good := Config{Witness: Witness{Cosigners: []Cosigner{{URL: "https://w.example/sub/", Key: key}, {URL: "http://127.0.0.1:8444", Key: other(t)}}}}
	if errs := good.validateCosigners(); len(errs) != 0 {
		t.Fatal(errs)
	}
	// Свидетель начат заново с новым ключом: прежний — в old_keys.
	good.Witness.Cosigners[0] = Cosigner{URL: "https://w.example/", Key: rekey(t, "witness.example/w1"), OldKeys: []string{key, rekey(t, "witness.example/w1-before")}}
	if errs := good.validateCosigners(); len(errs) != 0 {
		t.Fatal(errs)
	}
}

// rekey — новый ключ проверки свидетеля name.
func rekey(t *testing.T, name string) string {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := cosign.NewSigner(name, priv)
	if err != nil {
		t.Fatal(err)
	}
	return s.Verifier().String()
}

func other(t *testing.T) string {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := cosign.NewSigner("witness.example/w2", priv)
	if err != nil {
		t.Fatal(err)
	}
	return s.Verifier().String()
}

// ca свидетеля C2SP — путь от каталога конфигурации, как у прочих файлов.
func TestCosignerCAResolved(t *testing.T) {
	c := Config{Witness: Witness{Cosigners: []Cosigner{{CA: "witness-ca.pem"}, {CA: "/etc/ca.pem"}, {}}}}
	c.resolve("/etc/evidencestore")
	if got := c.Witness.Cosigners; got[0].CA != "/etc/evidencestore/witness-ca.pem" || got[1].CA != "/etc/ca.pem" || got[2].CA != "" {
		t.Fatalf("пути ca: %+v", got)
	}
}

// Вторая служба меток: адрес http(s), не та же служба, есть основная и
// доверие к её токенам; пути доверия — от каталога конфигурации.
func TestTSAArchive(t *testing.T) {
	base := func() *Config {
		c := &Config{DataDir: "/var/lib/es", RootsDir: "/var/lib/es-roots", Listen: ":8443",
			TSA:     TSA{URL: "http://tsa.one.example", Trust: []string{"/etc/one.pem"}, Archive: TSAArchive{URL: "https://tsa.two.example/tsr", Trust: []string{"/etc/two.pem"}}},
			Sources: []Source{{Name: "abs-core", ContentType: "syslog"}}}
		c.Defaults()
		return c
	}
	if err := base().Validate(); err != nil {
		t.Fatal(err)
	}
	// Разные службы на одном хосте — другой порт или запрос — не одна служба.
	for _, u := range []string{"http://tsa.one.example:8002/", "http://tsa.one.example/?svc=b", "https://tsa.one.example/"} {
		c := base()
		c.TSA.Archive.URL = u
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for name, spoil := range map[string]func(*Config){
		"ftp":          func(c *Config) { c.TSA.Archive.URL = "ftp://tsa.two.example/" },
		"local":        func(c *Config) { c.TSA.Archive.URL = "local" },
		"та же служба": func(c *Config) { c.TSA.Archive.URL = c.TSA.URL + "/" },
		"та же: регистр, порт по умолчанию": func(c *Config) { c.TSA.Archive.URL = "http://TSA.one.example:80/" },
		"без основной":                      func(c *Config) { c.TSA.URL, c.TSA.Trust = "", nil },
		"без доверия":                       func(c *Config) { c.TSA.Archive.Trust = nil },
	} {
		c := base()
		spoil(c)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "tsa.archive") {
			t.Errorf("%s: %v", name, err)
		}
	}
	c := Config{TSA: TSA{Archive: TSAArchive{Trust: []string{"two.pem", "/etc/abs.pem"}}}}
	c.resolve("/etc/evidencestore")
	if got := c.TSA.Archive.Trust; got[0] != "/etc/evidencestore/two.pem" || got[1] != "/etc/abs.pem" {
		t.Fatalf("пути доверия второй службы: %v", got)
	}
}
