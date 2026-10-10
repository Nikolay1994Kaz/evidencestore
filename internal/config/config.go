// Package config — настройки хранилища и реестр источников.
//
// Формат — JSON: стандартная библиотека, без зависимостей, и оператор
// банка читает его без справочника. Длительности пишутся строками Go
// ("10m", "168h").
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

// Config — настройки одного экземпляра хранилища.
type Config struct {
	// DataDir — каталог данных: журнал улик, цепь, keyring.dat.
	DataDir string `json:"data_dir"`
	// RootsDir — каталог корней кейринга (FileRoots). Обязан лежать вне
	// DataDir и не попадать в одну резервную копию с ним: копия, где есть и
	// keyring.dat, и корни, открывает всё.
	RootsDir string `json:"roots_dir"`
	// Listen — адрес приёма улик (HTTPS с обязательным клиентским сертификатом).
	Listen string `json:"listen"`
	// AdminSocket — unix-сокет администрирования; по умолчанию DataDir/admin.sock.
	AdminSocket string `json:"admin_socket"`
	// MetricsListen — адрес /metrics в формате Prometheus, например
	// 127.0.0.1:9464; пусто — выключено. Показатели без секретов, но и не
	// для всех: по умолчанию слушать только на этой машине.
	MetricsListen string `json:"metrics_listen"`

	TLS     TLS      `json:"tls"`
	Chain   Chain    `json:"chain"`
	TSA     TSA      `json:"tsa"`
	Keys    Keys     `json:"keys"`
	Replica Replica  `json:"replica"`
	Sources []Source `json:"sources"`

	// Demo — стенд для показа: разрешает короткие сроки (keys.min_wait меньше
	// часа), чтобы уничтожение ключа уложилось в демо. В бою — никогда:
	// окно отмены уничтожения тогда — секунды.
	Demo bool `json:"demo"`
}

// Replica — копия журнала улик и цепи наружу (S3 или каталог). keyring.dat
// туда не уезжает никогда: в копии только шифротекст.
type Replica struct {
	// URL: s3://bucket/prefix?endpoint=…&region=… (ключи из AWS_ACCESS_KEY_ID /
	// AWS_SECRET_ACCESS_KEY) или file:///abs/path. Пусто — без копии.
	URL string `json:"url"`
	// Every — как часто дотягивать копию. По умолчанию 1m: это и есть
	// наибольшее отставание копии (RPO).
	Every Duration `json:"every"`
}

// TLS — сертификаты приёма.
type TLS struct {
	Cert     string `json:"cert"`      // сертификат сервера
	Key      string `json:"key"`       // его ключ
	ClientCA string `json:"client_ca"` // УЦ, выпускающий сертификаты сборщиков
}

// Chain — ритм цепи.
type Chain struct {
	// Tick — как часто листья сворачиваются в звено. По умолчанию 1s.
	Tick Duration `json:"tick"`
	// PromiseMMD — обещанная наибольшая задержка включения улики в цепь
	// (подписанное обещание при приёме, по образцу RFC 6962). По умолчанию 1m.
	PromiseMMD Duration `json:"promise_mmd"`
}

// TSA — внешний свидетель времени.
type TSA struct {
	// URL службы RFC 3161, например http://tsp.pki.gov.kz. "local" —
	// встроенная демо-служба (ключи в DataDir/tsa-local), "" — без меток.
	URL string `json:"url"`
	// Every — как часто заверять голову цепи. По умолчанию 10m.
	Every Duration `json:"every"`
	// Trust — сертификаты, которым верит проверка токенов (у НУЦ:
	// root_rsa_2020.cer и nca_rsa_2022.cer). Для "local" не нужен.
	Trust []string `json:"trust"`
}

// Keys — правила ключей.
type Keys struct {
	// MinWait — наименьший срок между заявкой на уничтожение ключа и самим
	// уничтожением. По умолчанию 168h (7 дней, как минимум у AWS KMS).
	MinWait Duration `json:"min_wait"`
	// BackupDir — куда копировать keyring.dat после каждой записи. Пусто —
	// без резерва (только для разработки).
	BackupDir string `json:"backup_dir"`
	// RootsMirrorDir — второй каталог корней на другом диске или машине:
	// корень пишется в оба и уничтожается в обоих. Пусто — корни в одном
	// каталоге, и его потеря уносит тела всех месяцев.
	RootsMirrorDir string `json:"roots_mirror_dir"`
}

// Source — запись реестра источников. Заводит оператор вместе с ИБ.
type Source struct {
	// Name — имя источника. Должно совпадать с CommonName его клиентского
	// сертификата: источник берётся из сертификата, никогда из запроса.
	Name string `json:"name"`
	// CertSHA256 — если задан, сертификат сборщика закреплён: подходит
	// только он (SHA-256 от DER, hex), даже если УЦ выпустит другой с тем же
	// именем.
	CertSHA256 string `json:"cert_sha256"`
	// ContentType — что в телах: "syslog", "pipelock/receipt" и т. п.
	// Берётся отсюда, а не со слов сборщика.
	ContentType string `json:"content_type"`
	// RetentionMonths — срок хранения в месяцах; после него месяц источника
	// предлагается к уничтожению ключа. 0 — бессрочно.
	RetentionMonths int `json:"retention_months"`
	// ExpectEvery — ожидаемый ритм записей. Молчание дольше — событие
	// «источник молчит» в цепи. 0 — не следить.
	ExpectEvery Duration `json:"expect_every"`
	// Disabled — источник выведен из работы: приём отклоняется.
	Disabled bool `json:"disabled"`
	// GatewayKey — открытый ключ гейтвея (Ed25519, 64 hex) для источника с
	// content_type "pipelock/recorder": им при приёме проверяются подписи
	// контрольных точек бортового журнала. Пусто — подписи не проверяются,
	// сцепка и хэши — проверяются.
	GatewayKey string `json:"gateway_key"`
}

// GatewayContentType — строки бортового журнала Pipelock: такой источник
// проверяется при приёме (пакет gateway).
const GatewayContentType = "pipelock/recorder"

// MaxSourceName совпадает с evidence.MaxSourceLen.
const MaxSourceName = 255

// MaxContentType совпадает с evidence.MaxContentTypeLen: длиннее улику не
// запечатать, и приём отвечал бы 503 на каждую запись.
const MaxContentType = 255

// MaxSocketPath — предел пути unix-сокета в Linux (sun_path, 108 байт с
// завершающим нулём). Длиннее bind отвечает невнятным «invalid argument».
const MaxSocketPath = 107

// Duration — time.Duration, которая в JSON пишется строкой.
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"10m\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Load читает конфигурацию, подставляет умолчания и проверяет её.
// Относительные пути считаются от каталога файла конфигурации.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	c.resolve(filepath.Dir(path))
	c.Defaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) resolve(base string) {
	abs := func(p *string) {
		if *p != "" && *p != "local" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	abs(&c.DataDir)
	abs(&c.RootsDir)
	abs(&c.AdminSocket)
	abs(&c.TLS.Cert)
	abs(&c.TLS.Key)
	abs(&c.TLS.ClientCA)
	abs(&c.Keys.BackupDir)
	abs(&c.Keys.RootsMirrorDir)
	for i := range c.TSA.Trust {
		abs(&c.TSA.Trust[i])
	}
}

// Defaults подставляет значения по умолчанию.
func (c *Config) Defaults() {
	if c.Chain.Tick == 0 {
		c.Chain.Tick = Duration(time.Second)
	}
	if c.Chain.PromiseMMD == 0 {
		c.Chain.PromiseMMD = Duration(time.Minute)
	}
	if c.TSA.Every == 0 {
		c.TSA.Every = Duration(10 * time.Minute)
	}
	if c.Replica.Every == 0 {
		c.Replica.Every = Duration(time.Minute)
	}
	if c.Keys.MinWait == 0 {
		c.Keys.MinWait = Duration(7 * 24 * time.Hour)
	}
	if c.AdminSocket == "" && c.DataDir != "" {
		c.AdminSocket = filepath.Join(c.DataDir, "admin.sock")
	}
	// Отпечатки и ключи — hex в любом регистре: сравнение идёт строками.
	for i := range c.Sources {
		c.Sources[i].CertSHA256 = strings.ToLower(c.Sources[i].CertSHA256)
		c.Sources[i].GatewayKey = strings.ToLower(c.Sources[i].GatewayKey)
	}
}

// MinWaitFloor — наименьший keys.min_wait вне режима demo.
const MinWaitFloor = time.Hour

// Validate проверяет то, что иначе всплыло бы посреди работы.
func (c *Config) Validate() error {
	var errs []error
	if c.DataDir == "" {
		errs = append(errs, errors.New("data_dir is required"))
	}
	if c.RootsDir == "" {
		errs = append(errs, errors.New("roots_dir is required"))
	}
	if nested(c.DataDir, c.RootsDir) {
		errs = append(errs, errors.New("roots_dir and data_dir must not share a directory or contain one another: a copy holding both opens every key"))
	}
	// Копия, где лежат и keyring.dat (data_dir или его резерв), и корень,
	// открывает все ключи. Поэтому корни и их зеркало не делят каталог ни с
	// тем, ни с другим.
	for _, p := range []struct{ a, an, b, bn string }{
		{c.Keys.RootsMirrorDir, "keys.roots_mirror_dir", c.DataDir, "data_dir"},
		{c.Keys.RootsMirrorDir, "keys.roots_mirror_dir", c.RootsDir, "roots_dir"},
		{c.Keys.RootsMirrorDir, "keys.roots_mirror_dir", c.Keys.BackupDir, "keys.backup_dir"},
		{c.RootsDir, "roots_dir", c.Keys.BackupDir, "keys.backup_dir"},
	} {
		if nested(p.a, p.b) {
			errs = append(errs, fmt.Errorf("%s and %s must not share a directory or contain one another: a copy holding keyring.dat and its root opens every key", p.an, p.bn))
		}
	}
	if c.MetricsListen != "" {
		if _, _, err := net.SplitHostPort(c.MetricsListen); err != nil {
			errs = append(errs, fmt.Errorf("metrics_listen: %w", err))
		}
	}
	if len(c.AdminSocket) > MaxSocketPath {
		errs = append(errs, fmt.Errorf("admin_socket path is %d bytes, a unix socket allows %d: set admin_socket to a shorter path", len(c.AdminSocket), MaxSocketPath))
	}
	if c.Chain.Tick.D() < 10*time.Millisecond {
		errs = append(errs, errors.New("chain.tick must be at least 10ms"))
	}
	if c.Chain.PromiseMMD.D() < 2*c.Chain.Tick.D() {
		errs = append(errs, errors.New("chain.promise_mmd must be at least two ticks"))
	}
	// Сроки: отрицательный тикер — паника посреди работы, отрицательное
	// окно отмены — уничтожение ключа без окна.
	for name, d := range map[string]Duration{"tsa.every": c.TSA.Every, "replica.every": c.Replica.Every, "keys.min_wait": c.Keys.MinWait} {
		if d <= 0 {
			errs = append(errs, fmt.Errorf("%s must be positive", name))
		}
	}
	if !c.Demo && c.Keys.MinWait > 0 && c.Keys.MinWait.D() < MinWaitFloor {
		errs = append(errs, fmt.Errorf("keys.min_wait %v is shorter than %v: the window to cancel a key destruction would be too short (set \"demo\": true for a demo stand)", c.Keys.MinWait.D(), MinWaitFloor))
	}
	if c.TSA.URL != "" && c.TSA.URL != "local" && len(c.TSA.Trust) == 0 {
		errs = append(errs, errors.New("tsa.trust is required for a real TSA: tokens are verified before they enter the chain"))
	}
	seen := map[string]bool{}
	for i, s := range c.Sources {
		switch {
		case s.Name == "" || len(s.Name) > MaxSourceName || !utf8.ValidString(s.Name):
			errs = append(errs, fmt.Errorf("sources[%d]: bad name %q", i, s.Name))
		case strings.ContainsAny(s.Name, "/\x00"):
			errs = append(errs, fmt.Errorf("sources[%d]: name %q must not contain '/' (it is part of the key scope)", i, s.Name))
		case seen[s.Name]:
			errs = append(errs, fmt.Errorf("sources[%d]: duplicate name %q", i, s.Name))
		}
		seen[s.Name] = true
		if s.ContentType == "" || len(s.ContentType) > MaxContentType {
			errs = append(errs, fmt.Errorf("sources[%d] %s: content_type is required, at most %d bytes", i, s.Name, MaxContentType))
		}
		if s.ExpectEvery < 0 {
			errs = append(errs, fmt.Errorf("sources[%d] %s: expect_every must not be negative (0 — off)", i, s.Name))
		}
		if s.CertSHA256 != "" {
			if b, err := hex.DecodeString(s.CertSHA256); err != nil || len(b) != sha256.Size {
				errs = append(errs, fmt.Errorf("sources[%d] %s: cert_sha256 must be 64 hex characters", i, s.Name))
			}
		}
		if s.GatewayKey != "" {
			if b, err := hex.DecodeString(s.GatewayKey); err != nil || len(b) != 32 {
				errs = append(errs, fmt.Errorf("sources[%d] %s: gateway_key must be 64 hex characters (Ed25519 public key)", i, s.Name))
			}
			if s.ContentType != GatewayContentType {
				errs = append(errs, fmt.Errorf("sources[%d] %s: gateway_key is used only with content_type %q", i, s.Name, GatewayContentType))
			}
		}
		if s.RetentionMonths < 0 {
			errs = append(errs, fmt.Errorf("sources[%d] %s: retention_months must be >= 0", i, s.Name))
		}
	}
	return errors.Join(errs...)
}

// nested — один каталог совпадает с другим или лежит внутри него.
func nested(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	inside := func(x, y string) bool {
		rel, err := filepath.Rel(y, x)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
	}
	return inside(a, b) || inside(b, a)
}

// Source ищет источник по имени.
func (c *Config) Source(name string) (Source, bool) {
	for _, s := range c.Sources {
		if s.Name == name {
			return s, true
		}
	}
	return Source{}, false
}

// CertFingerprint — отпечаток сертификата для поля cert_sha256.
func CertFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
