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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Nikolay1994Kaz/evidencestore/internal/cosign"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
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
	Witness Witness  `json:"witness"`
	Seal    Seal     `json:"seal"`
	Sources []Source `json:"sources"`

	// Demo — стенд для показа: разрешает короткие сроки (keys.min_wait меньше
	// часа), чтобы уничтожение ключа уложилось в демо. В бою — никогда:
	// окно отмены уничтожения тогда — секунды.
	Demo bool `json:"demo"`
}

// Seal — печать организации на ключ хранилища (docs/keys.md): заявление,
// которое печатает evidencestore seal-statement, с печатью сертификатом X.509
// организации (CMS SignedData, содержимое внутри: openssl cms -sign -nodetach).
type Seal struct {
	// File — печать, DER или PEM. Пусто — печати нет.
	File string `json:"file"`
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

// Witness — канал свидетеля голов: туда уходят только подписанные головы
// цепи (номер, хэш, подпись), без журнала и тел. Держит его не тот, кто
// администрирует хранилище: проверяющий или другая организация. S3 под тем
// же администратором — не свидетель: блокировку объектов root на машине
// хранилища обходит мимо S3 (DECISIONS, «Свидетель голов»).
type Witness struct {
	// URL: s3://bucket/prefix?endpoint=…&region=… (ключи — только из
	// ES_WITNESS_ACCESS_KEY_ID / ES_WITNESS_SECRET_ACCESS_KEY) или
	// file:///abs/path. Пусто — без свидетеля.
	URL string `json:"url"`
	// Every — как часто отправлять текущую голову. По умолчанию 1m. Голова
	// под каждой меткой TSA уходит и без этого: ею кончается пакет. Тот же
	// ритм — у свидетелей C2SP (Cosigners).
	Every Duration `json:"every"`
	// Cosigners — свидетели C2SP (tlog-witness, eswitness): им уходят головы
	// с доказательством продолжения, они возвращают подпись, и она едет в
	// пакетах (DECISIONS п. 34). Независимо от URL: можно и то и другое.
	Cosigners []Cosigner `json:"cosigners"`
}

// Cosigner — свидетель C2SP.
type Cosigner struct {
	// URL — адрес приёма свидетеля (submission prefix): хранилище шлёт
	// POST <url>/add-checkpoint. Только http:// или https://.
	URL string `json:"url"`
	// Key — ключ проверки свидетеля (vkey: имя+номер ключа+ключ), как его
	// печатает eswitness vkey. Берётся у владельца свидетеля: им хранилище
	// проверяет каждую подпись до того, как положить её в журнал.
	Key string `json:"key"`
	// OldKeys — прежние ключи этого свидетеля (он начат заново с новым
	// ключом). Головы им не уходят, а их подписи из журнала подписей идут в
	// пакеты по-прежнему: аудитор, закрепивший прежний ключ, проверяет им
	// историю до смены.
	OldKeys []string `json:"old_keys"`
	// CA — сертификаты УЦ для HTTPS свидетеля (PEM). Пусто — системные.
	CA string `json:"ca"`
}

// MaxCosigners — предел свидетелей C2SP: каждый — запрос на каждую голову.
const MaxCosigners = 8

// MaxOldKeys — предел прежних ключей у свидетеля: каждый — ещё подпись в
// каждом пакете.
const MaxOldKeys = 4

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
	// (подписанное обещание при приёме, по образцу RFC 6962). По умолчанию
	// и не больше 1m (proof.MaxPromiseMMD): запись, придержанная за метку,
	// которая закрывает окно, обязана пропустить срок. Не меньше 55s и двух
	// тиков (proof.ReceiveLag): время приёма отстаёт от настоящего до 55 с,
	// а время звена — нет, и меньший срок честное хранилище нарушало бы.
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
	// Archive — вторая служба меток другого оператора: раз в Every она
	// заверяет голову цепи отдельно, как свидетель, и её метки служат
	// доказательством, что метки основной существовали раньше, если
	// сертификат основной отзовут по компрометации ключа (RFC 3161, 4). На T1,
	// T2 и время приёма не влияет. Пусто — без неё.
	Archive TSAArchive `json:"archive"`
}

// TSAArchive — вторая служба меток (tsa.archive).
type TSAArchive struct {
	// URL службы RFC 3161, только http:// или https://.
	URL string `json:"url"`
	// Trust — сертификаты, которыми проверяются её токены до записи.
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
	// SubjectField — поле верхнего уровня JSON-записи с субъектом (клиентом):
	// хранилище ставит записи обезличенную метку, и пакет по субъекту открывает
	// только его записи (DECISIONS, п. 32). Пусто — метки не ставятся.
	SubjectField string `json:"subject_field"`
	// RetentionMonths — срок хранения в месяцах; после него месяц источника
	// предлагается к уничтожению ключа. 0 — бессрочно.
	RetentionMonths int `json:"retention_months"`
	// ExpectEvery — ожидаемый ритм записей. Молчание дольше — событие
	// «источник молчит» в цепи. 0 — не следить.
	ExpectEvery Duration `json:"expect_every"`
	// ExpectContact — сборщик источника выходит на связь не реже: отправкой
	// или пульсом, когда отправлять нечего (heartbeat_every сборщика, 30 с).
	// Дольше — событие «сборщик пропал» в цепи. В отличие от expect_every,
	// порог зависит не от журнала, а от пульса, и одно значение годится
	// всем: 0 — 2 мин.
	ExpectContact Duration `json:"expect_contact"`
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

// MaxSubjectField совпадает с evidence.MaxSubjectField: длиннее улику не
// записать.
const MaxSubjectField = 64

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
	for i := range c.TSA.Archive.Trust {
		abs(&c.TSA.Archive.Trust[i])
	}
	for i := range c.Witness.Cosigners {
		abs(&c.Witness.Cosigners[i].CA)
	}
	abs(&c.Seal.File)
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
	if c.Witness.Every == 0 {
		c.Witness.Every = Duration(time.Minute)
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
		if c.Sources[i].ExpectContact == 0 {
			c.Sources[i].ExpectContact = Duration(DefaultExpectContact)
		}
	}
}

// DefaultExpectContact — expect_contact по умолчанию: четыре пульса
// сборщика (30 с). MinExpectContact — меньше нельзя: после рестарта
// хранилища сборщик возвращается с паузой до минуты (его пауза между
// повторами растёт до минуты), и каждый рестарт давал бы «сборщик пропал».
const (
	DefaultExpectContact = 2 * time.Minute
	MinExpectContact     = time.Minute
)

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
	switch least := proof.ReceiveLag + 2*c.Chain.Tick.D(); {
	case least > proof.MaxPromiseMMD:
		errs = append(errs, fmt.Errorf("chain.tick must be at most %v: chain.promise_mmd must be at least 55s plus two ticks and at most %v", (proof.MaxPromiseMMD-proof.ReceiveLag)/2, proof.MaxPromiseMMD))
	case c.Chain.PromiseMMD.D() < least:
		errs = append(errs, fmt.Errorf("chain.promise_mmd must be at least %v (55s plus two chain ticks): a receive time lags real time by up to 55 seconds, and the store must still link the record in time", least))
	case c.Chain.PromiseMMD.D() > proof.MaxPromiseMMD:
		errs = append(errs, fmt.Errorf("chain.promise_mmd must be at most %v: a record held back past the time-stamp that closes a window would still meet a longer deadline", proof.MaxPromiseMMD))
	}
	// Сроки: отрицательный тикер — паника посреди работы, отрицательное
	// окно отмены — уничтожение ключа без окна.
	for name, d := range map[string]Duration{"tsa.every": c.TSA.Every, "replica.every": c.Replica.Every, "witness.every": c.Witness.Every, "keys.min_wait": c.Keys.MinWait} {
		if d <= 0 {
			errs = append(errs, fmt.Errorf("%s must be positive", name))
		}
	}
	// Свидетель — чужое хранилище, копия — своё: в одном месте головы
	// свидетеля ничего бы не доказывали.
	if c.Replica.URL != "" && c.Keys.BackupDir == "" {
		errs = append(errs, errors.New("replica.url needs keys.backup_dir: the copy is encrypted with copy.key, and a copy whose key is lost with data_dir cannot be restored"))
	}
	if c.Witness.URL != "" && c.Witness.URL == c.Replica.URL {
		errs = append(errs, errors.New("witness.url must not be replica.url: the witness keeps heads out of the store administrator's reach, the copy is the store's own"))
	}
	errs = append(errs, c.validateCosigners()...)
	if !c.Demo && c.Keys.MinWait > 0 && c.Keys.MinWait.D() < MinWaitFloor {
		errs = append(errs, fmt.Errorf("keys.min_wait %v is shorter than %v: the window to cancel a key destruction would be too short (set \"demo\": true for a demo stand)", c.Keys.MinWait.D(), MinWaitFloor))
	}
	if c.TSA.URL != "" && c.TSA.URL != "local" && len(c.TSA.Trust) == 0 {
		errs = append(errs, errors.New("tsa.trust is required for a real TSA: tokens are verified before they enter the chain"))
	}
	if a := c.TSA.Archive; a.URL != "" {
		u, err := url.Parse(a.URL)
		switch {
		case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
			errs = append(errs, fmt.Errorf("tsa.archive.url %q must be http:// or https:// with a host", a.URL))
		case c.TSA.URL == "":
			errs = append(errs, errors.New("tsa.archive needs tsa.url: the second TSA vouches for the time-stamps of the first"))
		case sameService(a.URL, c.TSA.URL):
			errs = append(errs, errors.New("tsa.archive.url must not be tsa.url: a time-stamp of the same TSA shows nothing once its key is compromised"))
		case len(a.Trust) == 0:
			errs = append(errs, errors.New("tsa.archive.trust is required: its tokens are verified before they are kept"))
		}
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
		if len(s.SubjectField) > MaxSubjectField || !utf8.ValidString(s.SubjectField) {
			errs = append(errs, fmt.Errorf("sources[%d] %s: subject_field must be valid UTF-8, at most %d bytes", i, s.Name, MaxSubjectField))
		}
		// Вердикт гейтвея лежит в цепи открыто и называет сессию записи: чужие
		// записи окна не остались бы обезличенными.
		if s.SubjectField != "" && s.ContentType == GatewayContentType {
			errs = append(errs, fmt.Errorf("sources[%d] %s: subject_field is not for content_type %q: the store's verdicts show the session of every record in the open, so subjects would not stay closed", i, s.Name, GatewayContentType))
		}
		if s.ExpectEvery < 0 {
			errs = append(errs, fmt.Errorf("sources[%d] %s: expect_every must not be negative (0 — off)", i, s.Name))
		}
		if s.ExpectContact != 0 && s.ExpectContact.D() < MinExpectContact {
			errs = append(errs, fmt.Errorf("sources[%d] %s: expect_contact %v is shorter than %v: after a store restart its collector comes back within a minute, so every restart would read as a lost collector", i, s.Name, s.ExpectContact.D(), MinExpectContact))
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

// validateCosigners — свидетели C2SP: адрес http(s), ключ проверки
// разбирается, имена не повторяются; прежние ключи разбираются, и ни один
// ключ (имя и номер, или сам ключ) не встречается дважды.
func (c *Config) validateCosigners() []error {
	var errs []error
	if len(c.Witness.Cosigners) > MaxCosigners {
		errs = append(errs, fmt.Errorf("witness.cosigners: %d witnesses, at most %d", len(c.Witness.Cosigners), MaxCosigners))
	}
	names := map[string]bool{}
	type keyID struct {
		name string
		id   uint32
	}
	ids, keys := map[keyID]bool{}, map[string]bool{}
	seen := func(i int, v cosign.Verifier) error {
		if ids[keyID{v.Name, v.ID}] || keys[string(v.Key)] {
			return fmt.Errorf("witness.cosigners[%d]: key %s+%08x is listed twice", i, v.Name, v.ID)
		}
		ids[keyID{v.Name, v.ID}], keys[string(v.Key)] = true, true
		return nil
	}
	for i, w := range c.Witness.Cosigners {
		u, err := url.Parse(w.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			errs = append(errs, fmt.Errorf("witness.cosigners[%d]: url %q must be http:// or https:// with a host, without a query: the store posts to <url>/add-checkpoint", i, w.URL))
		}
		if len(w.OldKeys) > MaxOldKeys {
			errs = append(errs, fmt.Errorf("witness.cosigners[%d]: %d old_keys, at most %d", i, len(w.OldKeys), MaxOldKeys))
		}
		for j, k := range w.OldKeys {
			v, err := cosign.ParseVerifier(k)
			if err != nil {
				errs = append(errs, fmt.Errorf("witness.cosigners[%d].old_keys[%d]: %w", i, j, err))
			} else if err := seen(i, v); err != nil {
				errs = append(errs, err)
			}
		}
		v, err := cosign.ParseVerifier(w.Key)
		if err != nil {
			errs = append(errs, fmt.Errorf("witness.cosigners[%d]: %w (eswitness vkey prints it)", i, err))
			continue
		}
		if names[v.Name] {
			errs = append(errs, fmt.Errorf("witness.cosigners[%d]: witness %s is listed twice", i, v.Name))
		} else if err := seen(i, v); err != nil {
			errs = append(errs, err)
		}
		names[v.Name] = true
	}
	return errs
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

// sameService — две ссылки на одну службу меток: тот же хост (без учёта
// регистра), порт (явный или по умолчанию для схемы), путь (без косой черты
// в конце) и запрос. Та же служба под другим именем или портом — забота
// ArchiveOnce: он сверяет ключ, которым подписаны метки.
func sameService(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return strings.TrimRight(a, "/") == strings.TrimRight(b, "/")
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(ua.Hostname(), ub.Hostname()) && port(ua) == port(ub) &&
		strings.TrimRight(ua.EscapedPath(), "/") == strings.TrimRight(ub.EscapedPath(), "/") && ua.RawQuery == ub.RawQuery
}
