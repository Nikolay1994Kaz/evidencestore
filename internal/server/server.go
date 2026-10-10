// Package server — HTTP-обвязка хранилища.
//
// Два входа:
//
//	приём улик   HTTPS, TLS 1.3, обязательный клиентский сертификат от УЦ
//	             сборщиков; источник — CommonName сертификата, никогда не
//	             поле запроса; сертификат можно закрепить отпечатком.
//	админка      HTTP поверх unix-сокета с правами 0600: доступ — у того,
//	             кто вошёл на машину хранилища под его учётной записью.
//
// gRPC не используется: операция одна («принять пачку»), а HTTP/1.1 с JSON
// проходит через любые корпоративные прокси и отлаживается curl'ом.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"evidencestore/internal/config"
	"evidencestore/internal/evlog"
	"evidencestore/internal/keyring"
	"evidencestore/internal/metrics"
	"evidencestore/internal/proof"
	"evidencestore/internal/store"
)

// MaxRequest — предел тела запроса приёма: пачка до store.MaxBatch записей.
const MaxRequest = 16 << 20

// Server — приём и админка над одним хранилищем.
type Server struct {
	cfg   *config.Config
	store *store.Store
	log   *slog.Logger
}

func New(cfg *config.Config, st *store.Store, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return &Server{cfg: cfg, store: st, log: log}
}

// TLSConfig — TLS приёма: TLS 1.3, клиентский сертификат обязателен и
// проверяется по УЦ сборщиков.
func TLSConfig(cfg *config.Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
	if err != nil {
		return nil, fmt.Errorf("server certificate: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.TLS.ClientCA)
	if err != nil {
		return nil, fmt.Errorf("client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("client CA: no certificates in PEM")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

// Run слушает оба входа до отмены ctx, затем мягко останавливается.
func (s *Server) Run(ctx context.Context) error {
	if s.cfg.Listen == "" {
		return errors.New("listen is required: without it the intake would bind every interface on a random port")
	}
	tlsCfg, err := TLSConfig(s.cfg)
	if err != nil {
		return err
	}
	intake := &http.Server{
		Handler:           s.IntakeHandler(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	adminLn, err := ListenAdmin(s.cfg.AdminSocket)
	if err != nil {
		ln.Close()
		return err
	}
	admin := &http.Server{Handler: s.AdminHandler(), ReadHeaderTimeout: 10 * time.Second}
	mon := &http.Server{Handler: s.MetricsHandler(), ReadHeaderTimeout: 10 * time.Second}

	errc := make(chan error, 3)
	go func() { errc <- intake.ServeTLS(ln, "", "") }()
	go func() { errc <- admin.Serve(adminLn) }()
	if s.cfg.MetricsListen != "" {
		monLn, err := net.Listen("tcp", s.cfg.MetricsListen)
		if err != nil {
			intake.Close()
			admin.Close()
			return err
		}
		go func() { errc <- mon.Serve(monLn) }()
	}
	s.log.Info("evidencestore listening", "intake", ln.Addr().String(), "admin", s.cfg.AdminSocket, "metrics", s.cfg.MetricsListen)

	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	intake.Shutdown(shutdown)
	admin.Shutdown(shutdown)
	mon.Shutdown(shutdown)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

// MetricsHandler — GET /metrics в текстовом формате Prometheus.
func (s *Server) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if err := metrics.Write(w, s.store.Metrics(time.Now())); err != nil {
			s.log.Warn("metrics", "err", err)
		}
	})
	return mux
}

// ListenAdmin открывает unix-сокет админки с правами 0600.
func ListenAdmin(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// --- приём ---

// IngestRequest — пачка записей от сборщика.
type IngestRequest struct {
	Records []IngestRecord `json:"records"`
}

type IngestRecord struct {
	Seq  uint64 `json:"seq"`
	Body []byte `json:"body"` // base64
}

// IngestResponse — итог по каждой записи.
type IngestResponse struct {
	Results []IngestResult `json:"results"`
}

type IngestResult struct {
	Seq      uint64         `json:"seq"`
	Status   string         `json:"status"`
	Position uint64         `json:"position"`
	Digest   []byte         `json:"digest,omitempty"`
	Promise  *proof.Promise `json:"promise,omitempty"`
}

// StateResponse — что хранилище знает об источнике.
type StateResponse struct {
	Source    string `json:"source"`
	LastSeq   uint64 `json:"last_seq"`
	PublicKey string `json:"public_key"`
}

func (s *Server) IntakeHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/ingest", s.handleIngest)
	mux.HandleFunc("GET /v1/state", s.handleState)
	return mux
}

// source опознаёт источник по клиентскому сертификату.
func (s *Server) source(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("client certificate required")
	}
	cert := r.TLS.PeerCertificates[0]
	name := cert.Subject.CommonName
	src, ok := s.cfg.Source(name)
	if !ok {
		return "", fmt.Errorf("%w: %q", store.ErrUnknownSource, name)
	}
	if src.CertSHA256 != "" && src.CertSHA256 != config.CertFingerprint(cert.Raw) {
		return "", fmt.Errorf("certificate of %q is not the pinned one", name)
	}
	return name, nil
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	source, err := s.source(r)
	if err != nil {
		writeErr(w, http.StatusForbidden, err)
		return
	}
	if err := s.store.Admit(source, r.Header.Get(EpochHeader)); err != nil {
		s.writeIngestErr(w, source, err)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequest))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, err)
		return
	}
	var req IngestRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("bad JSON: %w", err))
		return
	}
	recs := make([]store.Incoming, len(req.Records))
	for i, rec := range req.Records {
		recs[i] = store.Incoming{Seq: rec.Seq, Body: rec.Body}
	}
	results, err := s.store.Ingest(source, recs)
	if err != nil {
		s.writeIngestErr(w, source, err)
		return
	}
	resp := IngestResponse{Results: make([]IngestResult, len(results))}
	for i, res := range results {
		resp.Results[i] = IngestResult{Seq: res.Seq, Status: res.Status, Position: res.Position, Digest: res.Digest[:], Promise: res.Promise}
	}
	writeJSON(w, http.StatusOK, resp)
}

// writeIngestErr — ответ сборщику с ошибкой приёма; Code говорит
// программе, что повторять нельзя.
func (s *Server) writeIngestErr(w http.ResponseWriter, source string, err error) {
	resp := ErrorResponse{Error: err.Error()}
	switch {
	case errors.Is(err, store.ErrSeqConflict):
		resp.Code = CodeSeqConflict
	case errors.Is(err, store.ErrEpochMismatch):
		resp.Code = CodeEpochMismatch
	}
	writeJSON(w, ingestStatus(err), resp)
	if ingestStatus(err) >= 500 {
		s.log.Error("ingest", "source", source, "err", err)
	}
}

func ingestStatus(err error) int {
	switch {
	case errors.Is(err, store.ErrUnknownSource), errors.Is(err, store.ErrSourceDisabled):
		return http.StatusForbidden
	case errors.Is(err, store.ErrBadRecord):
		return http.StatusBadRequest
	case errors.Is(err, store.ErrInFlight), errors.Is(err, store.ErrSeqConflict), errors.Is(err, store.ErrEpochMismatch):
		return http.StatusConflict
	case errors.Is(err, keyring.ErrScopeClosed), errors.Is(err, keyring.ErrScopeDestroyed):
		return http.StatusConflict
	case errors.Is(err, store.ErrClosed), errors.Is(err, evlog.ErrClosed):
		return http.StatusServiceUnavailable
	}
	// Отказ журнала улик и прочее: «принято» сказать нельзя, сборщик
	// повторит позже.
	return http.StatusServiceUnavailable
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	source, err := s.source(r)
	if err != nil {
		writeErr(w, http.StatusForbidden, err)
		return
	}
	// Сборщик спрашивает state при каждом запуске: чужая установка
	// получает отказ раньше, чем начнёт читать журнал.
	if err := s.store.Admit(source, r.Header.Get(EpochHeader)); err != nil {
		s.writeIngestErr(w, source, err)
		return
	}
	last, err := s.store.LastSeq(source)
	if err != nil {
		writeErr(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, StateResponse{Source: source, LastSeq: last, PublicKey: s.store.PublicKey()})
}

// --- админка ---

// ScheduleRequest — заявка на уничтожение ключа.
type ScheduleRequest struct {
	Scope     string   `json:"scope"`
	Wait      string   `json:"wait"` // длительность Go, "" — keys.min_wait
	Approvals []string `json:"approvals"`
}

func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.store.Status())
	})
	mux.HandleFunc("GET /admin/statement", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.store.Statement())
	})
	mux.HandleFunc("GET /admin/proof", func(w http.ResponseWriter, r *http.Request) {
		seq, err := strconv.ParseUint(r.URL.Query().Get("seq"), 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, errors.New("seq required"))
			return
		}
		b, err := s.store.Proof(r.URL.Query().Get("source"), seq, r.URL.Query().Get("dek") == "1")
		if err != nil {
			code := http.StatusInternalServerError
			if errors.Is(err, store.ErrNotFound) {
				code = http.StatusNotFound
			}
			writeErr(w, code, err)
			return
		}
		writeJSON(w, http.StatusOK, b)
	})
	mux.HandleFunc("POST /admin/stamp", func(w http.ResponseWriter, r *http.Request) {
		head, err := s.store.Stamp(r.Context())
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]uint64{"stamped_head": head})
	})
	mux.HandleFunc("GET /admin/tsa-root", func(w http.ResponseWriter, r *http.Request) {
		root := s.store.TSARoot()
		if root == nil {
			writeErr(w, http.StatusNotFound, errors.New("external TSA: use its own root certificate"))
			return
		}
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.Write(root)
	})
	mux.HandleFunc("GET /admin/keys", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, keyViews(s.store.Keys()))
	})
	mux.HandleFunc("GET /admin/keys/due", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.store.RetentionDue(time.Now()))
	})
	mux.HandleFunc("POST /admin/keys/deactivate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Scopes []string `json:"scopes"`
			Force  bool     `json:"force"` // закрыть и текущий месяц: приём от источника встанет
		}
		if !readJSON(w, r, &req) {
			return
		}
		if err := s.store.Deactivate(req.Force, req.Scopes...); err != nil {
			writeErr(w, keyStatus(err), err)
			return
		}
		writeJSON(w, http.StatusOK, keyViews(s.store.Keys()))
	})
	mux.HandleFunc("POST /admin/keys/schedule", func(w http.ResponseWriter, r *http.Request) {
		var req ScheduleRequest
		if !readJSON(w, r, &req) {
			return
		}
		wait := s.cfg.Keys.MinWait.D()
		if req.Wait != "" {
			d, err := time.ParseDuration(req.Wait)
			if err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			wait = d
		}
		ki, err := s.store.ScheduleDestroy(r.Context(), req.Scope, wait, approvals(req.Approvals))
		if err != nil {
			writeErr(w, keyStatus(err), err)
			return
		}
		writeJSON(w, http.StatusOK, keyView(ki))
	})
	mux.HandleFunc("POST /admin/keys/cancel", func(w http.ResponseWriter, r *http.Request) {
		var req ScheduleRequest
		if !readJSON(w, r, &req) {
			return
		}
		ki, err := s.store.CancelDestroy(req.Scope, approvals(req.Approvals))
		if err != nil {
			writeErr(w, keyStatus(err), err)
			return
		}
		writeJSON(w, http.StatusOK, keyView(ki))
	})
	mux.HandleFunc("POST /admin/keys/destroy-orphan-roots", func(w http.ResponseWriter, r *http.Request) {
		done, err := s.store.DestroyOrphanRoots()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string][]string{"destroyed": done})
	})
	mux.HandleFunc("POST /admin/sources/bind", func(w http.ResponseWriter, r *http.Request) {
		var req BindRequest
		if !readJSON(w, r, &req) {
			return
		}
		if err := s.store.BindEpoch(req.Source, req.Epoch); err != nil {
			code := http.StatusInternalServerError
			switch {
			case errors.Is(err, store.ErrUnknownSource):
				code = http.StatusNotFound
			case errors.Is(err, store.ErrBadRecord):
				code = http.StatusBadRequest
			}
			writeErr(w, code, err)
			return
		}
		writeJSON(w, http.StatusOK, req)
	})
	mux.HandleFunc("POST /admin/keys/complete", func(w http.ResponseWriter, r *http.Request) {
		changed, err := s.store.CompleteDue(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, keyViews(changed))
	})
	return mux
}

func approvals(who []string) []keyring.Approval {
	out := make([]keyring.Approval, len(who))
	for i, w := range who {
		out[i] = keyring.Approval{Who: w}
	}
	return out
}

func keyStatus(err error) int {
	switch {
	case errors.Is(err, keyring.ErrUnknownScope):
		return http.StatusNotFound
	case errors.Is(err, keyring.ErrBadState), errors.Is(err, keyring.ErrApproval), errors.Is(err, store.ErrCurrentMonth):
		return http.StatusConflict
	}
	return http.StatusInternalServerError
}

// KeyView — ключ для оператора, без самого ключа.
type KeyView struct {
	Scope         string     `json:"scope"`
	KEKID         string     `json:"kek_id"`
	State         string     `json:"state"`
	DeactivatedAt *time.Time `json:"deactivated_at,omitempty"`
	DestroyAfter  *time.Time `json:"destroy_after,omitempty"`
	DestroyedAt   *time.Time `json:"destroyed_at,omitempty"`
	EffectiveAt   *time.Time `json:"effective_at,omitempty"`
	Approvals     []string   `json:"approvals,omitempty"`
}

func keyView(ki keyring.KeyInfo) KeyView {
	opt := func(t time.Time) *time.Time {
		if t.IsZero() {
			return nil
		}
		u := t.UTC()
		return &u
	}
	return KeyView{
		Scope: ki.Scope, KEKID: fmt.Sprintf("%x", ki.KEKID), State: ki.State.String(),
		DeactivatedAt: opt(ki.DeactivatedAt), DestroyAfter: opt(ki.DestroyAfter),
		DestroyedAt: opt(ki.DestroyedAt), EffectiveAt: opt(ki.EffectiveAt), Approvals: ki.Approvals,
	}
}

func keyViews(kis []keyring.KeyInfo) []KeyView {
	out := make([]KeyView, len(kis))
	for i, ki := range kis {
		out[i] = keyView(ki)
	}
	return out
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("bad JSON: %w", err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	enc.Encode(v)
}

// ErrorResponse — тело ответа с ошибкой. Code — для программы, а не для
// человека: повторять запрос или остановиться.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// CodeSeqConflict — номер занят другим телом (store.ErrSeqConflict):
// сборщику нельзя повторять, ему надо остановиться.
const CodeSeqConflict = "seq_conflict"

// CodeEpochMismatch — источник закреплён за другой установкой сборщика
// (store.ErrEpochMismatch): этой установке надо остановиться.
const CodeEpochMismatch = "epoch_mismatch"

// EpochHeader — заголовок запроса сборщика: эпоха его установки
// (store.Admit). Без заголовка — сборщик прежней версии.
const EpochHeader = "Collector-Epoch"

// BindRequest — оператор закрепляет за источником эпоху сборщика: так
// принимается законная переустановка.
type BindRequest struct {
	Source string `json:"source"`
	Epoch  string `json:"collector_epoch"`
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, ErrorResponse{Error: err.Error()})
}
