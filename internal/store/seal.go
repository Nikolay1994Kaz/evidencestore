package store

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// Печать организации на ключ хранилища (seal.file; proof/seal.go). Хранилище
// её не ставит, а несёт: организация ставит печать своим сертификатом X.509
// на заявление SealStatement, хранилище при запуске проверяет, что печать
// цела и называет его ключ, берёт у основной службы метку над печатью —
// когда печать уже была — и кладёт печать с меткой в каждый пакет.

// sealTokenFile — метка над печатью в data_dir. В копию не едет: потеряна —
// хранилище возьмёт новую, позже.
const sealTokenFile = "seal.tsr"

// SealStatement — заявление, на которое организация ставит печать: ключ
// подписи голов этого хранилища (evidencestore seal-statement).
func SealStatement(cfg *config.Config) ([]byte, error) {
	_, chainDir, _ := dirs(cfg)
	if _, err := os.Stat(filepath.Join(chainDir, auditchain.SignKeyFileName)); err != nil {
		return nil, fmt.Errorf("the store has no signing key in %s (evidencestore init): %w", chainDir, err)
	}
	signer, err := auditchain.LoadOrCreateSigner(chainDir)
	if err != nil {
		return nil, err
	}
	return proof.SealStatement(signer.PublicKey()), nil
}

// readSeal — печать из файла: DER или PEM (CMS, PKCS7).
func readSeal(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if b, _ := pem.Decode(data); b != nil {
		if b.Type != "CMS" && b.Type != "PKCS7" {
			return nil, fmt.Errorf("a PEM block %q, not CMS", b.Type)
		}
		return b.Bytes, nil
	}
	return data, nil
}

// openSeal поднимает печать (seal.file): она цела и называет ключ этого
// хранилища — иначе старта нет. Метка над печатью — из data_dir/seal.tsr,
// если она над этой печатью.
func (s *Store) openSeal() error {
	path := s.cfg.Seal.File
	if path == "" {
		return nil
	}
	der, err := readSeal(path)
	if err != nil {
		return fmt.Errorf("seal.file: %w", err)
	}
	sealed, err := tsa.OpenSeal(der)
	if err != nil {
		return fmt.Errorf("seal.file %s: %w", path, err)
	}
	pub, err := proof.SealedStatementKey(sealed.Content)
	if err != nil {
		return fmt.Errorf("seal.file %s: %w", path, err)
	}
	if !pub.Equal(s.signer.PublicKey()) {
		return fmt.Errorf("seal.file %s vouches for another key than this store's: seal the statement evidencestore seal-statement prints", path)
	}
	s.sealCMS, s.sealBy = der, sealed.Signer.Subject.String()
	switch tok, err := os.ReadFile(filepath.Join(s.cfg.DataDir, sealTokenFile)); {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return fmt.Errorf("seal: %w", err)
	case tsa.Signed(tok, proof.SealImprint(der)) != nil:
		s.log.Warn("seal: the time-stamp in data_dir is over another seal: a new one is taken", "file", sealTokenFile)
	default:
		s.sealToken.Store(&tok)
	}
	s.log.Info("seal: the store key is sealed", "by", s.sealBy)
	return nil
}

// startSealLoop — метка над печатью, пока её нет: при запуске и раз в
// tsa.every.
func (s *Store) startSealLoop() {
	if s.sealCMS == nil || s.tsaURL == "" && s.tsaLocal == nil {
		return
	}
	s.loopNow(s.cfg.TSA.Every.D(), func() {
		if s.sealToken.Load() != nil {
			return
		}
		ctx, cancel := s.stopCtx(time.Minute)
		defer cancel()
		if err := s.StampSeal(ctx); err != nil {
			s.log.Error("seal: time-stamp", "err", err)
		}
	})
}

// StampSeal берёт у основной службы метку над печатью и кладёт её в
// data_dir/seal.tsr.
func (s *Store) StampSeal(ctx context.Context) error {
	if s.sealCMS == nil {
		return errors.New("seal: no seal.file")
	}
	imprint := proof.SealImprint(s.sealCMS)
	var token []byte
	var err error
	if s.tsaLocal != nil {
		token, err = s.tsaLocal.Sign(imprint[:], nil)
	} else {
		token, err = tsa.Request(ctx, s.tsaHTTP, s.tsaURL, imprint)
	}
	if err != nil {
		return err
	}
	if _, err := tsa.Verify(token, imprint, s.tsaTrust); err != nil {
		return fmt.Errorf("seal: TSA token rejected: %w", err)
	}
	if err := writeAtomic(filepath.Join(s.cfg.DataDir, sealTokenFile), token); err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	s.sealToken.Store(&token)
	s.log.Info("seal: time-stamped")
	return nil
}

// bundleSeal — печать с меткой для пакета; nil — печати нет.
func (s *Store) bundleSeal() *proof.StoreSeal {
	if s.sealCMS == nil {
		return nil
	}
	out := &proof.StoreSeal{CMS: s.sealCMS}
	if t := s.sealToken.Load(); t != nil {
		out.Token = *t
	}
	return out
}

// SealStatus — печать в status.
type SealStatus struct {
	By      string    `json:"by"`
	Stamped time.Time `json:"stamped,omitempty"` // время метки над печатью; ноль — ещё нет
}

func (s *Store) sealStatus() *SealStatus {
	if s.sealCMS == nil {
		return nil
	}
	st := &SealStatus{By: s.sealBy}
	if t := s.sealToken.Load(); t != nil {
		st.Stamped, _ = tsa.GenTime(*t)
	}
	return st
}
