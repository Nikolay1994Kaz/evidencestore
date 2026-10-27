package store

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
)

// Эпоха сборщика — случайный идентификатор установки сборщика (его
// spool_dir), который сборщик шлёт с каждым запросом. Хранилище закрепляет
// за источником эпоху первой установки, вышедшей на связь, и отказывает
// установке с другой эпохой. Так из двух сборщиков с одним сертификатом
// встаёт новая установка, а не та, что отправила позже: раньше вставал
// любой из двух, в том числе законный, и тот потом не стартовал. Законную
// переустановку (потерян spool_dir) принимает оператор — BindEpoch.
//
// Закрепление — событие в цепи (EventEpoch): переживает рестарт и видно
// аудитору, как и отказы чужим установкам.
//
// Предел: копии одной установки (снимок ВМ, бэкап spool_dir) несут одну
// эпоху. Их различает сверка номеров: ErrStoreAhead у сборщика, конфликт
// номера у хранилища.

// ErrEpochMismatch — за источником закреплена другая установка сборщика.
var ErrEpochMismatch = errors.New("store: the source is bound to another collector installation")

// EpochLen — длина эпохи: 16 случайных байт в hex.
const EpochLen = 32

// ValidEpoch — эпоха: EpochLen строчных шестнадцатеричных цифр.
func ValidEpoch(e string) bool {
	if len(e) != EpochLen {
		return false
	}
	for i := 0; i < len(e); i++ {
		if c := e[i]; !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// epochEvent — предмет события EventEpoch.
type epochEvent struct {
	Epoch    string `json:"epoch"`              // эпоха запроса; "" — сборщик без эпохи
	Previous string `json:"previous,omitempty"` // закрепление: прежняя эпоха
	Bound    string `json:"bound,omitempty"`    // отказ: закреплённая эпоха
	Reason   string `json:"reason"`
}

const (
	epochFirstContact = "first contact"
	epochOperator     = "bound by operator"
	epochRefused      = "refused"
)

// Admit сверяет эпоху сборщика с закреплённой за источником. Эпоха первой
// установки, вышедшей на связь, закрепляется. Пустая эпоха — сборщик
// прежней версии: принимается, пока за источником ничего не закреплено.
//
// Ingest эпоху не сверяет: это делает сервер через Admit до приёма, как
// источник — по сертификату. Пропущенный запрос — контакт со сборщиком
// (contact.go); отказанный — нет.
func (s *Store) Admit(source, epoch string) error {
	if err := s.admit(source, epoch); err != nil {
		return err
	}
	s.noteContact(source)
	return nil
}

func (s *Store) admit(source, epoch string) error {
	if epoch != "" && !ValidEpoch(epoch) {
		return fmt.Errorf("%w: collector epoch %q is not %d hex digits", ErrBadRecord, epoch, EpochLen)
	}
	st, bound, err := s.epochOf(source)
	if err != nil || epoch == bound {
		return err
	}
	if bound == "" {
		s.epochMu.Lock()
		defer s.epochMu.Unlock()
		// Пока ждали замка, эпоху мог закрепить другой запрос.
		if _, bound, err = s.epochOf(source); err != nil || epoch == bound {
			return err
		}
		if bound == "" {
			return s.setEpochLocked(st, source, epochEvent{Epoch: epoch, Reason: epochFirstContact})
		}
	}
	return s.refuseEpoch(st, source, epoch, bound)
}

// BindEpoch закрепляет за источником эпоху сборщика по слову оператора:
// так принимается законная переустановка (потерян spool_dir). Прежняя
// установка с этого момента получает отказ.
func (s *Store) BindEpoch(source, epoch string) error {
	if !ValidEpoch(epoch) {
		return fmt.Errorf("%w: collector epoch %q is not %d hex digits", ErrBadRecord, epoch, EpochLen)
	}
	s.epochMu.Lock()
	defer s.epochMu.Unlock()
	st, bound, err := s.epochOf(source)
	if err != nil || epoch == bound {
		return err
	}
	return s.setEpochLocked(st, source, epochEvent{Epoch: epoch, Previous: bound, Reason: epochOperator})
}

// epochOf — источник из реестра и закреплённая за ним эпоха.
func (s *Store) epochOf(source string) (*sourceState, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.sources[source]
	if !ok || !st.known {
		return nil, "", fmt.Errorf("%w: %q", ErrUnknownSource, source)
	}
	return st, st.epoch, nil
}

// setEpochLocked закрепляет эпоху (вызывающий держит epochMu). Событие
// ложится в цепь звеном сразу, с fsync: закрепление не держится в памяти,
// иначе падение в первую секунду отдало бы источник следующей установке.
func (s *Store) setEpochLocked(st *sourceState, source string, ev epochEvent) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	at := s.lockChainAt()
	s.appendLeafLocked(auditchain.Leaf{
		UnixNano: at,
		Type:     auditchain.EventEpoch,
		Scope:    source,
		Payload:  payload,
	})
	err = s.flushLocked()
	s.chainMu.Unlock()
	if err != nil {
		return err
	}
	s.mu.Lock()
	st.epoch = ev.Epoch
	s.mu.Unlock()
	if ev.Previous != "" {
		s.log.Warn("collector epoch rebound by operator: the previous collector installation is refused from now on",
			"source", source, "epoch", ev.Epoch, "previous", ev.Previous)
	} else {
		s.log.Info("collector epoch bound", "source", source, "epoch", ev.Epoch, "reason", ev.Reason)
	}
	return nil
}

// maxRefusedEpochs — сколько разных отказанных эпох источника ложится в
// цепь за время работы процесса. Дальше — только счётчик: держатель
// сертификата источника с выдуманными эпохами не раздувает ни цепь, ни
// память.
const maxRefusedEpochs = 16

// refuseEpoch — отказ установке с чужой эпохой. В журнал и в цепь — один
// раз на эпоху за время работы процесса: отказанный сборщик
// останавливается, но повтор не должен засорять цепь.
//
// Закреплённая эпоха — только в журнал сервера и в цепь, в ответ её не
// пишем: в ответе она работала бы паролем. Самозванец с тем же
// сертификатом повторил бы запрос с ней, и два сборщика пошли бы под одной
// эпохой (B-03 вернулся бы). Свою эпоху сборщик знает и так.
func (s *Store) refuseEpoch(st *sourceState, source, epoch, bound string) error {
	st.epochRefused.Add(1)
	s.mu.Lock()
	if st.refusedEpochs == nil {
		st.refusedEpochs = map[string]bool{}
	}
	first := !st.refusedEpochs[epoch] && len(st.refusedEpochs) < maxRefusedEpochs
	if first {
		st.refusedEpochs[epoch] = true
	}
	s.mu.Unlock()
	if first {
		s.log.Error("collector refused: the source is bound to another collector installation",
			"source", source, "epoch", epoch, "bound", bound)
		s.appendJSONEvent(auditchain.EventEpoch, source, "", epochEvent{Epoch: epoch, Bound: bound, Reason: epochRefused})
	}
	if epoch == "" {
		return fmt.Errorf("%w (source %s); this collector sends no epoch (older version): upgrade it",
			ErrEpochMismatch, source)
	}
	return fmt.Errorf("%w (source %s); this collector is epoch %s; "+
		"if it replaces the bound one (reinstalled, spool_dir lost), accept it on the store host: "+
		"evidencestore sources bind -source %s -epoch %s",
		ErrEpochMismatch, source, epoch, source, epoch)
}
