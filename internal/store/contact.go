package store

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
)

// Связь со сборщиком (P-05; DECISIONS «Устройство», п. 26). Сборщик выходит
// на связь отправкой, а когда отправлять нечего, — пульсом раз в
// heartbeat_every (GET /v1/state). Хранилище помнит последнее обращение
// каждого источника, которое пропустил Admit; отказанные (чужая эпоха) не в
// счёт: подменённый сборщик не прикрывает пропажу настоящего. Нет обращений
// дольше expect_contact — в цепь событие «сборщик пропал» с последним
// контактом; вернулся — «вернулся» с окном, когда журнал источника никто не
// читал. Тихий журнал с живым сборщиком — не пропажа, а молчание
// (expect_every, CheckSilence).
//
// Отсчёт — не раньше старта хранилища: его собственный простой — не
// пропажа сборщика. Эпизод, начатый до рестарта, продолжается: «пропал» без
// «вернулся» в цепи — сборщик ещё не вернулся (replayContact).
//
// Предел: root на машине источника держит сертификат, ключ и эпоху
// сборщика и подделает пульс тем же запросом; окно короче expect_contact не
// видно.

// Виды события EventContact (Subject).
const (
	contactLost = "lost"
	contactBack = "back"
)

// noteContact — Admit пропустил запрос сборщика источника: тот на связи.
func (s *Store) noteContact(source string) {
	now := s.nowTime()
	s.mu.Lock()
	if st := s.sources[source]; st != nil {
		if !st.lostSince.IsZero() && st.backAt.IsZero() {
			st.backAt = now // им кончается окно без связи
		}
		st.contactAt = now
	}
	s.mu.Unlock()
}

// CheckContact пишет в цепь «сборщик пропал», если сборщик источника не
// выходил на связь дольше expect_contact, и «вернулся», когда он снова на
// связи. Событие одно на эпизод.
func (s *Store) CheckContact(now time.Time) {
	type change struct {
		name, subject string
		payload       map[string]any
	}
	var found []change
	s.mu.Lock()
	for name, st := range s.sources {
		expect := st.cfg.ExpectContact.D()
		if !st.known || st.cfg.Disabled || expect == 0 {
			continue
		}
		if !st.lostSince.IsZero() {
			if !st.backAt.IsZero() {
				found = append(found, change{name, contactBack, map[string]any{"since": st.lostSince.UTC(), "back": st.backAt.UTC()}})
				st.lostSince, st.backAt = time.Time{}, time.Time{}
			}
			continue
		}
		last := st.contactAt
		if last.Before(s.opened) {
			last = s.opened // и ноль: с запуска обращений ещё не было
		}
		if now.Sub(last) > expect {
			st.lostSince = last
			found = append(found, change{name, contactLost, map[string]any{"since": last.UTC(), "expect_contact": expect.String()}})
		}
	}
	s.mu.Unlock()
	for _, f := range found {
		s.appendJSONEvent(auditchain.EventContact, f.name, f.subject, f.payload)
		if f.subject == contactLost {
			s.log.Warn("collector lost: no contact from the source's collector", "source", f.name, "since", f.payload["since"])
		} else {
			s.log.Info("collector back", "source", f.name, "since", f.payload["since"], "back", f.payload["back"])
		}
	}
}

// replayContact — событие связи из цепи при подъёме: эпизод «сборщик
// пропал» без «вернулся» продолжается.
func (s *Store) replayContact(num uint64, l auditchain.Leaf) error {
	st := s.sources[l.Scope]
	if st == nil {
		return nil
	}
	switch l.Subject {
	case contactLost:
		var ev struct {
			Since time.Time `json:"since"`
		}
		if err := json.Unmarshal(l.Payload, &ev); err != nil {
			return fmt.Errorf("chain leaf %d: collector contact: %w", num, err)
		}
		st.lostSince = ev.Since
	case contactBack:
		st.lostSince = time.Time{}
	}
	return nil
}
