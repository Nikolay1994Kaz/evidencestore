package store

import (
	"context"
	"fmt"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
)

// Канал свидетеля голов (witness.url; решение 25.10, DECISIONS «Свидетель
// голов»). Туда уходят только подписанные головы цепи — номер, хэш,
// подпись, — без журнала улик и тел. Держит его не тот, кто администрирует
// хранилище: проверяющий или другая организация. Голова у свидетеля
// закрепляет цепь до неё, и пакет из цепи, переписанной после этого, с ней не
// сойдётся (esverify -heads).
//
// Уходят голова под каждой меткой TSA — ею кончается пакет (P-06), и просить
// пакет длиннее не нужно — и текущая голова раз в witness.every. Ключ —
// heads/<номер>.json, как в копии наружу. Очередь живёт в памяти: головы под
// метками, не ушедшие до остановки, после запуска не досылаются, и пакет по
// их уликам просят до следующей головы свидетеля (proof -to-head).

// witnessHead — голова в очереди к свидетелю; stamped — над ней метка TSA.
type witnessHead struct {
	head    auditchain.Head
	stamped bool
}

// queueWitnessLocked ставит голову в очередь к свидетелю. Ещё не ушедшая
// текущая голова из очереди уходит: новая голова её накрывает. Головы под
// метками остаются все — ими кончаются пакеты, — так что, пока свидетель
// недоступен, очередь растёт только ими. Зовётся под chainMu.
func (s *Store) queueWitnessLocked(h auditchain.Head, stamped bool) {
	if s.witnessRemote == nil || h.Seq == 0 || h.Seq <= s.witnessQueued {
		return
	}
	if n := len(s.witnessQueue); n > 0 && !s.witnessQueue[n-1].stamped {
		s.witnessQueue = s.witnessQueue[:n-1]
	}
	s.witnessQueue = append(s.witnessQueue, witnessHead{head: h, stamped: stamped})
	s.witnessQueued = h.Seq
}

// WitnessOnce ставит в очередь текущую голову и отправляет свидетелю очередь
// по порядку. Неудача — остаток очереди ждёт следующего прохода.
func (s *Store) WitnessOnce(ctx context.Context) error {
	if s.witnessRemote == nil {
		return nil
	}
	s.chainMu.Lock()
	s.queueWitnessLocked(s.chain.Head(), false)
	queue := append([]witnessHead(nil), s.witnessQueue...)
	s.chainMu.Unlock()
	for _, h := range queue {
		data, err := s.signer.Sign(h.head, int(h.head.Seq), s.nowTime().Unix()).JSON()
		if err != nil {
			return err
		}
		if err := s.witnessRemote.Put(ctx, fmt.Sprintf("heads/%020d.json", h.head.Seq), data); err != nil {
			s.witnessErrors.Add(1)
			return fmt.Errorf("witness: head %d: %w", h.head.Seq, err)
		}
		s.chainMu.Lock()
		if len(s.witnessQueue) > 0 && s.witnessQueue[0] == h {
			s.witnessQueue = s.witnessQueue[1:]
		}
		s.chainMu.Unlock()
		s.witnessOK.Store(time.Now().UnixNano())
	}
	return nil
}
