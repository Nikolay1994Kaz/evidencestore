package store

import (
	"context"
	"fmt"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Канал свидетеля голов (witness.url; решение 25.10, DECISIONS «Свидетель
// голов»). Туда уходят только подписанные головы цепи — контрольные точки
// (число звеньев и корень дерева над ними, п. 30), без журнала улик и тел. Держит его не тот, кто администрирует
// хранилище: проверяющий или другая организация. Голова у свидетеля
// закрепляет цепь до неё, и пакет из цепи, переписанной после этого, с ней не
// сойдётся (esverify -heads).
//
// Уходят голова под каждой меткой TSA — ею кончается пакет одной улики
// (P-06), — голова звена её токена — им кончаются пакеты за окно и по
// источнику (Q-23), — и текущая голова раз в witness.every. Ключ —
// heads/<номер>.json, как в копии наружу. Очередь живёт в памяти: головы под
// метками, не ушедшие до остановки, после запуска не досылаются, и пакет по
// их уликам просят до следующей головы свидетеля (proof -to-head).
//
// Свидетель не обгоняет копию наружу: когда она есть, уходят только головы,
// до которых копия держит цепь после удачного прохода. Иначе подъём из копии
// оборвал бы цепь раньше головы, которую свидетель уже видел, и под теми же
// номерами поднятое хранилище написало бы другое — для свидетеля развилка
// (P-11). Головы дальше копии ждут в очереди её следующего прохода.

// witnessHead — голова в очереди к свидетелю: число звеньев и корень дерева
// над ними, снятые с границы в памяти; stamped — над ней метка TSA.
type witnessHead struct {
	size    uint64
	root    [32]byte
	stamped bool
}

// queueWitnessLocked ставит текущую голову в очередь к свидетелю. Ещё не
// ушедшая текущая голова из очереди уходит: новая голова её накрывает.
// Головы под метками остаются все — ими кончаются пакеты, — так что, пока
// свидетель недоступен, очередь растёт только ими. Зовётся под chainMu.
func (s *Store) queueWitnessLocked(stamped bool) {
	h := witnessHead{size: s.tree.size(), root: s.tree.root(), stamped: stamped}
	if s.witnessRemote == nil || h.size == 0 {
		return
	}
	if h.size <= s.witnessQueued {
		// Голова уже в очереди или у свидетеля. Голова под меткой встаёт в
		// очередь, когда создаётся (хвосты перед запросом, stamp), — раньше
		// любой текущей новее неё.
		return
	}
	if n := len(s.witnessQueue); n > 0 && !s.witnessQueue[n-1].stamped {
		s.witnessQueue = s.witnessQueue[:n-1]
	}
	s.witnessQueue = append(s.witnessQueue, h)
	s.witnessQueued = h.size
}

// WitnessOnce ставит в очередь текущую голову и отправляет свидетелю очередь
// по порядку. Неудача — остаток очереди ждёт следующего прохода.
func (s *Store) WitnessOnce(ctx context.Context) error {
	if s.witnessRemote == nil {
		return nil
	}
	s.chainMu.Lock()
	s.queueWitnessLocked(false)
	queue := append([]witnessHead(nil), s.witnessQueue...)
	s.chainMu.Unlock()
	limit := ^uint64(0)
	if s.replicaRemote != nil {
		limit = s.replicaShipped.Load()
	}
	for _, h := range queue {
		if h.size > limit {
			break // очередь по возрастанию: дальше — тоже за копией
		}
		data, err := proof.SignCheckpoint(s.signer, h.size, h.root).JSON()
		if err != nil {
			return err
		}
		if err := s.witnessRemote.Put(ctx, fmt.Sprintf("heads/%020d.json", h.size), data); err != nil {
			s.witnessErrors.Add(1)
			return fmt.Errorf("witness: head %d: %w", h.size, err)
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
