package store

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/mod/sumdb/tlog"

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

// servedHeadLocked — голова, которую хранилище отдаёт наружу: сборщикам и
// по evidencestore statement. С копией наружу — та, что держит копия, как у
// свидетеля голов (P-11): подъём из копии обрывает цепь не раньше её, и
// честный подъём не выглядит переписью тому, кто её хранит. Без копии —
// текущая. ok = false — отдавать нечего: копия с запуска ещё не прошла или
// цепь пуста. Подпись повторяется только при новой голове. Звать под chainMu.
func (s *Store) servedHeadLocked() (proof.Checkpoint, bool, error) {
	n := s.tree.size()
	m := n
	if s.replicaRemote != nil {
		m = min(m, s.replicaShipped.Load())
	}
	if m == 0 {
		return proof.Checkpoint{}, false, nil
	}
	if s.servedHead.Size != m {
		root := s.tree.root()
		if m < n {
			h, err := tlog.TreeHash(int64(m), s.tree)
			if err != nil {
				return proof.Checkpoint{}, false, err
			}
			if err := s.tree.agreesLocked(m, h); err != nil {
				return proof.Checkpoint{}, false, err
			}
			root = h
		}
		s.servedHead = proof.SignCheckpoint(s.signer, m, root)
	}
	return s.servedHead, true, nil
}

// CollectorCheckpoint — голова для сборщика (сборщики-свидетели, п. 31,
// servedHeadLocked) и доказательство, что она продолжает голову из from
// звеньев, которую сборщик принял последней (from = 0 — ещё не принимал).
// ok = false — отдавать нечего. Сборщик, который принял голову новее отдаваемой (хранилище потеряло
// хвост цепи без копии), получает её без доказательства — для него это
// расхождение, и так и есть. Доказательство берётся из tree.hashes и до
// отдачи сверяется с корнем, подписанным по границе в памяти: испорченный
// файл дал бы сборщику ложную развилку — тогда голова идёт без
// доказательства, а ошибка — хранилищу.
func (s *Store) CollectorCheckpoint(from uint64) (_ proof.Checkpoint, consistency [][]byte, ok bool, _ error) {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	c, ok, err := s.servedHeadLocked()
	if !ok || err != nil {
		return c, nil, false, err
	}
	m := c.Size
	if from == 0 || from >= m {
		return c, nil, true, nil
	}
	p, err := tlog.ProveTree(int64(m), int64(from), s.tree)
	if err != nil {
		return c, nil, true, err
	}
	old, err := tlog.TreeHash(int64(from), s.tree)
	if err != nil {
		return c, nil, true, err
	}
	if tlog.CheckTree(p, int64(m), tlog.Hash(c.RootHash()), int64(from), old) != nil {
		return c, nil, true, errTreeFile
	}
	for _, h := range p {
		consistency = append(consistency, h[:])
	}
	return c, consistency, true, nil
}
