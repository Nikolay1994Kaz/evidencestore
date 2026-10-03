package auditchain

import (
	"fmt"
)

// Чтение цепи для сверки и доказательств.
//
// ⚠ВСЁ ЗДЕСЬ ЛИНЕЙНО И ЗНАЕТ ОБ ЭТОМ. Цепь не компактится, поэтому «прошли по
// журналу» — операция, цена которой растёт вечно: замерено 415-453 нс на
// звено на проверку и 442-813 нс на чтение, то есть 27-40 с на годовую цепь
// (verify_bench_test.go). Отсюда два правила, которые видны в сигнатурах:
// поиск идёт ОТ КОНЦА и ограничен окном, а обход отчитывается о том, сколько
// успел прочесть.

// Coverage — сколько журнала прочитано. Если обход оборвался ошибкой, по
// нему видно, докуда журнал цел.
type Coverage struct {
	Links          int    // звеньев в цепи
	HeadSeq        uint64 // последнее звено
	FirstLeafKnown uint64 // первый прочитанный лист
	LeavesRead     int    // сколько листьев прочитано
}

// ForEachLeaf проходит листья от старых к новым.
//
// Листья не удаляются никогда, поэтому пропавший файл листьев — ошибка
// (ErrLeavesMissing), как и порча. В ядре, откуда пришёл этот код, листья
// жили по сроку хранения и пропажа считалась штатной; для улик это была бы
// тихая потеря.
func ForEachLeaf(dir string, fn func(Leaf)) (Coverage, error) {
	var cov Coverage
	links, err := ReadChain(dir)
	if err != nil {
		return cov, err
	}
	cov.Links = len(links)
	if len(links) > 0 {
		cov.HeadSeq = links[len(links)-1].Seq
	}
	first := true
	for i, link := range links {
		p, err := DecodeBatchPayload(link.Payload)
		if err != nil {
			return cov, fmt.Errorf("auditchain: звено %d: %w", i, err)
		}
		leaves, err := ReadLeaves(dir, p.FirstLeaf, int(p.Count))
		if err != nil {
			return cov, fmt.Errorf("auditchain: листья звена %d: %w", i, err)
		}
		if first {
			cov.FirstLeafKnown = p.FirstLeaf
			first = false
		}
		cov.LeavesRead += len(leaves)
		for _, l := range leaves {
			fn(l)
		}
	}
	return cov, nil
}

// LeafQuery — что ищем для доказательства включения.
type LeafQuery struct {
	Type     EventType
	Scope    string
	Subject  string // пусто = не сравнивать (у сводных событий предмета нет)
	MaxLinks int    // сколько звеньев просмотреть с конца; 0 = разумное окно
}

// defaultSearchLinks — окно поиска по умолчанию.
//
// Поиск идёт от конца, потому что доказывают обычно СВЕЖУЮ квитанцию. Окно
// нужно, чтобы команда не превращалась в полный проход по цепи молча: при
// промахе честнее сказать «в последних N звеньях не найдено», чем потратить
// полминуты и ответить «нет».
const defaultSearchLinks = 100_000

// FindLeaf ищет событие в цепи, начиная с самых новых звеньев.
// Возвращает звено, все листья его батча и позицию найденного среди них —
// ровно то, из чего строится путь Меркла.
func FindLeaf(dir string, q LeafQuery) (Record, []Leaf, int, error) {
	links, err := ReadChain(dir)
	if err != nil {
		return Record{}, nil, 0, err
	}
	window := q.MaxLinks
	if window <= 0 {
		window = defaultSearchLinks
	}
	stop := 0
	if len(links) > window {
		stop = len(links) - window
	}
	for i := len(links) - 1; i >= stop; i-- {
		p, err := DecodeBatchPayload(links[i].Payload)
		if err != nil {
			return Record{}, nil, 0, fmt.Errorf("auditchain: звено %d: %w", i, err)
		}
		leaves, err := ReadLeaves(dir, p.FirstLeaf, int(p.Count))
		if err != nil {
			return Record{}, nil, 0, fmt.Errorf("auditchain: листья звена %d: %w", i, err)
		}
		for idx, l := range leaves {
			if l.Type != q.Type || l.Scope != q.Scope {
				continue
			}
			if q.Subject != "" && l.Subject != q.Subject {
				continue
			}
			return links[i], leaves, idx, nil
		}
	}
	return Record{}, nil, 0, fmt.Errorf("auditchain: событие не найдено в последних %d звеньях (всего %d)",
		window, len(links))
}

// VerifyRange проверяет отрезок цепи от звена from до головы.
//
// ⭐Отрезок, а не всё, потому что полный проход измерен и не влезает в бюджет
// команды: 27-40 с на годовой цепи. from = 0 запрашивает полный проход явно.
// Нулевое from и пустая цепь — не ошибка: проверять нечего, голова нулевая.
func VerifyRange(dir string, from uint64, want *Head) (Head, int, error) {
	links, err := ReadChain(dir)
	if err != nil {
		return Head{}, 0, err
	}
	if from == 0 {
		head, err := Verify(links, want)
		return head, len(links), err
	}
	if from > uint64(len(links)) {
		return Head{}, 0, fmt.Errorf("auditchain: в цепи %d звеньев, сверка запрошена с %d", len(links), from)
	}
	// Звено from становится опорой: его хеш берётся как данность, дальше
	// проверяется связность. Это ровно то, что делает аудитор с прошлым
	// подписанным заявлением на руках.
	base := links[from-1]
	head := Head{Seq: base.Seq, Hash: Hash(base)}
	rest := links[from:]
	for i, r := range rest {
		if r.Seq != head.Seq+1 {
			return Head{}, 0, fmt.Errorf("auditchain: звено %d имеет seq %d, ожидался %d — цепь с пропуском",
				from+uint64(i), r.Seq, head.Seq+1)
		}
		if r.PrevHash != head.Hash {
			return Head{}, 0, fmt.Errorf("auditchain: звено seq %d не связано с предыдущим — прошлое переписано", r.Seq)
		}
		head = Head{Seq: r.Seq, Hash: Hash(r)}
	}
	if want != nil {
		if want.Seq != head.Seq {
			return Head{}, 0, fmt.Errorf("auditchain: в журнале %d звеньев, голова помнит %d — хвост обрезан",
				head.Seq, want.Seq)
		}
		if want.Hash != head.Hash {
			return Head{}, 0, fmt.Errorf("auditchain: голова журнала не совпадает с сохранённой — цепь подменена")
		}
	}
	return head, len(rest), nil
}
