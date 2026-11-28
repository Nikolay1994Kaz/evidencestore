package pginput

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
)

// История линий времени — так, как её отдаёт сервер после двух переключений
// (TIMELINE_HISTORY 3 на стенде experiments/pg-ha).
func TestParseTimelineHistory(t *testing.T) {
	got, err := parseTimelineHistory("1\t0/36E9B28\tno recovery target specified\n\n2\t0/370FE18\tno recovery target specified\n")
	if err != nil || len(got) != 2 || got[0] != (timelineSwitch{1, 0x36E9B28}) || got[1] != (timelineSwitch{2, 0x370FE18}) {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := parseTimelineHistory("# comment\n\n"); err != nil || got != nil {
		t.Fatalf("an empty history: %v %v", got, err)
	}
	for _, bad := range []string{"x\t0/1\twhy", "1\tnot-a-place\twhy", "1", "2\t0/20\ta\n1\t0/30\tb", "1\t0/30\ta\n2\t0/20\tb"} {
		if got, err := parseTimelineHistory(bad); err == nil {
			t.Errorf("%q is taken as a history: %v", bad, got)
		}
	}
}

// tlIntent — намерение с отметками базы: запуск и линия времени (0 — шлюз
// линию не пишет).
func tlIntent(id string, gw time.Time, xid uint32, started time.Time, timeline uint32) gateway.Draft {
	d := intent(id, gw, fmt.Sprint(xid))
	body := fmt.Sprintf(`{"agent":"bot","tool":"execute","xid8":"%d","db_started":"%d"`, xid, started.UnixMicro())
	if timeline != 0 {
		body += fmt.Sprintf(`,"db_timeline":"%d"`, timeline)
	}
	d.Body = json.RawMessage(body + "}")
	return d
}

// Кластер переключился на реплику (линия 2 → 3 на месте 0x200), ничего из
// прочитанного не потеряно: намерения остаются в счёте, но каждое решает
// только транзакцию своей линии. Прежняя основная выдала номер 761 действию,
// которое до реплики не дошло; новая выдаёт 761 чужой транзакции — намерение
// прежней основной её не решает.
func TestIntentDecidesOnlyATransactionOfItsTimeline(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	start := now.Add(-time.Hour) // обе базы запущены давно: реплика — не позже основной
	g.sign("esmcp.jsonl", tlIntent("before", now.Add(-3*time.Second), 760, start, 2))
	g.sign("esmcp.jsonl", tlIntent("lost", now.Add(-2*time.Second), 761, start, 2))
	g.sign("esmcp.jsonl", tlIntent("after", now.Add(-time.Second), 762, start, 3))
	g.sign("esmcp.jsonl", tlIntent("unmarked", now.Add(-time.Second), 763, start, 0))
	g.sign("esmcp.jsonl", tlIntent("at-the-switch", now.Add(-time.Second), 765, start, 3))
	g.r.setTimelines(3, []timelineSwitch{{1, 0x100}, {2, 0x200}})
	// Фиксация ровно на месте, где прежняя линия кончилась, — уже новой линии.
	if in, ok, _ := g.r.Intent(765, now, 0x200); !ok || in.ID != "at-the-switch" {
		t.Error("a transaction committed at the very place of the switch is not taken as one of the new timeline")
	}
	if in, ok, _ := g.r.Intent(760, now, 0x1f0); !ok || in.ID != "before" {
		t.Error("an action committed on the earlier timeline, read after the switchover, is not taken by its intent")
	}
	if _, ok, _ := g.r.Intent(761, now, 0x210); ok {
		t.Error("an intent written on the earlier primary decides a transaction the new primary gave the same number to")
	}
	if in, ok, _ := g.r.Intent(762, now, 0x220); !ok || in.ID != "after" {
		t.Error("an action on the new primary is not taken by its intent")
	}
	if _, ok, _ := g.r.Intent(763, now, 0x230); !ok {
		t.Error("an intent without the timeline mark (another gateway) is refused by the timeline")
	}
	// Историю линий сервер не дал — по линии не сверяется ничего.
	g.r.setTimelines(0, nil)
	if _, ok, _ := g.r.Intent(761, now, 0x210); !ok {
		t.Error("without the server's timeline history an intent is refused by its timeline")
	}
}

// База ушла назад, пока сборщик читал линию 2 (отставшая реплика заняла
// место основной): намерения линии 2 не в счёт, а намерения новой основной,
// линии 3, — в счёте, хотя запущена она раньше границы. До отметки линии
// такие шли отпечатком, пока новую основную не перезапустят.
func TestVoidSparesTheNewTimeline(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	start, place := now.Add(-time.Hour), now.Add(-10*time.Minute)
	g.sign("esmcp.jsonl", tlIntent("old", now.Add(-11*time.Minute), 751, start, 2))
	g.sign("esmcp.jsonl", tlIntent("unmarked", now.Add(-11*time.Minute), 753, start, 0))
	if err := g.r.void(voidSpec{startedBefore: place.UnixMicro(), timeline: 2}); err != nil {
		t.Fatal(err)
	}
	g.r.setTimelines(3, []timelineSwitch{{2, 0x200}})
	g.sign("esmcp.jsonl", tlIntent("new", now, 752, start, 3))
	g.sign("esmcp.jsonl", tlIntent("same-line", now, 754, start, 2)) // прежней истории, прочитано позже
	check := func(when string) {
		t.Helper()
		g.r.setTimelines(3, []timelineSwitch{{2, 0x200}})
		if _, ok, _ := g.r.Intent(751, now, 0x250); ok {
			t.Errorf("%s: an intent of the timeline the database left decides a transaction", when)
		}
		if _, ok, _ := g.r.Intent(753, now, 0x250); ok {
			t.Errorf("%s: an intent without the timeline mark, of a database started before the bound, decides a transaction", when)
		}
		if _, ok, _ := g.r.Intent(754, now, 0x250); ok {
			t.Errorf("%s: an intent of the timeline the database left, read after the void, decides a transaction", when)
		}
		if in, ok, _ := g.r.Intent(752, now, 0x260); !ok || in.ID != "new" {
			t.Errorf("%s: an intent of the new primary is void: it was started before the bound, but its timeline is newer", when)
		}
	}
	check("at once")
	g.open() // сборщик перезапущен: граница и линия — из receipts.json
	check("after a restart")
}

// Состояние прежней версии: граница по запуску есть, линии при ней нет.
// Отметка линии тогда ничего не снимает с намерения: что было до границы, по
// состоянию не узнать.
func TestVoidWithoutATimelineKeepsTheStartRule(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	start, place := now.Add(-time.Hour), now.Add(-10*time.Minute)
	if err := g.r.void(voidSpec{startedBefore: place.UnixMicro()}); err != nil {
		t.Fatal(err)
	}
	g.sign("esmcp.jsonl", tlIntent("old-start", now, 752, start, 3))
	g.sign("esmcp.jsonl", tlIntent("new-start", now, 755, now.Add(-time.Minute), 3))
	if _, ok, _ := g.r.Intent(752, now, 0x260); ok {
		t.Error("with no timeline in the void an intent of a database started before the bound decides a transaction")
	}
	if _, ok, _ := g.r.Intent(755, now, 0x270); !ok {
		t.Error("an intent of a database started after the bound is void")
	}
}

// Чистое переключение кластера (switched): намерения с отметкой линии
// остаются в счёте, а без неё — прочитанные до сих пор не в счёт: по такому
// намерению не узнать, на какой основной оно писалось. Дописанные позже — в
// счёте. Так и после перезапуска сборщика.
func TestSwitchoverVoidsOnlyIntentsWithoutATimeline(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	start := now.Add(-time.Hour)
	g.sign("esmcp.jsonl", tlIntent("lined", now.Add(-3*time.Second), 760, start, 2))
	g.sign("esmcp.jsonl", tlIntent("started-only", now.Add(-2*time.Second), 761, start, 0)) // esmcp прежней версии
	g.sign("esmcp.jsonl", intent("unmarked", now.Add(-2*time.Second), "762"))               // другой шлюз
	if err := g.r.switched(); err != nil {
		t.Fatal(err)
	}
	g.sign("esmcp.jsonl", tlIntent("started-only-after", now, 763, start, 0))
	g.sign("esmcp.jsonl", intent("unmarked-after", now, "764"))
	check := func(when string) {
		t.Helper()
		g.r.setTimelines(3, []timelineSwitch{{2, 0x200}})
		if _, ok, _ := g.r.Intent(760, now, 0x1f0); !ok {
			t.Errorf("%s: an intent with the timeline mark is void after a switchover", when)
		}
		for _, xid := range []uint32{761, 762} {
			if _, ok, _ := g.r.Intent(xid, now, 0x210); ok {
				t.Errorf("%s: intent %d without the timeline mark, written before the switchover, decides a transaction of the new primary", when, xid)
			}
		}
		for _, xid := range []uint32{763, 764} {
			if _, ok, _ := g.r.Intent(xid, now.Add(time.Second), 0x220); !ok {
				t.Errorf("%s: intent %d without the timeline mark, written after the switchover, is void", when, xid)
			}
		}
	}
	check("at once")
	g.open()
	check("after a restart")
}

// База ушла назад на той же линии времени (копия каталога, поднятая снова):
// линия у прежней и новой истории одна, и намерения различает запуск базы,
// как и без отметки линии.
func TestVoidOnTheSameTimelineGoesByTheStart(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	oldStart, place, newStart := now.Add(-time.Hour), now.Add(-10*time.Minute), now.Add(-5*time.Minute)
	g.sign("esmcp.jsonl", tlIntent("old", now.Add(-11*time.Minute), 751, oldStart, 2))
	if err := g.r.void(voidSpec{startedBefore: place.UnixMicro(), timeline: 2}); err != nil {
		t.Fatal(err)
	}
	g.r.setTimelines(2, nil)
	g.sign("esmcp.jsonl", tlIntent("old-late", now, 753, oldStart, 2)) // прежней истории, прочитано позже
	g.sign("esmcp.jsonl", tlIntent("new", now, 752, newStart, 2))
	for _, xid := range []uint32{751, 753} {
		if _, ok, _ := g.r.Intent(xid, now, 0x250); ok {
			t.Errorf("intent %d of the history before the restore, on the same timeline, decides a transaction", xid)
		}
	}
	if in, ok, _ := g.r.Intent(752, now, 0x260); !ok || in.ID != "new" {
		t.Error("an intent of the restored database, started after the bound, is void")
	}
}
