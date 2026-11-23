package proof

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
)

// Пакет по сделке (DECISIONS, п. 42): одно действие шлюза, известное в
// нескольких источниках. Квитанции действия называют, под какими номерами оно
// там известно (refs: xid транзакции у источника базы). Пакет по сделке — это
// пакеты по субъекту за одно окно: источника квитанций (метка — номер
// действия) и каждого источника, который квитанции называют (метка — номер
// там). Каждый проверяется своими правилами (VerifySource), а связывает их
// открытая квитанция: метки разных источников не совпадают и совпадать не
// должны (п. 32).
//
// Сделка доказана, когда все пакеты проходят, у действия в окне открыты все
// квитанции (связь закрытой не видна), и на каждый номер из refs есть пакет,
// где открыты все его записи окна, а пакетов, которых квитанции не называют,
// нет.

// DealLink — источник и номер в нём, названные квитанциями действия.
type DealLink struct {
	Source  string `json:"source"`
	Subject string `json:"subject"`
	// Receipts — номера записей квитанций у их источника, назвавших его.
	Receipts []uint64 `json:"receipts"`
	// Bundle — номер пакета в linked (с нуля); -1 — пакета нет.
	Bundle int `json:"bundle"`
	// Records, Opened — записей этого номера в окне пакета и открытых из них.
	Records int `json:"records"`
	Opened  int `json:"opened"`
}

// DealReport — итог сведения пакетов сделки.
type DealReport struct {
	Checks  []Check
	Action  string
	Gateway string
	// Receipts — открытых квитанций действия; Signed — из них с подписью,
	// проверенной ключом проверяющего (KeyChecked — ключ задан).
	Receipts   int
	Signed     int
	KeyChecked bool
	Links      []DealLink
}

// Valid — все проверки прошли.
func (r DealReport) Valid() bool {
	for _, c := range r.Checks {
		if !c.OK {
			return false
		}
	}
	return len(r.Checks) > 0
}

// Verdict — итог одной строкой.
func (r DealReport) Verdict() string {
	if r.Valid() {
		return "VERIFIED"
	}
	return "NOT VERIFIED"
}

// fullyOpen — у пакета по субъекту открыты все записи субъекта в окне, и ни
// одна не может прятаться: ни без ключа, ни под меткой месяца без открытого
// тела, ни в месяце, которому пакет метки не называет. Пусто — так.
func fullyOpen(r SourceReport) string {
	switch {
	case r.Subject == "":
		return "it is not a bundle by subject (evidencestore proof -source S -subject X -from -to)"
	case r.SubjectRecords == 0:
		return fmt.Sprintf("no record of %q in the window", r.Subject)
	case r.SubjectKeyless > 0:
		return fmt.Sprintf("%d of its %d records in the window come without their record keys", r.SubjectKeyless, r.SubjectRecords)
	case r.SubjectOpened != r.SubjectRecords:
		return fmt.Sprintf("%d of its %d records in the window are open", r.SubjectOpened, r.SubjectRecords)
	case r.SubjectUnbound > 0:
		return fmt.Sprintf("%d records are under its label in %s, where no body of it is open: whose they are is not shown", r.SubjectUnbound, QuotedList(r.SubjectUnboundMonths))
	case r.SubjectNoLabel > 0:
		return fmt.Sprintf("the bundle names no label for %s, and its records there, if any, are not shown", QuotedList(r.SubjectNoLabelMonths))
	case len(r.SubjectUnconfirmedMonths) > 0:
		// Метку месяца связывает с субъектом только открытое тело этого
		// месяца, а подписи на метках нет (P-75): кто держит пакет до
		// проверяющего, может назвать для такого месяца любую метку и снять
		// ключи его записей — и все открытые записи останутся «всеми» (R1-1).
		return fmt.Sprintf("no body of it is open in %s, and only an open body of a month ties that month's label to it: its records there, if any, are not shown; "+
			"ask for a window inside the months where the action has records", QuotedList(r.SubjectUnconfirmedMonths))
	}
	return ""
}

// LinkDeal сводит проверенные пакеты сделки: receipts — пакет по субъекту
// источника квитанций (метка — номер действия), linked — пакеты источников,
// которые квитанции называют.
func LinkDeal(receipts SourceReport, linked []SourceReport) DealReport {
	r := DealReport{Action: receipts.Subject, KeyChecked: receipts.ReceiptKeyChecked}
	add := func(name string, err error, ok string) {
		c := Check{Name: name, OK: err == nil, Detail: ok}
		if err != nil {
			c.Detail = err.Error()
		}
		r.Checks = append(r.Checks, c)
	}
	var bad []string
	if !receipts.Valid() {
		bad = append(bad, "the receipts bundle")
	}
	for i, l := range linked {
		if !l.Valid() {
			bad = append(bad, fmt.Sprintf("linked bundle %d (%s)", i+1, l.Source))
		}
	}
	var badErr error
	if len(bad) > 0 {
		badErr = fmt.Errorf("%s: NOT VERIFIED (its report is below)", strings.Join(bad, ", "))
	}
	add("every bundle of the deal verifies on its own", badErr, fmt.Sprintf("%d bundles", 1+len(linked)))

	// Квитанции действия — все открыты: связь закрытой квитанции не видна.
	var recErr error
	switch {
	case !receipts.Receipts:
		recErr = fmt.Errorf("the first bundle (-proof) is of source %s, which holds no gateway receipts (receipt/v1): a deal starts at the receipts of an action", receipts.Source)
	case receipts.SubjectField != "" && receipts.SubjectField != "action":
		recErr = fmt.Errorf("the receipts bundle is by %q; a deal is by the action (subject_field \"action\")", receipts.SubjectField)
	default:
		if why := fullyOpen(receipts); why != "" {
			recErr = fmt.Errorf("the receipts of action %q: %s", receipts.Subject, why)
		}
	}
	// Что квитанции называют.
	at := map[[2]string]int{}
	gateways := map[string]bool{}
	if recErr == nil {
		for _, body := range receipts.Bodies {
			rc, err := gateway.ParseReceipt(body.Body)
			if err != nil {
				recErr = fmt.Errorf("record %s/%d: %w", receipts.Source, body.Seq, err)
				break
			}
			if rc.Action != receipts.Subject {
				recErr = fmt.Errorf("record %s/%d is a receipt of action %q, not of %q", receipts.Source, body.Seq, rc.Action, receipts.Subject)
				break
			}
			gateways[rc.Gateway] = true
			r.Gateway = rc.Gateway
			r.Receipts++
			for _, ref := range rc.Refs {
				k := [2]string{ref.Source, ref.Subject}
				i, seen := at[k]
				if !seen {
					i = len(r.Links)
					at[k] = i
					r.Links = append(r.Links, DealLink{Source: ref.Source, Subject: ref.Subject, Bundle: -1})
				}
				if !slices.Contains(r.Links[i].Receipts, body.Seq) {
					r.Links[i].Receipts = append(r.Links[i].Receipts, body.Seq)
				}
			}
		}
		if recErr == nil && len(gateways) > 1 {
			recErr = fmt.Errorf("the receipts of action %q are of %d gateways: an action is one gateway's", receipts.Subject, len(gateways))
		}
	}
	if receipts.ReceiptKeyChecked {
		r.Signed = receipts.ReceiptsSigned
	}
	detail := fmt.Sprintf("action %q of gateway %s: %d receipts open", r.Action, r.Gateway, r.Receipts)
	if r.KeyChecked {
		detail += fmt.Sprintf(", %d signatures checked with your gateway key", r.Signed)
	} else {
		detail += "; their signatures were checked by the store at intake (give -gateway-key to check them yourself)"
	}
	add("every receipt of the action in the window is open, and they are of one gateway", recErr, detail)

	// Каждый названный номер — в своём пакете, открыт целиком и за то же окно.
	var linkErr []string
	used := make([]bool, len(linked))
	for i := range r.Links {
		l := &r.Links[i]
		for j, b := range linked {
			if b.Source != l.Source || b.Subject != l.Subject {
				continue
			}
			if l.Bundle >= 0 {
				linkErr = append(linkErr, fmt.Sprintf("%s %q is in linked bundles %d and %d", l.Source, l.Subject, l.Bundle+1, j+1))
				continue
			}
			l.Bundle, used[j] = j, true
			l.Records, l.Opened = b.SubjectRecords, b.SubjectOpened
			if why := fullyOpen(b); why != "" {
				linkErr = append(linkErr, fmt.Sprintf("%s %q (linked bundle %d): %s", l.Source, l.Subject, j+1, why))
			}
			if !b.From.Equal(receipts.From) || !b.To.Equal(receipts.To) {
				linkErr = append(linkErr, fmt.Sprintf("%s %q (linked bundle %d) is over %s–%s, and the receipts over %s–%s: a deal is over one window",
					l.Source, l.Subject, j+1, b.From.Format(timeFmt), b.To.Format(timeFmt), receipts.From.Format(timeFmt), receipts.To.Format(timeFmt)))
			}
		}
		if l.Bundle < 0 {
			linkErr = append(linkErr, fmt.Sprintf("receipt %s/%v names %s %q, and no linked bundle is of it (evidencestore proof -source %s -subject %s -from -to)",
				receipts.Source, l.Receipts, l.Source, l.Subject, l.Source, l.Subject))
		}
	}
	for j, b := range linked {
		if !used[j] && !slices.ContainsFunc(r.Links, func(l DealLink) bool { return l.Source == b.Source && l.Subject == b.Subject }) {
			linkErr = append(linkErr, fmt.Sprintf("linked bundle %d (%s %q) is named by no receipt of the action", j+1, b.Source, b.Subject))
		}
	}
	var lerr error
	if recErr != nil {
		lerr = fmt.Errorf("not checked: the receipts are not all open")
	} else if len(linkErr) > 0 {
		lerr = fmt.Errorf("%s", strings.Join(linkErr, "; "))
	}
	var named []string
	for _, l := range r.Links {
		named = append(named, fmt.Sprintf("%s %q: %d records, %d open", l.Source, l.Subject, l.Records, l.Opened))
	}
	if len(named) == 0 {
		named = append(named, "the receipts name no record of another source")
	}
	add("every record the receipts name is in a linked bundle over the same window, all of it open, and every linked bundle is named", lerr, strings.Join(named, "; "))
	return r
}

// timeFmt — время окна в тексте поломки.
const timeFmt = "2006-01-02T15:04:05.999999999Z07:00"

// Text — отчёт о сведении текстом: вердикт, действие, связи, проверки, и
// что сведение не доказывает. Имена и номера пришли из пакетов — в кавычках.
func (r DealReport) Text() string {
	var b strings.Builder
	verdict := r.Verdict()
	b.WriteString(verdict + "\n\n")
	fmt.Fprintf(&b, "Deal: action %q", r.Action)
	if r.Gateway != "" {
		fmt.Fprintf(&b, " of gateway %q", r.Gateway)
	}
	fmt.Fprintf(&b, ", %d receipts open\n", r.Receipts)
	for _, l := range r.Links {
		where := "no linked bundle"
		if l.Bundle >= 0 {
			where = fmt.Sprintf("linked bundle %d: %d records, %d open", l.Bundle+1, l.Records, l.Opened)
		}
		fmt.Fprintf(&b, "  named by receipts %v: %q %q — %s\n", l.Receipts, l.Source, l.Subject, where)
	}
	b.WriteString("\nChecks:\n")
	for _, c := range r.Checks {
		mark := "✔"
		if !c.OK {
			mark = "✘"
		}
		fmt.Fprintf(&b, "  %s %s", mark, c.Name)
		if c.Detail != "" {
			b.WriteString(" — " + strings.ReplaceAll(c.Detail, "\n", `\n`))
		}
		b.WriteString("\n")
	}
	b.WriteString("\nWhat the deal does not prove:\n")
	for _, n := range r.Notes() {
		b.WriteString("  — " + n + "\n")
	}
	return Printable(b.String()) + "\n" + verdict + "\n"
}

// Notes — чего сведение пакетов не доказывает.
func (r DealReport) Notes() []string {
	return []string{
		"the link is what the gateway's receipts say: a gateway that names a wrong transaction in its intent is believed; the database cannot vouch for whose a transaction is",
		"records of the action outside the window are not here: a window is the auditor's question, and an action that runs over its edges shows only its part",
		"each bundle's own notes below hold for it",
	}
}
