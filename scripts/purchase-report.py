#!/usr/bin/env python3
# Отчёт по одной покупке ИИ-агента из пакета по субъекту (docs/purchases.md).
#
# Скрипт сам ничего не доказывает: он зовёт esverify и печатает отчёт, только
# если пакет прошёл проверку. Шаги покупки — квитанции шлюза платформы
# (receipt/v2, docs/receipts.md) из тел, которые esverify записал байт в байт
# (-bodies); время приёма — из заголовков улик пакета (их esverify сверил с
# листьями цепи). С -gateway-key esverify сам проверяет подпись платформы у
# каждой открытой квитанции; без него её проверило только хранилище при
# приёме. Подпись говорит, кто написал квитанцию, а не что написанное правда:
# дальше — пересказ шагов и сверки их между собой.
#
# Мандат внутри квитанции — отдельная подпись. С -mandate-key (открытый ключ
# подписавшего, PEM) скрипт проверяет её, если это компактный JWS с ES256
# (RFC 7515, 7518), через openssl, и тогда корзина сверяется с подписанными
# условиями, а не с тем, что написано в квитанции. Чьи это ключи —
# устанавливает проверяющий. SD-JWT с раскрытиями и привязкой ключа (так несёт
# мандаты AP2) не разбирается.
#
#   python3 scripts/purchase-report.py -proof p-1002.json -store-key store.pub \
#       -tsa-trust tsa-root.crt -purchase p-1002 [-gateway-key platform.pub] \
#       [-mandate-key customer.pub] [-esverify PATH] [-- флаги esverify]
#
# Код выхода: 0 — пакет проверен, отчёт напечатан (расхождения шагов — в отчёте);
# 1 — пакет не проверен или он о другой покупке; 2 — неверный вызов, это не
# пакет по субъекту или тела не открылись.
import argparse
import base64
import json
import os
import struct
import subprocess
import sys
import tempfile
import unicodedata
from datetime import datetime, timezone


def q(v, limit=160):
    """Значение из строки журнала — в отчёт: управляющие символы экранированы
    (строка журнала не должна дорисовывать отчёт), длинное обрезано."""
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    out = []
    for ch in s[:limit]:
        if ch == "\\" or unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out) + ("…" if len(s) > limit else "")


def money(v):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return q(v)
    return f"{v:,}".replace(",", " ")


def when(ns):
    return datetime.fromtimestamp(ns / 1e9, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def rfc3339(s):
    """Время из строки журнала или отчёта esverify; None — не время."""
    if not isinstance(s, str):
        return None
    s = s.strip().replace("Z", "+00:00")
    dot = s.find(".")
    if dot != -1:  # Go пишет до наносекунд, Python берёт микросекунды
        end = dot + 1
        while end < len(s) and s[end].isdigit():
            end += 1
        s = s[:dot] + "." + s[dot + 1:end][:6] + s[end:]
    try:
        t = datetime.fromisoformat(s)
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def stamp(s):
    t = rfc3339(s)
    return t.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if t else q(s)


def num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


B64URL = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def b64url(part):
    """Часть компактного JWS: base64url без дополнения. None — не она."""
    if not part or not set(part) <= B64URL or len(part) % 4 == 1:
        return None
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def der_int(b):
    b = b.lstrip(b"\x00") or b"\x00"
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def mandate_jws(credential, keyfile):
    """Подпись мандата — компактного JWS с ES256 — ключом из keyfile (PEM).

    Отдаёт (ok, kid, claims, why): ok — True (подпись сошлась), False (не
    сошлась) или None (проверить нельзя, причина — why); claims — подписанное
    содержимое, только при ok = True: неподписанному верить нечему.
    """
    parts = credential.split(".") if isinstance(credential, str) else []
    raw = [b64url(x) for x in parts]
    if len(parts) != 3 or None in raw:
        return None, None, None, "the credential is not a compact JWS (three base64url parts)"
    try:
        header = json.loads(raw[0])
    except ValueError:
        header = None
    if not isinstance(header, dict):
        return None, None, None, "the JWS header is not a JSON object"
    kid = header.get("kid") if isinstance(header.get("kid"), str) else None
    if header.get("alg") != "ES256":
        return None, kid, None, f'its algorithm is "{q(header.get("alg"))}", and this script checks ES256 only'
    if len(raw[2]) != 64:
        return False, kid, None, "an ES256 signature is 64 bytes"
    # r ‖ s (RFC 7518, 3.4) → DER, как его читает openssl.
    body = der_int(raw[2][:32]) + der_int(raw[2][32:])
    with tempfile.TemporaryDirectory() as tmp:
        sig, msg = os.path.join(tmp, "sig.der"), os.path.join(tmp, "signed")
        with open(sig, "wb") as f:
            f.write(b"\x30" + bytes([len(body)]) + body)
        with open(msg, "wb") as f:
            f.write((parts[0] + "." + parts[1]).encode("ascii"))
        try:
            run = subprocess.run(["openssl", "dgst", "-sha256", "-verify", keyfile, "-signature", sig, msg], capture_output=True)
        except OSError:
            return None, kid, None, "openssl is not installed"
    out = run.stdout.decode(errors="replace")
    if run.returncode == 0 and "Verified OK" in out:
        try:
            claims = json.loads(raw[1])
        except ValueError:
            claims = None
        if not isinstance(claims, dict):
            return None, kid, None, "the signature verifies, but what was signed is not a JSON object"
        return True, kid, claims, ""
    if "Verification failure" in out or "Verification Failure" in out:
        return False, kid, None, ""
    err = (run.stderr.decode(errors="replace").strip().splitlines() or ["openssl gave no reason"])[0]
    return None, kid, None, "openssl could not check it: " + err


SIGNED_FIELDS = ("purchase_id", "customer", "instruction", "scope")


def signed_against_line(claims, line):
    """Чем квитанция мандата расходится с подписанным: (расходятся, не подписаны).
    line — поля шага с номером покупки: purchase_id — это action квитанции."""
    differ = [k for k in SIGNED_FIELDS if k in claims and claims[k] != line.get(k)]
    unsigned = [k for k in SIGNED_FIELDS if k not in claims]
    return differ, unsigned


def receipt_of(raw):
    """Квитанция шлюза из тела: (шаг, поля шага, одобрение, ссылки) или None."""
    try:
        r = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(r, dict) or r.get("v") != 2 or not isinstance(r.get("step"), str):
        return None
    body = r.get("body") if isinstance(r.get("body"), dict) else {}
    approval = r.get("approval") if isinstance(r.get("approval"), dict) else None
    refs = [x for x in r.get("refs") or [] if isinstance(x, dict)]
    return r["step"], dict(body, purchase_id=r.get("action")), approval, refs


def main():
    ap = argparse.ArgumentParser(allow_abbrev=False, description="Print a verified purchase bundle as the story of that purchase.")
    ap.add_argument("-proof", required=True, help="the bundle: evidencestore proof -source S -subject ID -from FROM -to TO")
    ap.add_argument("-store-key", required=True, dest="store_key", help="pinned store public key, as for esverify")
    ap.add_argument("-tsa-trust", required=True, dest="tsa_trust", help="TSA certificates, as for esverify")
    ap.add_argument("-purchase", help="the purchase you asked about: a bundle about another one is refused")
    ap.add_argument("-gateway-key", dest="gateway_key", help="the platform's gateway public key (64 hex or a file): esverify checks the signature of every open receipt with it")
    ap.add_argument("-mandate-key", dest="mandate_key", help="public key (PEM) of whoever signed the mandate: its signature is checked (a compact JWS with ES256, through openssl), and the cart is compared with what was signed")
    ap.add_argument("-esverify", default="esverify", help="path to esverify (default: from PATH)")
    ap.add_argument("extra", nargs="*", help="after --: more esverify flags, e.g. -from, -to, -witness-key, -tsa-crl")
    a = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        cmd = [a.esverify, "-proof", a.proof, "-store-key", a.store_key, "-tsa-trust", a.tsa_trust,
               "-json", "-bodies", os.path.join(tmp, "bodies")] + (["-gateway-key", a.gateway_key] if a.gateway_key else []) + a.extra
        try:
            run = subprocess.run(cmd, capture_output=True)
        except OSError as e:
            print(f"purchase-report: cannot run {a.esverify}: {e}", file=sys.stderr)
            sys.exit(2)
        try:
            rep = json.loads(run.stdout)
        except ValueError:
            rep = None
        if run.returncode != 0 or not isinstance(rep, dict) or rep.get("valid") is not True:
            print("NOT VERIFIED: no report is printed for a bundle that esverify does not accept")
            for c in (rep or {}).get("checks") or []:
                if not c.get("OK"):
                    print(f"  ✘ {q(c.get('Name', ''), 300)}" + (f" — {q(c.get('Detail'), 300)}" if c.get("Detail") else ""))
            err = run.stderr.decode(errors="replace").strip()
            if err:
                print("  esverify: " + q(err, 600))
            sys.exit(run.returncode if run.returncode in (1, 2) else 1)

        subj = rep.get("subject")
        if rep.get("kind") != "source" or not isinstance(subj, dict):
            print("purchase-report: this is not a bundle for one subject: ask the store with -source, -subject, -from and -to", file=sys.stderr)
            sys.exit(2)
        if a.purchase is not None and subj.get("value") != a.purchase:
            print(f'NOT YOUR PURCHASE: the bundle is about "{q(subj.get("value"))}", you asked about "{q(a.purchase)}"')
            sys.exit(1)

        # Время приёма — из заголовка улики: version(1) | seq(8) | received_at(8) | …
        received = {}
        with open(a.proof, "rb") as f:
            bundle = json.load(f)
        for r in bundle.get("records") or []:
            if r.get("evidence"):
                raw = base64.b64decode(r["evidence"])
                seq, ns = struct.unpack(">QQ", raw[1:17])
                received[seq] = ns

        lines = []  # (номер, квитанция или None, сырые байты)
        bdir = os.path.join(tmp, "bodies")
        for name in os.listdir(bdir) if os.path.isdir(bdir) else []:
            seq = int(name.rsplit("-", 1)[1])
            raw = open(os.path.join(bdir, name), "rb").read()
            lines.append((seq, receipt_of(raw), raw))
        lines.sort(key=lambda x: x[0])

    pid = subj.get("value")
    print(f'PURCHASE "{q(pid)}" — source "{q(rep.get("source"))}", field "{q(subj.get("field"))}"')
    print()
    print("Verified by esverify with the keys you gave:")
    print(f"  the lines below are byte for byte what the store received, each between T1 = {stamp(rep.get('lower'))}")
    print(f"  and T2 = {stamp(rep.get('upper'))} (TSA time-stamps), and no record of the source in the window is left out.")
    print(f"  Window (receive time): {stamp(rep.get('from'))} – {stamp(rep.get('to'))}"
          + (" (as named in the bundle: pass your own after --, with -from and -to)" if rep.get("window_from_bundle") else ""))
    print(f"  Lines of this purchase: {subj.get('records')}, open: {subj.get('opened')}. "
          f"Other lines of the source in the window: {subj.get('others')}, closed: {subj.get('others_closed')}.")
    rc = rep.get("gateway_receipts") or {}
    if not rc:
        print("  The source is not a gateway receipt source: no signature of the platform covers the lines.")
    elif rc.get("gateway_key_checked"):
        print(f"  Every line is a receipt the platform signed: esverify checked {rc.get('signatures_checked')} of {rc.get('opened')} with the gateway key you gave.")
    else:
        print("  Every line is a receipt the platform signed: the store checked the signatures at intake (give -gateway-key to check them yourself).")
    print("  A signature shows who wrote a line, not that it is true. The mandate inside carries a signature of its own,")
    print("  checked only with -mandate-key.")

    withheld = subj.get("withheld") or 0
    incomplete = []
    if (subj.get("records") or 0) - withheld != subj.get("opened"):
        incomplete.append(f"{(subj.get('records') or 0) - withheld - (subj.get('opened') or 0)} line(s) of this purchase did not open: their keys are not in the bundle")
    for key, what in (("no_label_months", "the bundle names no label"), ("unbound_months", "no body of this purchase opens"),
                      ("unconfirmed_months", "the label is not confirmed by an open body"), ("leaf_only_months", "records come without evidence")):
        if rep.get(key) or subj.get(key):
            incomplete.append(f"months where {what}: {q(rep.get(key) or subj.get(key))}")
    if not rep.get("source_named", True):
        incomplete.append("the source tails do not name this source: compare the name above with the one you expect")
    if incomplete:
        print()
        print("INCOMPLETE — this report may miss lines of the purchase:")
        for s in incomplete:
            print(f"  ✘ {s}")
    if withheld:
        broken = ", ".join(str(x) for x in rep.get("gateway_broken") or [])
        print()
        print(f"NOT THE PLATFORM'S — {withheld} line(s) under this purchase's label the store found broken at intake")
        print(f"  (broken records of the source: {broken}): a signature that is not the platform's, a gap in its chain, or a line")
        print("  out of format. Their bodies are not opened, and nothing below relies on them; a single-record bundle shows what is wrong.")

    by = {}
    approvals = {}
    for seq, r, raw in lines:
        step = r[0] if r else None
        by.setdefault(step, []).append((seq, r[1] if r else None, raw))
        if r:
            approvals[seq] = (r[2], r[3])

    signed = {}  # номер строки мандата → итог проверки его подписи

    def head(title, seq):
        t = f", received {when(received[seq])}" if seq in received else ""
        print(f"\n{title} [record {seq}{t}]")

    def first(event):
        return by[event][0] if by.get(event) else None

    for seq, o, _ in by.get("mandate", []):
        sc = o.get("scope") if isinstance(o.get("scope"), dict) else {}
        head("Mandate: what the customer allowed", seq)
        print(f"  customer {q(o.get('customer'))} asked for: {q(o.get('instruction'))}")
        print(f"  allowed: up to {money(sc.get('price_cap'))} {q(sc.get('currency'))} at {q(', '.join(map(str, sc.get('merchants') or [])) or '—')}, until {stamp(sc.get('expires'))}")
        appr = approvals.get(seq, (None, None))[0] or {}
        cred = appr.get("credential") if appr.get("format") == "jws" else None
        if appr and not cred:
            print(f"  signed mandate: carried as {q(appr.get('format'))}, which this script does not check")
        elif not cred:
            print("  signed mandate: not in the receipt")
        elif not a.mandate_key:
            print(f"  signed mandate: carried in the receipt, {len(str(cred))} characters; its signature is not checked (give the signer's public key with -mandate-key)")
        else:
            ok, kid, claims, why = signed.setdefault(seq, mandate_jws(cred, a.mandate_key))
            verdict = "the signature verifies under the key you gave" if ok else "the signature does NOT verify under the key you gave" if ok is False else "not checked: " + why
            print(f"  signed mandate: carried in the receipt, {len(str(cred))} characters" + (f', key id "{q(kid)}"' if kid else "") + f"; {verdict}")
            ssc = claims.get("scope") if ok and isinstance(claims.get("scope"), dict) else None
            if ssc is not None and ssc != sc:
                print(f"  SIGNED, and the receipt differs from it: up to {money(ssc.get('price_cap'))} {q(ssc.get('currency'))} at {q(', '.join(map(str, ssc.get('merchants') or [])) or '—')}, until {stamp(ssc.get('expires'))}")
    for seq, o, _ in by.get("agent_verified", []):
        head("Agent: who acted", seq)
        print(f"  {q(o.get('agent_id'))}, key {q(o.get('key_id'))}, checked by {q(o.get('checked_by'))}: {q(o.get('result'))}")
    for seq, o, _ in by.get("cart", []):
        head("Cart: what the agent bought", seq)
        for it in o.get("items") if isinstance(o.get("items"), list) else []:
            if isinstance(it, dict):
                print(f"  {q(it.get('qty'))} × {q(it.get('name'))} ({q(it.get('sku'))}) at {money(it.get('price'))}")
        print(f"  at {q(o.get('merchant'))}, total {money(o.get('total'))} {q(o.get('currency'))}")
    for seq, o, _ in by.get("notification", []):
        head("Notification: the customer was told", seq)
        print(f"  by {q(o.get('channel'))}; could cancel until {stamp(o.get('cancel_until'))}")
    for seq, o, _ in by.get("cancel", []):
        head("Cancellation", seq)
        print(f"  by {q(o.get('by'))}, through {q(o.get('channel'))}")
    for seq, o, _ in by.get("payment", []):
        head("Payment", seq)
        print(f"  {money(o.get('amount'))} {q(o.get('currency'))}, {q(o.get('method'))} {q(o.get('token_ref'))}, {q(o.get('authentication'))}, reference {q(o.get('network_ref'))}")
        for ref in approvals.get(seq, (None, []))[1]:
            print(f"  the receipt names it as {q(ref.get('subject'))} in source {q(ref.get('source'))}: a bundle of that source shows the other side's records")
    for seq, o, _ in by.get("delivery", []):
        head("Delivery", seq)
        print(f"  {q(o.get('carrier'))} {q(o.get('tracking'))}: {q(o.get('status'))}")
    known = {"mandate", "agent_verified", "cart", "notification", "cancel", "payment", "delivery"}
    for event, items in by.items():
        if event in known:
            continue
        for seq, o, raw in items:
            head("Another step" if o else "A line that is not a gateway receipt", seq)
            print("  " + q(raw.decode(errors="replace").rstrip("\n"), 300))

    # Сверки строк между собой. True — сходится, False — расходится, None — сказать нельзя.
    checks = []
    m, cart, pay = first("mandate"), first("cart"), first("payment")
    if by.get("cart"):
        cart = ([c for c in by["cart"] if not pay or c[0] < pay[0]] or by["cart"])[-1]  # корзина, по которой платили
    sc = m[1].get("scope") if m and isinstance(m[1].get("scope"), dict) else {}
    checks.append((bool(m), "a mandate is recorded" if m else "no mandate receipt: nothing here shows what the customer allowed"))
    the_mandate = "the mandate"  # с чем сверяется корзина: с квитанцией или с подписанным
    m_appr = (approvals.get(m[0], (None, None))[0] or {}) if m else {}
    if m and not a.mandate_key:
        checks.append((None, "the mandate's signature was not checked (no -mandate-key): what the customer allowed is the platform's word"))
    elif m and m_appr.get("format") != "jws":
        checks.append((False, "the mandate receipt carries no signed mandate this script can check (a compact JWS)"))
    elif m:
        ok, _, claims, why = signed[m[0]]
        if ok is None:
            checks.append((None, "the mandate's signature was not checked: " + why))
        elif not ok:
            checks.append((False, "the mandate's signature does NOT verify under the key you gave" + (f" ({why})" if why else "") + ": what the customer allowed is only the platform's word"))
        else:
            checks.append((True, "the mandate's signature verifies under the key you gave"))
            if "purchase_id" not in claims:
                checks.append((None, "the signed mandate does not name the purchase: it could have been signed for another one"))
            elif claims["purchase_id"] != pid:
                checks.append((False, f'the signed mandate is for another purchase: "{q(claims["purchase_id"])}"'))
            differ, unsigned = signed_against_line(claims, m[1])
            if differ:
                checks.append((False, f"the mandate receipt differs from what was signed in: {', '.join(differ)}"))
            else:
                checks.append((True, "the mandate receipt says what was signed" + (f" (not covered by the signature: {', '.join(unsigned)})" if unsigned else "")))
            if isinstance(claims.get("scope"), dict):
                sc, the_mandate = claims["scope"], "the signed mandate"
                if differ:
                    checks.append((None, "the cart is compared below with the signed mandate, not with the receipt"))
    for event in ("mandate", "cart", "payment"):
        if len(by.get(event, [])) > 1:
            checks.append((None, f"{len(by[event])} {event} receipts: the report compares the " + ("first mandate" if event == "mandate" else "last cart before the payment" if event == "cart" else "first payment")))
    ag = by.get("agent_verified", [])
    if not ag:
        checks.append((None, "no receipt says the agent's identity was checked"))
    else:
        bad = [s for s, o, _ in ag if o.get("result") != "ok"]
        checks.append((not bad, "the agent's identity check is recorded as ok" if not bad else f"the agent's identity check did not pass (record {bad[0]})"))
    if m and cart:
        allowed = sc.get("merchants") if isinstance(sc.get("merchants"), list) else None
        if allowed is None:
            checks.append((None, f"{the_mandate} names no merchants to compare the cart with"))
        else:
            ok = cart[1].get("merchant") in allowed
            checks.append((ok, f"the merchant of the cart is {'one ' + the_mandate + ' allows' if ok else 'not among those ' + the_mandate + ' allows'} ({q(cart[1].get('merchant'))})"))
        cap, total = num(sc.get("price_cap")), num(cart[1].get("total"))
        if cap is None or total is None:
            checks.append((None, "the price cap or the cart total is not a number"))
        else:
            same = sc.get("currency") == cart[1].get("currency")
            ok = same and total <= cap
            checks.append((ok, f"the cart total is {'within' if ok else 'over' if same else 'in another currency than'} {the_mandate}'s price cap ({money(total)} {q(cart[1].get('currency'))} against {money(cap)} {q(sc.get('currency'))})"))
        exp = rfc3339(sc.get("expires"))
        if exp is None or cart[0] not in received:
            checks.append((None, f"{the_mandate}'s expiry cannot be compared with the time the cart was received"))
        else:
            ok = received[cart[0]] / 1e9 <= exp.timestamp()
            checks.append((ok, f"the store received the cart {'before' if ok else 'AFTER'} {the_mandate} expired ({when(received[cart[0]])} against {stamp(sc.get('expires'))})"))
    if cart:
        items = cart[1].get("items") if isinstance(cart[1].get("items"), list) else []
        parts = [num(i.get("qty")) is not None and num(i.get("price")) is not None for i in items if isinstance(i, dict)]
        if items and all(parts) and len(parts) == len(items) and num(cart[1].get("total")) is not None:
            s = sum(i["qty"] * i["price"] for i in items)
            checks.append((s == cart[1]["total"], f"the items add up to the cart total ({money(s)} against {money(cart[1]['total'])})"))
    cancels = by.get("cancel", [])
    if pay:
        note = [n for n in by.get("notification", []) if n[0] < pay[0]]
        checks.append((bool(note), "the customer was notified before the payment" if note else "no notification receipt lies before the payment"))
        early = [c for c in cancels if c[0] < pay[0]]
        if early:
            checks.append((False, f"a cancellation is recorded (record {early[0][0]}) BEFORE the payment (record {pay[0]})"))
        elif cancels:
            checks.append((None, f"a cancellation is recorded (record {cancels[0][0]}) after the payment (record {pay[0]})"))
        else:
            checks.append((True, "no cancellation is recorded among the receipts of this purchase"))
        if cart:
            a1, t1 = num(pay[1].get("amount")), num(cart[1].get("total"))
            ok = a1 is not None and a1 == t1 and pay[1].get("currency") == cart[1].get("currency")
            checks.append((ok, f"the amount paid {'equals' if ok else 'differs from'} the cart total ({money(pay[1].get('amount'))} {q(pay[1].get('currency'))} against {money(cart[1].get('total'))} {q(cart[1].get('currency'))})"))
        else:
            checks.append((False, "a payment is recorded without a cart receipt before it"))
        checks.append((bool(by.get("delivery")), "a delivery is recorded" if by.get("delivery") else "no delivery receipt is recorded"))
    elif cancels:
        checks.append((True, f"the purchase was cancelled (record {cancels[0][0]}), and no payment is recorded"))
    else:
        checks.append((None, "no payment receipt is recorded"))

    print("\nThe steps compared with each other (record numbers give the order the receipts were written in):")
    for ok, text in checks:
        print(f"  {'✔' if ok else '✘' if ok is False else '?'} {text}")
    bad = sum(1 for ok, _ in checks if ok is False)
    print()
    print(f"{bad} of these comparisons disagree{'s' if bad == 1 else ''}." if bad else "The steps agree with each other.")
    print(f"esverify's notes on what this bundle does not prove: {len(rep.get('notes') or [])} (run esverify on the bundle to read them).")
    sys.exit(0)


if __name__ == "__main__":
    main()
