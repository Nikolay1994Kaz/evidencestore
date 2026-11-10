package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// P-105 (тестировщик T, третий раунд; R1, R2). Список версий, снятый
// страницами (aws s3api list-object-versions --max-items, затем
// --starting-token; у всех страниц, кроме последней, NextToken), сделал бы
// свидетелем S3 каждую страницу, и честный пакет просили бы до первой головы
// последней страницы. Сверка отказывает с советом склеить список.
func TestHeadsPagedVersionsList(t *testing.T) {
	w := newLyWorld(t)
	all := w.objs("witness", lyAWS, 0)
	dir := t.TempDir()
	pages := [][]lyObj{all[:3], all[3:6], all[6:]} // ключи по порядку: 2 3 8 | 10 11 12 | 13 14
	for i, p := range pages {
		next := ""
		if i < len(pages)-1 {
			next = fmt.Sprintf("eyJLZXlNYXJrZXIiOiBudWxsLCAiYm90b190cnVuY2F0ZV9hbW91bnQiOiAzfQ==%d", i)
		}
		lyWrite(t, filepath.Join(dir, fmt.Sprintf("versions-%d.json", i+1)), versionsPage(p, false, next))
	}
	writeVersionFiles(t, dir, all, byVID)
	code, text, _ := w.verify(w.honest, dir)
	if code != exitInvalid || !strings.Contains(text, "is one page of several") || !strings.Contains(text, "without --max-items") {
		t.Fatalf("список версий страницами: код %d\n%s", code, grepLine(text, "agrees with the heads"))
	}
	// Склеенный в один файл — честный пакет проходит.
	one := t.TempDir()
	lyWrite(t, filepath.Join(one, "versions.json"), versionsPage(all, false, ""))
	writeVersionFiles(t, one, all, byVID)
	if code, text, rep := w.verify(w.honest, one); code != exitValid || jsonWitness(rep) != lyOK8 {
		t.Fatalf("список одним файлом: код %d %s\n%s", code, jsonWitness(rep), grepLine(text, "agrees with the heads"))
	}
}

func grepLine(out, sub string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, sub) {
			return l
		}
	}
	return ""
}
