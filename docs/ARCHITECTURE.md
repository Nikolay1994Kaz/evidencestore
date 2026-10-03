# Карта кода

Написано для разбора: что где лежит, как по коду идёт одна улика, какие свойства держат какие тесты и в каком порядке читать. Почему выбрано именно так — в [DECISIONS.md](DECISIONS.md), теория — на странице «evidencestore от А до Я».

## Путь одной улики

```
источник (файл журнала АБС, рекордер Pipelock)
   │
   ▼
escollect ─ cmd/escollect, internal/collector
   строка → номер Seq → буфер на диске (вместе с позицией в файле) → пачка
   │  HTTPS, TLS 1.3, клиентский сертификат (CN = источник)
   ▼
server ─ internal/server
   источник берётся из сертификата; JSON → store.Ingest
   │
   ▼
store.Ingest ─ internal/store/ingest.go           ┐
   повтор (Source, Seq)? → время приёма (монотонно)│ синхронно,
   → evidence.Record.Seal (keyring: DEK под KEK)   │ до ответа
   → evlog.Append: запись, fsync пачки              │ «принято»
   → лист цепи (из потока журнала, по порядку)     │
   → подписанное обещание (proof.Promise)          ┘
   │
   ▼ в фоне (internal/store/jobs.go)
   звено раз в тик · метка TSA над головой → токен листом в цепь ·
   ключи месяцев (завести, закрыть, уничтожить по заявке) · молчание источников
   │
   ▼
store.Proof → proof.Bundle ─ internal/store/proofs.go
   │  JSON-файл проверяющему
   ▼
esverify ─ cmd/esverify, internal/proof
   офлайн: ключ хранилища, сертификаты TSA (у НУЦ — root_rsa_2020)
```

## Пакеты

| Пакет | Что делает | Главные файлы | Тесты |
|---|---|---|---|
| `internal/evidence` | формат улики: заголовок открыто, тело конвертом; отпечаток `SHA-256("evidencestore/sealed/v1" ‖ байты)` | `record.go`, `seal.go` | золотые байты, обрезки, фазз, стирание |
| `internal/keyring` | ключи: корень → KEK месяца → DEK записи; формат KRNG2; уничтожение поворотом корня; состояния и двухэтапное уничтожение | `keyring.go`, `format.go`, `envelope.go`, `lifecycle.go`, `destroy.go`, `rootfile.go` | 17 тестов, 35 мутаций |
| `internal/evlog` | журнал улик: групповой коммит, ответ после fsync, сегменты только дописываются, fail-stop | `evlog.go` | 9 тестов, 10 мутаций |
| `internal/auditchain` | цепь (ядро): листья, звено с корнем Меркла, голова в двух слотах, подписанное заявление Ed25519 | `carrier.go`, `chain.go`, `merkle.go`, `export.go` | тесты ядра + `TestReadersDoNotTruncate` |
| `internal/tsa` | RFC 3161: запрос, офлайн-проверка CMS до корня, встроенная демо-служба | `tsa.go`, `local.go`, `testdata/` (настоящий токен НУЦ) | 11 тестов (один — живой НУЦ, по переменным окружения), 10 мутаций |
| `internal/proof` | пакет доказательств и его проверка; обещание при приёме | `proof.go`, `promise.go` | синтетическая цепь: каждая проверка — свой тест |
| `internal/store` | движок: приём, цепь, метки, ключи, полнота, выдача доказательств, восстановление после падения, копия наружу и восстановление из неё | `store.go`, `ingest.go`, `chain.go`, `keys.go`, `jobs.go`, `proofs.go`, `replica.go` | 12 тестов (падение, откат кейринга, стирание, копия…) |
| `internal/server` | HTTPS-приём с mTLS и админка через unix-сокет | `server.go` | mTLS, источник из сертификата, админка |
| `internal/collector` | сборщик: файл → буфер → пачки; обещания хранилища | `collector.go` | доставка, рестарт без дублей, ротация (с дочитыванием старого файла), переустановка, длинные строки |
| `internal/config` | конфигурация JSON и реестр источников | `config.go` | предел пути сокета; остальное — через тесты движка и сервера |
| `internal/pki` | учебный УЦ для стенда | `pki.go` | через тесты сервера |
| `cmd/evidencestore` | сервер и команды оператора | `main.go` | демо |
| `cmd/esverify` | утилита проверяющего | `main.go` | демо |
| `cmd/escollect` | сборщик | `main.go` | демо |
| `internal/ship` | ядро: используется только транспорт `Remote` (S3 с SigV4, каталог) | `remote.go`, `s3_remote.go`, `file_remote.go` | свои тесты |
| `internal/wal` | ядро старого проекта, **не используется** (заменён `evlog`) | — | свои тесты |

## Что лежит на диске

```
data_dir/
  keyring.dat          ключи месяцев, заперты корнем; копия → keys.backup_dir
  evidence/seg_*.log   журнал улик; сегменты только дописываются
  chain/chain.log      звенья (append-only)
  chain/chain.head     голова, два слота с CRC
  chain/leaves_*.log   листья (не удаляются никогда)
  chain/sign.key       ключ подписи хранилища (Ed25519)
  tsa-local/           демо-TSA, если tsa.url = "local"
  admin.sock           админка, права 0600
  replica.json         докуда доехала копия наружу
roots_dir/             корни кейринга (FileRoots), отдельно от data_dir
keys.backup_dir/       копии keyring.dat и sign.key (секреты; не в копию наружу)
replica.url            копия: evidence/…, chain/… кусками по смещению, heads/<n>.json
```

Копия `keyring.dat` в резерве безопасна: без корня она бесполезна. Копия, где лежат и `data_dir`, и `roots_dir`, открывает всё, поэтому `config.Validate` запрещает вкладывать один каталог в другой.

## Свойства и кто их стережёт

| Свойство | Где обеспечено | Тест |
|---|---|---|
| «принято» только после fsync | `evlog.commit` | `TestFsyncFailureIsNotAcknowledged` |
| повтор безопасен | `store.Ingest` (индекс `seqIndex`) | `TestDuplicatesAndLastSeq` |
| источник только из сертификата | `server.source` | `TestSourceComesFromCertificate` |
| время приёма не идёт назад | `store.clockLocked` | `TestReceivedAtIsMonotonic` |
| после падения цепь досчитывается | `store.open` (хвост журнала → листья) | `TestCrashCatchUp` |
| потеря подтверждённой улики не скрывается | `store.open` (`ErrEvidenceLost`) | `TestLostEvidenceStopsStart` |
| подделка в пакете ловится | `proof.Verify` | `TestTamperingIsDetected`, тесты `internal/proof` |
| токен TSA проверяется до цепи | `store.Stamp` | `TestStampRejectsUntrustedToken` |
| правка любого байта токена ловится | `tsa.Verify` | `TestEveryByteOfTokenMatters` (и токен НУЦ) |
| уничтоженный ключ не открывается ни в одной копии | `keyring` (поворот корня) | `TestDestroy`, `TestDestroyWaitsForBackup` |
| уничтожение — только двое и не раньше срока | `keyring.ScheduleDestroy` | `TestLifecycle`, `TestRetentionErasure` |
| откат `keyring.dat` виден | `store.reconcileKeys` | `TestKeyringRollbackDetected` |
| пропуски и молчание — в цепи | `store.indexLocked`, `store.CheckSilence` | `TestGapsAndSilence` |
| сборщик не задваивает строки после падения | `collector` (позиция в буфере) | `TestRestartNoDuplicates` |
| ротация не теряет хвост старого файла; потеря — пропуск номера, а не тишина | `collector.ReadOnce` | `TestRotationDrainsOldFile`, `TestLostRotatedTailLeavesGap` |
| длинные строки не застревают в пределе запроса | `collector.SendOnce` (8 МиБ на пачку) | `TestBigLinesFitRequestLimit` |
| текущий месяц не закрывается случайно | `store.Deactivate` (`-force`) | `TestKeyringRollbackDetected`, `TestAdminProofAndKeys` |
| копия восстанавливается и сверяется с подписанной головой | `store.RestoreReplica` | `TestReplicaRestore` |
| отчёт проверяющего называет верную причину, почему тело закрыто | `proof.Report.Notes` | `TestNotesTellWhyBodyIsClosed` |
| слишком длинный путь сокета админки — ошибка конфига, а не `bind: invalid argument` | `config.Validate` | `TestAdminSocketPathLimit` |

## Как проверить

```
go build ./... && go vet ./... && go test -race ./...     # гейт
python3 scripts/mutate.py keyring|evlog|tsa|store|edge    # мутации: каждая поломка должна уронить тест
scripts/demo.sh                                           # демо на бинарниках, без интернета
DEMO_TSA=nca scripts/demo.sh                              # то же с настоящей TSA НУЦ РК
ES_TSA_URL=http://tsp.pki.gov.kz \
ES_TSA_ROOTS=configs/tsa/nca-kz/root_rsa_2020.cer,configs/tsa/nca-kz/nca_rsa_2022.cer \
  go test -run Live ./internal/tsa/                       # живой токен НУЦ
```

## Порядок чтения

1. `internal/evidence/record.go`: что такое улика.
2. `internal/keyring/keyring.go` (шапка), затем `envelope.go`: как запечатывается тело.
3. `internal/evlog/evlog.go` (шапка и `commit`): как улика ложится на диск.
4. `internal/store/ingest.go`: весь синхронный путь в одной функции.
5. `internal/store/chain.go` и `internal/auditchain/chain.go`: листья, звенья, голова.
6. `internal/store/jobs.go` (`Stamp`) и `internal/tsa/tsa.go` (шапка, `Verify`): метка НУЦ.
7. `internal/proof/proof.go` (шапка, `Verify`): что получает и проверяет проверяющий.
8. `internal/store/keys.go` и `internal/keyring/lifecycle.go`, `destroy.go`: жизнь ключа и стирание.
9. `scripts/demo.sh`: всё вместе.
