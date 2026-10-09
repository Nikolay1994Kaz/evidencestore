# Карта кода

Написано для разбора: что где лежит, как по коду идёт одна улика, какие свойства держат какие тесты и в каком порядке читать. Почему выбрано именно так — в [DECISIONS.md](DECISIONS.md), теория — на странице «evidencestore от А до Я».

## Путь одной улики

```
источник (файл журнала АБС, рекордер Pipelock)
   │
   ▼
escollect ─ cmd/escollect, internal/collector
   строка (файл или файлы по маске — шарды Pipelock) → номер Seq →
   буфер на диске (вместе с позицией в файле) → пачка
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
   → журнал гейтвея: вердикт (gateway) листом рядом │
   → подписанное обещание (proof.Promise)          ┘
   │
   ▼ в фоне (internal/store/jobs.go)
   звено раз в тик · метка TSA над головой → токен листом в цепь ·
   ключи месяцев (повторить копию кейринга, завести, закрыть, уничтожить по
   заявке) · молчание источников · /metrics по запросу
   │
   ▼
store.Proof → proof.Bundle ─ internal/store/proofs.go
   │  JSON-файл проверяющему
   ▼
esverify ─ cmd/esverify, internal/proof
   офлайн: ключ хранилища, сертификаты TSA (у НУЦ — root_rsa_2020),
   для журналов гейтвея — его ключ (-gateway-key)
```

## Пакеты

| Пакет | Что делает | Главные файлы | Тесты |
|---|---|---|---|
| `internal/evidence` | формат улики: заголовок открыто, тело конвертом; отпечаток `SHA-256("evidencestore/sealed/v1" ‖ байты)` | `record.go`, `seal.go` | золотые байты, обрезки, фазз, стирание |
| `internal/keyring` | ключи: корень → ключ файла → KEK месяца → DEK записи; формат KRNG3 (корень заворачивает только ключ файла); уничтожение поворотом корня; состояния и двухэтапное уничтожение; зеркало корней и корни-сироты | `keyring.go`, `format.go`, `envelope.go`, `lifecycle.go`, `destroy.go`, `rootfile.go` | 27 тестов, 54 мутации |
| `internal/gateway` | проверка бортового журнала Pipelock при приёме: хэш записи (проекции v1–v3), сцепка `prev_hash` по писателям, подписи контрольных точек | `pipelock.go`, `testdata/pipelock-v3.6.0` (настоящий вывод Pipelock) | 8 тестов, 12 мутаций |
| `internal/metrics` | показатели в текстовом формате Prometheus, без зависимостей | `metrics.go` | формат вывода |
| `internal/evlog` | журнал улик: групповой коммит, ответ после fsync, сегменты только дописываются, fail-stop; `Release` (удаление доставленных сегментов) — только для буфера сборщика | `evlog.go` | 13 тестов, 15 мутаций |
| `internal/auditchain` | цепь (ядро): листья, звено с корнем Меркла, голова в двух слотах, подписанное заявление Ed25519 | `carrier.go`, `chain.go`, `merkle.go`, `export.go`, `query.go` | тесты ядра + `TestReadersDoNotTruncate`, `TestMissingLeavesAreLoud`; 4 мутации |
| `internal/tsa` | RFC 3161: запрос, офлайн-проверка CMS до корня, встроенная демо-служба | `tsa.go`, `local.go`, `testdata/` (настоящий токен НУЦ) | 11 тестов (один — живой НУЦ, по переменным окружения), 10 мутаций |
| `internal/proof` | пакет доказательств и его проверка; обещание при приёме; часть пакета для журналов гейтвея | `proof.go`, `promise.go`, `gateway.go` | синтетическая цепь: каждая проверка — свой тест |
| `internal/store` | движок: приём, цепь, метки, ключи, полнота, выдача доказательств, восстановление после падения, копия наружу и восстановление из неё, вердикты гейтвея, показатели | `store.go`, `ingest.go`, `chain.go`, `keys.go`, `jobs.go`, `proofs.go`, `replica.go`, `gateway.go`, `metrics.go` | 23 теста (падение, откат кейринга, стирание, копия, журнал Pipelock, окно отмены по TSA, конфликт номера…) |
| `internal/server` | HTTPS-приём с mTLS и админка через unix-сокет | `server.go` | mTLS, источник из сертификата, админка |
| `internal/collector` | сборщик: файл или файлы по маске → буфер (`evlog`) → пачки; обещания хранилища проверяются закреплённым ключом | `collector.go` | 32 теста: доставка, рестарт без дублей, ротация, переустановка, длинные строки, шарды Pipelock, старт после переустановки, откат буфера, второй сборщик, неверные обещания, часы назад, опасные настройки; 38 мутаций в наборе `edge` |
| `internal/config` | конфигурация JSON и реестр источников | `config.go` | предел пути сокета; остальное — через тесты движка и сервера |
| `internal/pki` | учебный УЦ для стенда | `pki.go` | через тесты сервера |
| `cmd/evidencestore` | сервер и команды оператора | `main.go` | демо |
| `cmd/esverify` | утилита проверяющего | `main.go` | демо |
| `cmd/escollect` | сборщик | `main.go` | демо |
| `internal/ship` | ядро: транспорт копии наружу `Remote` (S3 с SigV4, каталог), без удаления | `remote.go`, `s3_remote.go`, `file_remote.go` | S3 — свои тесты; каталог — через `TestReplicaRestore` |

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
keys.roots_mirror_dir/ вторая копия корней (другой диск или машина): пишется и уничтожается вместе с roots_dir
keys.backup_dir/       копии keyring.dat и sign.key (секреты; не в копию наружу)
replica.url            копия: evidence/…, chain/… кусками по смещению, heads/<n>.json
```

У сборщика (`spool_dir`):

```
spool/seg_*.log          буфер — экземпляр evlog; доставленные сегменты удаляются, граница — spool/floor
state.json               докуда доставлено (acked)
files.json               что известно о файлах: докуда прочитан, первая строка
promises.jsonl           обещания хранилища, сошедшиеся с закреплённым ключом
promises-rejected.jsonl  обещания, которые не сошлись: улика против хранилища
```

Копия `keyring.dat` в резерве безопасна: без корня она бесполезна. Копия, где лежат и `data_dir`, и `roots_dir`, открывает всё, поэтому `config.Validate` запрещает вкладывать один каталог в другой.

## Свойства и кто их стережёт

| Свойство | Где обеспечено | Тест |
|---|---|---|
| «принято» только после fsync | `evlog.commit` | `TestFsyncFailureIsNotAcknowledged` |
| повтор безопасен и получает то же обещание, что приём | `store.Ingest`, `store.checkDuplicate` | `TestDuplicatesAndLastSeq`, `TestResendGetsPromise` |
| другое тело под занятым номером — отказ пачке и событие в цепи, а не «duplicate» | `store.checkDuplicate` (`ErrSeqConflict`, `EventConflict`) | `TestSeqConflict`, `TestIngestOverMTLS` |
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
| сборщик не задваивает строки после падения | `collector` (позиция в буфере) | `TestRestartNoDuplicates`, `TestTornLongLineResumesAtChunk` |
| первый запуск помнит место чтения; без буфера сборщик не гадает | `collector.Bootstrap` (запись «старт»), `collector.load` | `TestBootstrapPositionSurvivesRestart`, `TestLinesWrittenWhileDownAfterFirstStart`, `TestLostSpoolRefusesToGuess`, `TestGlobFirstStartSkipsExisting` |
| буфер: fail-stop, доставленное уходит с диска, номера только растут | `evlog` (экземпляр сборщика), `collector.SendOnce` (`Release`) | `TestFailStop`, `TestReleaseDropsWholeSegments`, `TestSpoolReleasesDelivered`, `TestSpoolSeqMustGrow` |
| ротация не теряет хвост старого файла; потеря — пропуск номера, а не тишина; подменённый на месте файл читается с начала | `collector.ReadOnce` | `TestRotationDrainsOldFile`, `TestLostRotatedTailLeavesGap`, `TestFileReplacedInPlaceIsReadFromStart` |
| длинные строки не застревают в пределе запроса | `collector.SendOnce` (1 МиБ тел на пачку) | `TestBigLinesFitRequestLimit` |
| доставлено — только с обещанием, которое сходится с закреплённым ключом; неверное обещание — улика, записи ждут | `collector.keepPromise` | `TestBadPromiseKeepsRecords`, `TestDeliveryAndPromises`, `TestTornPromiseLine` |
| откат `spool_dir` и второй сборщик с тем же сертификатом останавливают сборщик, а не теряют строки | `collector.Bootstrap` (`ErrStoreAhead`), `collector.send` (`ErrConflict`) | `TestRolledBackSpoolStops`, `TestSecondCollectorWithSameCertificateStops` |
| опасные настройки сборщика — ошибка при загрузке | `collector.Config.validate` | `TestConfigRejectsDangerousValues`, `TestBadServerAddressIsAnError` |
| текущий месяц не закрывается случайно | `store.Deactivate` (`-force`) | `TestKeyringRollbackDetected`, `TestAdminProofAndKeys` |
| копия восстанавливается и сверяется с подписанной головой | `store.RestoreReplica` | `TestReplicaRestore` |
| копия `keyring.dat` в резерв не держит шифрование; ключ без копии не выдаётся | `keyring.persistLocked` (общий замок отпущен, изменения в очереди на `wmu`), `keyring.Seal` | `TestBackupDoesNotBlockSeal`, `TestNewKeyWaitsForBackup` |
| пропавшие листья цепи — громкая ошибка, а не «истёкшие» | `auditchain.ReadLeaves` (`ErrLeavesMissing`) | `TestMissingLeavesAreLoud` |
| квитанция ключа — только по состоянию, дошедшему до резерва; восстановление после сбоя резерва стартует | `store.logKeyLocked` (`KeyInfo.Confirmed`), `keyring.Confirm` | `TestRestoreAfterFailedKeyringBackup`, `TestKeyReceiptWaitsForBackup`, `TestConfirmWaitsForBackup` |
| улики под ключом, которого не знает `keyring.dat`, останавливают старт | `store.checkKeyUse` | `TestWrongKeyringStopsStart` |
| пока есть корни-сироты, уничтожение не окончательно | `keyring.finishLocked`, `keyring.OrphanRoots` | `TestOrphanRootBlocksEffective`, `TestOrphanRootAfterStaleRestore`, `TestOrphanRootsAdmin` |
| потеря каталога корней не уносит ключи, уничтожение затирает обе копии | `keyring.FileRoots` (`Mirror`) | `TestRootsMirror`, `TestFileRootsMirrorFailures` |
| каталоги ключей не вкладываются друг в друга | `config.Validate` | `TestKeyDirsDoNotNest` |
| хранилищу корней (HSM, KMS) уходит только ключ файла, 32 байта | `keyring.persistLocked` (KRNG3) | `TestRootSeesOnlyFileKey`, `TestFileKeyIsFreshPerWrite`, `TestLegacyFormatRefused` |
| окно отмены отмеряется и по метке TSA; без метки уничтожение ждёт | `store.CompleteDue`, `keyring.CompleteDueAt` | `TestDestroyWaitsForTSATime` |
| хэши и подписи Pipelock повторяются байт в байт | `gateway.Entry.ComputeHash`, `gateway.Tracker` | `TestPipelockRecorderVectors`, `TestPipelockTamperedEntry`, `TestDetailBytesAreHashedAsWritten`, `TestTimestampNormalizedLikePipelock` |
| запись журнала гейтвея: вердикт в цепи, после падения досчитывается | `store.recordGateway`, `store.open` (вердикты по телам) | `TestGatewayJournalProof`, `TestGatewayVerdictCatchUp` |
| пакет: тело — та самая запись гейтвея, её накрывает подписанная точка | `proof.verifyGateway` | `TestGatewayJournalProof`, `TestGatewayBodyMustMatchVerdict`, `TestGatewayVerdictOfAnotherRecord`, `TestGatewayTamperedEntry` |
| шарды по маске — по порядку, без повторов; удалённый файл — пропуск номера; шард «из прошлого» по часам читается | `collector.readGlob` (`files.json`) | `TestGlobFollowsPipelockShards`, `TestGlobEqualMTimesUseNaturalOrder`, `TestGlobCurrentFileGoneLeavesGap`, `TestGlobFileFromThePastIsRead`, `TestGlobDeletedCurrentDoesNotRereadOlder` |
| показатели для тревог | `store.Metrics`, `server.MetricsHandler` | `TestMetrics`, `TestMetricsEndpoint` |
| из копии наружу ничего не удаляется | `ship.Remote`: метода удаления нет | — (держит тип) |
| отчёт проверяющего называет верную причину, почему тело закрыто | `proof.Report.Notes` | `TestNotesTellWhyBodyIsClosed` |
| слишком длинный путь сокета админки — ошибка конфига, а не `bind: invalid argument` | `config.Validate` | `TestAdminSocketPathLimit` |

## Как проверить

```
go build ./... && go vet ./... && go test -race ./...     # гейт
python3 scripts/mutate.py keyring|evlog|tsa|store|edge|auditchain|gateway   # мутации: каждая поломка должна уронить тест
PIPELOCK_BIN=$(which pipelock) scripts/demo-pipelock.sh  # демо с настоящим Pipelock
scripts/demo.sh                                           # демо на бинарниках, без интернета
DEMO_TSA=nca scripts/demo.sh                              # то же с настоящей TSA НУЦ РК
DEMO_TSA=digicert scripts/demo.sh                         # то же с публичной TSA DigiCert
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
9. `internal/gateway/pipelock.go`, `internal/store/gateway.go`, `internal/proof/gateway.go`: журнал гейтвея от приёма до пакета.
10. `scripts/demo.sh` и `scripts/demo-pipelock.sh`: всё вместе.
