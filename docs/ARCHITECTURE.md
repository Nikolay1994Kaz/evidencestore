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
   источник берётся из сертификата, эпоха установки сборщика —
   из заголовка (store.Admit); JSON → store.Ingest
   │
   ▼
store.Ingest ─ internal/store/ingest.go           ┐
   повтор (Source, Seq)? → время приёма            │ синхронно,
     (часы хоста в окне по якорю TSA, монотонно)   │
   → evidence.Record.Seal (keyring: DEK под KEK)   │ до ответа
   → evlog.Append: запись, fsync пачки              │ «принято»
   → лист цепи (из потока журнала, по порядку)     │
   → журнал гейтвея: вердикт (gateway) листом рядом │
   → подписанное обещание (proof.Promise)          ┘
   │
   ▼ в фоне (internal/store/jobs.go)
   звено раз в тик · метка TSA над головой → токен листом в цепь ·
   подписанные головы свидетелю (witness.url: под каждой меткой и текущая) ·
   ключи месяцев (повторить копию кейринга, завести, закрыть, уничтожить по
   заявке) · молчание источников · /metrics по запросу
   │
   ▼
store.Proof → proof.Bundle ─ internal/store/proofs.go
   │  JSON-файл проверяющему
   ▼
esverify ─ cmd/esverify, internal/proof
   офлайн: ключ хранилища, сертификаты TSA (у НУЦ — root_rsa_2020),
   для журналов гейтвея — его ключ (-gateway-key), головы свидетеля,
   взятые проверяющим самим (-heads)
```

## Пакеты

| Пакет | Что делает | Главные файлы | Тесты |
|---|---|---|---|
| `internal/evidence` | формат улики: заголовок открыто, тело конвертом; отпечаток `SHA-256("evidencestore/sealed/v1" ‖ байты)` | `record.go`, `seal.go` | золотые байты, обрезки, фазз, стирание |
| `internal/keyring` | ключи: корень → ключ файла → KEK месяца → DEK записи; формат KRNG3 (корень заворачивает только ключ файла); конверт EV2 (обязательство на DEK); уничтожение поворотом корня; состояния и двухэтапное уничтожение; зеркало корней, починка копий и корни-сироты | `keyring.go`, `format.go`, `envelope.go`, `lifecycle.go`, `destroy.go`, `rootfile.go` | 34 теста, 62 мутации |
| `internal/gateway` | проверка бортового журнала Pipelock при приёме: хэш записи (проекции v1–v3), сцепка `prev_hash` по писателям, подписи контрольных точек | `pipelock.go`, `testdata/pipelock-v3.6.0` (настоящий вывод Pipelock) | 9 тестов, 15 мутаций |
| `internal/metrics` | показатели в текстовом формате Prometheus, без зависимостей | `metrics.go` | формат вывода |
| `internal/version` | версия программы из сведений о сборке: тег (или псевдоверсия) и коммит, которые `go build` кладёт в бинарник сам | `version.go` | формат вывода; `esverify -version` |
| `internal/evlog` | журнал улик: групповой коммит, ответ после fsync, сегменты только дописываются, fail-stop; хвост режется, только если за ним нет целой записи, и откладывается рядом; `Release` и `floor` — только у буфера сборщика (`AllowRelease`) | `evlog.go` | 17 тестов, 20 мутаций |
| `internal/auditchain` | цепь (ядро): листья, звено с корнем Меркла, голова в двух слотах, подписанное заявление Ed25519; защёлка отказа записи; сверка листьев с корнями (`ScanVerifiedLeaves`) | `carrier.go`, `chain.go`, `merkle.go`, `export.go`, `query.go`; `sync_linux.go` / `sync_other.go` — `fdatasync` (вне Linux — полный `fsync`: пакет нужен и `esverify` на любой системе) | тесты ядра + `TestReadersDoNotTruncate`, `TestMissingLeavesAreLoud`, `TestLeafTamperIsSeenOnScan`, `TestCarrier_FailureLatches`, `TestTrimToHead`; 12 мутаций |
| `internal/tsa` | RFC 3161: запрос, офлайн-проверка CMS до корня, встроенная демо-служба | `tsa.go`, `local.go`, `testdata/` (настоящий токен НУЦ) | 13 тестов (один — живой НУЦ, по переменным окружения), 14 мутаций |
| `internal/proof` | пакет доказательств и его проверка; обещание при приёме; часть пакета для журналов гейтвея; сверка с головами свидетеля | `proof.go`, `promise.go`, `gateway.go`, `heads.go` | синтетическая цепь: каждая проверка — свой тест |
| `internal/store` | движок: приём, эпоха установки сборщика, цепь, метки, ключи, полнота, выдача доказательств, восстановление после падения, копия наружу и восстановление из неё, вердикты гейтвея, показатели | `store.go`, `ingest.go`, `epoch.go`, `chain.go`, `keys.go`, `jobs.go`, `proofs.go`, `replica.go`, `witness.go`, `gateway.go`, `metrics.go` | 61 тест (падение, откат кейринга, стирание, копия, журнал Pipelock, окно отмены по TSA, конфликт номера, эпоха сборщика, замок `data_dir`, отказ цепи, часы…; находки 09.10 — `hardening_test.go`); симуляции `TestClockSim` (часы) и `TestStoreCrashSim` (`crashsim_test.go`: падения в каждой точке записи, обрыв записи, `keyring.dat` из резерва и откат, недоступный резерв, чужая установка, ротация сегментов, поворот корня и уничтожение ключей, врущий диск, потеря диска и подъём из копии — и в том числе из копии, чей проход прерван посреди записи, и вместе с падением посреди прохода; параллельная работа (клиенты и фоновые циклы в своих горутинах, одна пачка двумя запросами сразу, чужая установка во время приёма); эталон — каждое обещание выполнено, каждый номер один раз, каждый пропуск в цепи, всё уехавшее полным проходом копии — на месте после подъёма из неё); набор мутаций `store` — 132 (вместе с `proof`, сервером, сборщиком и `esverify`) |
| `internal/server` | HTTPS-приём с mTLS (эпоха сборщика — заголовок `Collector-Epoch`) и админка через unix-сокет | `server.go` | mTLS, источник из сертификата, эпоха, админка |
| `internal/collector` | сборщик: реестр файлов (путь журнала или маска) → буфер (`evlog`) → пачки; обещания хранилища проверяются закреплённым ключом; эпоха установки — с каждым запросом | `collector.go` | 67 тестов: доставка, рестарт без дублей, ротация (дочитывание до тишины), переустановка, длинные строки, шарды Pipelock, старт после переустановки, откат буфера, второй сборщик и копия установки, неверные обещания, часы назад, опасные настройки, смена места после падения, права на файлы и каталог; симуляция `TestCollectorSim` (`sim_test.go`: у сценария свой набор помех — длинные строки, падения до, после и посреди записи, потерянные ответы, права, `dateext`; хранилище поддельное в памяти или настоящее по mTLS — у настоящего каждый номер ещё и проходит `proof.Verify`); 69 мутаций сборщика в наборе `edge` |
| `internal/config` | конфигурация JSON и реестр источников; режим `demo` | `config.go` | предел пути сокета, опасные значения, вложенность каталогов, свидетель не совпадает с копией; 9 мутаций (набор `config`); остальное — через тесты движка и сервера |
| `internal/pki` | учебный УЦ для стенда | `pki.go` | через тесты сервера |
| `cmd/evidencestore` | сервер и команды оператора, `version` | `main.go` | `dev-pki` хранит УЦ; демо |
| `cmd/esverify` | утилита проверяющего: коды выхода 0/1/2, `-allow-no-tsa`, `-version`, `-body` (тело в файл байт в байт — только из пакета, прошедшего проверку); собирается и под macOS и Windows | `main.go` | коды выхода, обещание в вердикте, пакет без TSA, `-version`, `-body` (`TestBodyFlag`: точные байты с управляющими символами, права 0600, чистый JSON, отказы без ключа записи и у непрошедшего пакета); демо |
| `cmd/escollect` | сборщик, `-version` | `main.go` | демо |
| `internal/ship` | ядро: транспорт копии наружу и канала свидетеля `Remote` (S3 с SigV4 и `Content-MD5` для бакетов с Object Lock, каталог), без удаления; у свидетеля свои ключи (`OpenRemoteEnv`) | `remote.go`, `s3_remote.go`, `file_remote.go` | S3 — против поддельного S3 в памяти (прогон на MinIO с Object Lock 25.10 — разовый, DECISIONS п. 25); каталог — через `TestReplicaRestore`; 2 мутации (набор `ship`) |

## Что лежит на диске

```
data_dir/
  LOCK                 замок (flock): один процесс на data_dir — serve, init, restore
  keyring.dat          ключи месяцев, заперты корнем; копия → keys.backup_dir
  evidence/seg_*.log   журнал улик; сегменты только дописываются; floor здесь — порча
  chain/chain.log      звенья (append-only)
  chain/chain.head     голова, два слота с CRC
  chain/leaves_*.log   листья (не удаляются никогда)
  chain/sign.key       ключ подписи хранилища (Ed25519)
  tsa-local/           демо-TSA, если tsa.url = "local"
  admin.sock           админка, права 0600 (или admin_socket)
  replica-generation   поколение копии, в которое пишет хранилище, поднятое из копии (кладёт restore)
  *.torn-<смещение>    рядом с сегментом или файлом цепи: отрезанный оборванный хвост (не удаляется)
roots_dir/             корни кейринга (FileRoots), отдельно от data_dir
keys.roots_mirror_dir/ вторая копия корней (другой диск или машина): пишется и уничтожается вместе с roots_dir
keys.backup_dir/       копии keyring.dat (+ keyring.dat.gen — поколение) и sign.key (секреты; не в копию наружу)
replica.url            копия: evidence/…, chain/… кусками по смещению, heads/<n>.json; докуда доехала — по листингу;
                       поднятое из копии хранилище пишет новое поколение gen/<n>/ (номер — в data_dir/replica-generation)
witness.url            свидетель: только heads/<n>.json — голова под каждой меткой TSA и текущая раз в witness.every
```

У сборщика (`spool_dir`):

```
spool/seg_*.log          буфер — экземпляр evlog: записи L (строка), S («старт»), P (файл в реестре с этого
                         места: новый или после пропуска), D (файл ушёл из реестра: дочитан или пропал);
                         доставленные сегменты удаляются, граница — spool/floor
state.json               докуда доставлено (acked)
files.json               снимок реестра файлов (перед освобождением буфера): inode, рождение, путь,
                         докуда прочитан, первая строка
start-files.json         реестр файлов на момент первого запуска (пишется раньше записи «старт»)
epoch.json               эпоха этой установки сборщика: с каждым запросом; потерян — новая установка
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
| время приёма не идёт назад и держится в окне по якорю TSA [hi − 55 с, lo]: не позже T2 + 1 с и не раньше T1 − 1 мин при любых часах хоста; часы хоста за окном — тревога | `store.clockLocked`, `store.anchorWindowLocked`, `store.anchorClock` | `TestReceivedAtIsMonotonic`, `TestReceiveTimeHeldByTSAAnchor`, `TestReceiveTimeNeverPassesNextStamp`, `TestSlowTSAAnswerIsNotClockAlarm`, `TestRecordAcceptedWhileAnchorMoves`, `TestClockSim` (симуляция) |
| с TSA приём открыт, только пока окно по якорю не шире 55 с: до первой метки процесса и при несвежем якоре — `503`; якорь освежается раз в час и в простой, несвежий — повтор метки каждые 10 с | `store.anchored`, `store.anchorStale`, `store.keepAnchor`, `store.Ingest` | `TestIntakeWaitsForFirstStamp`, `TestServeOpensIntakeAfterFirstStamp`, `TestFirstStampRetriedUntilAnchored`, `TestAnchorRefreshedWhenIdle`, `TestClockSim` |
| после падения цепь досчитывается | `store.open` (хвост журнала → листья) | `TestCrashCatchUp` |
| потеря подтверждённой улики не скрывается | `store.open` (`ErrEvidenceLost`) | `TestLostEvidenceStopsStart` |
| один бит порчи не стирает подтверждённое: порча середины — отказ, оборванный хвост откладывается рядом | `evlog.scanSegment` (`findFrame`), `auditchain.scanFrames` (`frameAfter`) | `TestCorruptionInLastSegmentIsNotCut`, `TestTornTailIsCut`, `TestCarrier_TornTailIsNotTamper`, `TestChainCorruptionIsLoud`, `TestBitRotInEvidenceLogRefused` |
| `floor` — только у буфера сборщика, и граница — начало сегмента; сбой посреди создания сегмента не валит запуск | `evlog.readFloor`, `evlog.newSegment` | `TestFloorRefusedWithoutAllowRelease`, `TestFloorMustStartASegment`, `TestFloorInEvidenceLogRefused`, `TestHeaderlessLastSegmentRecovered` |
| отказ записи цепи защёлкивается, и приём стоит; неудачный `Open` цепи ничего не пишет | `auditchain.Carrier.flushLocked`, `auditchain.Open`, `store.Healthy` | `TestCarrier_FailureLatches`, `TestCarrier_FailedOpenWritesNothing`, `TestChainFailureStopsIntake` |
| подменённый лист цепи не проходит запуск; испорченный слот головы виден | `auditchain.ScanVerifiedLeaves`, `store.scanChain`, `auditchain.readHead` | `TestLeafTamperIsSeenOnScan`, `TestTamperedLeafStopsStart`, `TestCarrier_DamagedHeadSlotIsReported` |
| второй процесс над `data_dir` не стартует | `store.lockDataDir` | `TestDataDirLocked` |
| подделка в пакете ловится | `proof.Verify` | `TestTamperingIsDetected`, тесты `internal/proof` |
| пакет — от головы под T1 до головы под T2 (у журнала гейтвея — до звена контрольной точки, если оно позже) и не растёт со звеньями после неё; звенья читаются потоком, в памяти — только звенья пакета | `store.Proof`, `auditchain.ReadLinks` | `TestProofEndsAtUpperStamp`, `TestGatewayProofReachesLateCheckpoint`, `TestReadLinks` |
| пакет без T2 не проходит, пока не сказано `-allow-no-tsa`; улика гейтвея без части `gateway` не проходит; непроверенная подпись точки запись не накрывает | `proof.Verify`, `proof.verifyGateway` | `TestBundleWithoutUpperFailsByDefault`, `TestBundleWithoutTSAIsRefused`, `TestGatewayPartCannotBeStripped`, `TestNoKeyCheckpointDoesNotCover` |
| отчёт: вердикт первой и последней строкой, управляющие символы экранированы, обещание — часть вердикта; код выхода 0/1/2 | `proof.Report.Text`, `cmd/esverify` | `TestReportTextEscapesControls`, `TestExitCodesAndPromiseVerdict` |
| ключ записи из пакета связан с отпечатком улики (EV2); конверт EV1 без обязательства не распознаётся и не вскрывается | `keyring.OpenWithDEK`, `keyring.KEKIDOf` | `TestDEKCommitment`, `TestLegacyEnvelopeRejected` |
| токен TSA проверяется до цепи | `store.Stamp` | `TestStampRejectsUntrustedToken` |
| правка любого подписанного байта токена ловится; атрибут сертификата подписанта (v1 или v2) обязателен; точность метки не хуже минуты | `tsa.Verify` | `TestEveryByteOfTokenMatters` (и токен НУЦ), `TestSigningCertificateV1AndRequired`, `TestAccuracyBound` |
| метка TSA — только когда после прошлой в цепь легло новое | `store.stamp` | `TestStampOnlyAfterNewLeaves` |
| уничтоженный ключ не открывается ни в одной копии | `keyring` (поворот корня) | `TestDestroy`, `TestDestroyWaitsForBackup` |
| уничтожение — только двое и не раньше срока; срок от времени TSA при заявке, не длиннее 10 лет | `keyring.ScheduleDestroyFrom`, `store.ScheduleDestroy` | `TestLifecycle`, `TestRetentionErasure`, `TestDestroyWindowFromTSATime`, `TestWaitLimitAndTimeRange` |
| откат `keyring.dat` виден и не затирает свежий резерв; `init` не затирает резерв; цепь без `sign.key` не стартует | `store.reconcileKeys` (копия после сверки), `store.backupFile` (`.gen`), `store.Init`, `store.open` | `TestKeyringRollbackDetected`, `TestOldKeyringDoesNotOverwriteBackup`, `TestInitRefusesWithKeysInBackup`, `TestSigningKeyGuarded` |
| пропуски и молчание — в цепи; пропуск, найденный перед падением, объявляется после; молчание — одно событие на эпизод и через рестарт; индекс номеров вразброс не раздувается | `store.indexLocked`, `store.announceTailGaps`, `store.CheckSilence`, `store.seqIndex` | `TestGapsAndSilence`, `TestGapSurvivesCrash`, `TestSilenceSurvivesRestart`, `TestSeqIndexSparse` |
| сборщик не задваивает строки после падения | `collector` (позиция в буфере) | `TestRestartNoDuplicates`, `TestTornLongLineResumesAtChunk` |
| первый запуск помнит место чтения и встаёт на конец целой строки; без буфера сборщик не гадает | `collector.Bootstrap` (запись «старт», `start-files.json`), `collector.load` | `TestBootstrapPositionSurvivesRestart`, `TestLinesWrittenWhileDownAfterFirstStart`, `TestLostSpoolRefusesToGuess`, `TestGlobFirstStartSkipsExisting`, `TestStartRecordCarriesNoRegistry`, `TestFirstStartMidLineTakesWholeLine`, `TestFirstStartRemembersHead` |
| буфер: fail-stop, доставленное уходит с диска, номера только растут | `evlog` (экземпляр сборщика), `collector.SendOnce` (`Release`) | `TestFailStop`, `TestReleaseDropsWholeSegments`, `TestSpoolReleasesDelivered`, `TestSpoolSeqMustGrow` |
| реестр файлов: каждый файл по inode со своим местом, первой строкой, рождением и тишиной; новый — в буфер записью `P` до первой строки, дочитанный — `D`; ушедший с пути дочитывается через дескриптор до тишины после ухода; файлы читаются независимо (вторая ротация, два писателя — без потерь); после рестарта ушедший находится по inode и рождению; потеря — пропуск номера, а не тишина; подменённый на месте файл читается с начала; нечитаемая первая строка — не подмена; файл, который не открыть (права), — в реестре и читается, когда откроется (Z-01, Z-02, Z-04); нечитаемый каталог — не «файлов нет» (Z-03); чтение не ждёт паузы отправки; нет файла — предупреждение | `collector.ReadOnce`, `collector.reconcile`, `collector.adopt`, `collector.readFile`, `collector.retire`, `collector.forget`, `collector.sameFile`, `collector.Run`, `collector.warnMissing` | `TestRotationDrainsOldFile`, `TestRotationWaitsForQuietOldFile`, `TestSecondRotationWhileDrainingKeepsMiddleFile`, `TestUnopenableNewFileDoesNotBlockDrain`, `TestReadingGoesOnWhileStoreIsDown`, `TestRotatedFileFoundByInodeAfterRestart`, `TestLostRotatedTailLeavesGap`, `TestFileReplacedInPlaceIsReadFromStart`, `TestUnreadableHeadIsNotReplacement`, `TestPositionSwitchSurvivesCrash`, `TestMissingSourceIsReported`, `TestRegistryKnowsFileByBirth`, `TestUnreadableRotatedFileDoesNotBlockReading`, `TestUnreadableNewFileIsFollowed`, `TestUnreadableNewFileGoneIsGap`, `TestUnreadableLogDirIsNotEmpty`, `TestUnreadableDirKeepsRotatedFile`, `TestRegistryKnowsUnreadableFileByBirth`, `TestCollectorSim` (симуляция: 4 мира — file и glob, без разрушений и с ними; с поддельным и с настоящим хранилищем) |
| длинные строки не застревают в пределе запроса | `collector.SendOnce` (1 МиБ тел на пачку) | `TestBigLinesFitRequestLimit` |
| доставлено — только с обещанием, которое сходится с закреплённым ключом; неверное обещание — улика, записи ждут | `collector.keepPromise` | `TestBadPromiseKeepsRecords`, `TestDeliveryAndPromises`, `TestTornPromiseLine`, `TestTornPromiseWriteIsCut` |
| второй сборщик с тем же сертификатом (другая установка) получает отказ уже при запуске; законную переустановку принимает оператор, и тогда отказ — прежней установке; закрепление переживает падение; одновременный первый контакт закрепляет ровно одну; выдуманные эпохи не раздувают цепь; отказ не называет закреплённую эпоху | `store.Admit`, `store.BindEpoch`, `server.handleState`, `server.handleIngest`, `collector.loadEpoch` | `TestEpochBindsSource`, `TestEpochBindingSurvivesCrash`, `TestEpochFirstContactRace`, `TestEpochRefusalsBounded`, `TestEpochOverMTLS`, `TestSecondCollectorWithSameCertificateStops`, `TestRunStopsWhenRebound`, `TestLostEpochFileIsNewInstallation` |
| откат `spool_dir` и копия одной установки останавливают сборщик, а не теряют строки | `collector.Bootstrap` (`ErrStoreAhead`), `collector.send` (`ErrConflict`) | `TestRolledBackSpoolStops`, `TestInstallationCloneStopsOnConflict` |
| опасные настройки сборщика и хранилища — ошибка при загрузке | `collector.Config.validate`, `config.Validate` | `TestConfigRejectsDangerousValues`, `TestBadServerAddressIsAnError`, `TestValidateRejectsDangerousValues` |
| текущий месяц не закрывается случайно | `store.Deactivate` (`-force`) | `TestKeyringRollbackDetected`, `TestAdminProofAndKeys` |
| копия восстанавливается и сверяется с подписанной головой; прерванный проход не ломает восстановление (цепь обрезается по голове); голова копии не новее её звеньев; куски внахлёст сверяются; поднятое хранилище пишет копию новым поколением, и следующий подъём из неё проходит; копию, которую `data_dir` не продолжает, хранилище не дописывает | `store.ShipOnce` (журнал раньше цепи, голова под замком цепи, сверка хвоста копии), `store.RestoreReplica` (поколения, `auditchain.TrimToHead`) | `TestReplicaRestore`, `TestReplicaInterruptedPassRestores`, `TestReplicaInterruptedBetweenLinksAndLeaves`, `TestRestoredStoreContinuesCopy`, `TestShipRefusesDataDirBehindCopy`, `TestRestoreSkipsGenerationWithoutHead`, `TestRestoreFromChunkCutMidRecord`, `TestReplicaHeadNotAheadOfShippedChain`, `TestRestoreSkipsHeadAheadOfLinks`, `TestReplicaRestoreToleratesOverlap`, `TestTrimToHead`; `TestStoreCrashSim` |
| пакет сверяется с головами свидетеля: голова свидетеля с номером звена из пакета обязана с ним совпасть; две разные головы с одним номером — развилка; первая голова свидетеля не раньше звена улики закрепляет её, и пакет до неё доходит (иначе отчёт говорит, какой пакет просить); головы под чужим ключом и посторонние файлы не в счёт | `proof.checkWitness`, `esverify -heads` | `TestWitnessHeadFixesRecord`, `TestWitnessHeadOfAnotherChain`, `TestWitnessSeesFork`, `TestWitnessHeadBeyondBundle`, `TestWitnessHasNothingYet`, `TestHeadsFlag` |
| свидетель получает голову под каждой меткой TSA и текущую; пока он недоступен, в очереди — головы под метками и одна текущая; пакет выдаётся до головы свидетеля (`proof -to-head`) | `store.queueWitnessLocked`, `store.WitnessOnce`, `store.ProofTo`, `server` (`to_head`) | `TestWitnessGetsStampedHeads`, `TestWitnessQueueWhileUnreachable`, `TestProofToWitnessHead`, `TestAdminProofAndKeys` |
| у свидетеля свои ключи S3, ключи копии ему не подставляются; запись в S3 несёт `Content-MD5`; свидетель не может совпадать с копией | `ship.OpenRemoteEnv`, `s3Remote.do`, `config.Validate` | `TestOpenRemoteEnv_OwnCredentials`, `TestS3Remote_RoundTrip`, `TestValidateRejectsDangerousValues` |
| копия `keyring.dat` в резерв не держит шифрование; ключ без копии не выдаётся | `keyring.persistLocked` (общий замок отпущен, изменения в очереди на `wmu`), `keyring.Seal` | `TestBackupDoesNotBlockSeal`, `TestNewKeyWaitsForBackup` |
| пропавшие листья цепи — громкая ошибка, а не «истёкшие» | `auditchain.ReadLeaves`, `ScanLeaves`, `ScanVerifiedLeaves`, `Open` (`ErrLeavesMissing`) | `TestMissingLeavesAreLoud` |
| квитанция ключа — только по состоянию, дошедшему до резерва; восстановление после сбоя резерва стартует | `store.logKeyLocked` (`KeyInfo.Confirmed`), `keyring.Confirm` | `TestRestoreAfterFailedKeyringBackup`, `TestKeyReceiptWaitsForBackup`, `TestConfirmWaitsForBackup` |
| улики под ключом, которого не знает `keyring.dat`, останавливают старт | `store.checkKeyUse` | `TestWrongKeyringStopsStart` |
| пока есть корни-сироты, уничтожение не окончательно | `keyring.finishLocked`, `keyring.OrphanRoots` | `TestOrphanRootBlocksEffective`, `TestOrphanRootAfterStaleRestore`, `TestOrphanRootsAdmin` |
| потеря каталога корней не уносит ключи, уничтожение затирает обе копии; недостающая копия докладывается (пропавший каталог не создаётся; доклад и поворот корня не перемежаются), испорченная обходится, расходящимися не заворачивают; недоступное зеркало не мешает старту; медленные корни не держат приём | `keyring.FileRoots` (`Mirror`, `RepairRoots`, `Wrap`, `Unwrap`), `store.open` | `TestRootsMirror`, `TestFileRootsMirrorFailures`, `TestRootCopiesRepairedAndChecked`, `TestRepairDoesNotCreateMissingDir`, `TestRepairRootsExcludesKeyringChanges`, `TestMirrorDownDoesNotStopStart`, `TestSlowRootsDoNotBlockSeal` |
| каталоги ключей не вкладываются друг в друга | `config.Validate` | `TestKeyDirsDoNotNest` |
| хранилищу корней (HSM, KMS) уходит только ключ файла, 32 байта | `keyring.persistLocked` (KRNG3) | `TestRootSeesOnlyFileKey`, `TestFileKeyIsFreshPerWrite`, `TestLegacyFormatRefused` |
| окно отмены отмеряется и по метке TSA; без метки уничтожение ждёт | `store.CompleteDue`, `keyring.CompleteDueAt` | `TestDestroyWaitsForTSATime` |
| хэши и подписи Pipelock повторяются байт в байт; ключ, повторённый со свёрткой регистра, и невалидный UTF-8 — ошибка | `gateway.Entry.ComputeHash`, `gateway.Tracker`, `gateway.ParseEntry` | `TestPipelockRecorderVectors`, `TestPipelockTamperedEntry`, `TestDetailBytesAreHashedAsWritten`, `TestTimestampNormalizedLikePipelock`, `TestCaseFoldedDuplicateKeyAndBadUTF8` |
| запись журнала гейтвея: вердикт в цепи, после падения досчитывается | `store.recordGateway`, `store.open` (вердикты по телам) | `TestGatewayJournalProof`, `TestGatewayVerdictCatchUp` |
| пакет: тело — та самая запись гейтвея, её накрывает подписанная точка | `proof.verifyGateway` | `TestGatewayJournalProof`, `TestGatewayBodyMustMatchVerdict`, `TestGatewayVerdictOfAnotherRecord`, `TestGatewayTamperedEntry` |
| шарды по маске — по порядку, без повторов; удалённый или ушедший из-под маски файл дочитывается через дескриптор, пока не замолчит, а остальные файлы под маской тем временем читаются независимо (реестр); пропуск — только после перезапуска; подменённый на месте — пропуск и чтение с начала, без дубля; файл с чужим inode забывается; устаревший листинг (файл переименован под маской) — перечитать каталог, а не пропуск; шард «из прошлого» по часам читается | `collector.globFiles`, `collector.reconcile` (`files.json`), `collector.retire` | `TestGlobFollowsPipelockShards`, `TestGlobEqualMTimesUseNaturalOrder`, `TestGlobCurrentFileGoneLeavesGap`, `TestGlobFileFromThePastIsRead`, `TestGlobDeletedCurrentDoesNotRereadOlder`, `TestGlobRotatedOutOfMaskWaitsForQuiet`, `TestGlobSecondRotationWhileDrainingKeepsMiddleFile`, `TestGlobQueuedFileKeepsItsOffset`, `TestGlobRenameBetweenListingAndOpen`, `TestGlobReplacedInPlaceIsGapNotDuplicate`, `TestGlobForgetsFileWithReusedInode` |
| показатели для тревог | `store.Metrics`, `server.MetricsHandler` | `TestMetrics`, `TestMetricsEndpoint` |
| из копии наружу ничего не удаляется | `ship.Remote`: метода удаления нет | — (держит тип) |
| отчёт проверяющего называет верную причину, почему тело закрыто | `proof.Report.Notes` | `TestNotesTellWhyBodyIsClosed` |
| слишком длинный путь сокета админки — ошибка конфига, а не `bind: invalid argument` | `config.Validate` | `TestAdminSocketPathLimit` |
| `dev-pki` повторно не ломает выданные сертификаты: ключ УЦ хранится | `cmd/evidencestore` (`pki.LoadCA`) | `TestDevPKIKeepsCA` |

## Как проверить

```
go build ./... && go vet ./... && go test -race ./...     # гейт (его же гоняет GitHub Actions на каждый пуш)
scripts/release.sh dist                                   # бинарники релиза и SHA256SUMS (на тег v* — в Actions)
python3 scripts/mutate.py keyring|evlog|tsa|store|edge|auditchain|gateway|config|ship   # мутации: каждая поломка должна уронить тест
PIPELOCK_BIN=$(which pipelock) scripts/demo-pipelock.sh  # демо с настоящим Pipelock
scripts/demo.sh                                           # демо на бинарниках, без интернета
scripts/demo-intruder.sh                                  # взломщик почистил auth.log: удалённые строки — из хранилища
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
10. `scripts/demo.sh`, `scripts/demo-intruder.sh` и `scripts/demo-pipelock.sh`: всё вместе.
