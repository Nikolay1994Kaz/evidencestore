# Происхождение кода

Ядро скопировано 25.09.2026 из `~/storage_in_memory` (модуль `kvstore`), коммит `bd60927`.

| Пакет | Откуда | Что делает |
|---|---|---|
| `internal/wal` | `kvstore/internal/wal` | WAL с групповым fsync, заголовок формата, LSN (удалён 03.10) |
| `internal/auditchain` | `kvstore/internal/auditchain` | хэш-цепь, Merkle, подписанный экспорт Ed25519 |
| `internal/keyring` | `kvstore/internal/keyring` | KEK/DEK, уничтожение ключа |
| `internal/ship` | `kvstore/internal/ship` | копирование в S3 (SigV4 без aws-sdk) и в файл |
| `internal/monitoring` | новый файл | 3 метрики из исходных 20+ (`WalWriteDuration`, `ShipErrors`, `ShipBytes`), префикс `evidencestore_` (удалён 03.10) |

Изменено при переносе: только пути импорта (`kvstore/kvstore/internal/` → `evidencestore/internal/`) и путь в комментарии fuzz-теста. Логика не менялась. С 17.10 путь модуля — `github.com/Nikolay1994Kaz/evidencestore` (находка P-04), импорты — `github.com/Nikolay1994Kaz/evidencestore/internal/…`.

Версии зависимостей закреплены как в исходнике: `VictoriaMetrics/metrics v1.43.2`, `golang.org/x/sys v0.38.0`.

## Изменено после переноса (03.10.2026)

- `internal/keyring` переписан целиком: формат KRNG2 (файл заперт корнем `RootStore`; с 03.10 — KRNG3, корень заворачивает только ключ файла), уничтожение поворотом корня, состояния ключа и двухэтапное уничтожение с подтверждениями. Причины — разборы 26.09 и 29.09: гонка `Seal`/`Destroy`, тихая потеря ключей при порче файла, воскрешение стёртого скоупа, «нет файла = всё стёрто», ключи в файле открытым текстом.
- `internal/auditchain`:
  - типы событий улик вместо событий памяти агентов;
  - домен подписи `evidencestore/statement/v1`;
  - читатели больше не обрезают файл (читатель во время записи мог отрезать недописанный кадр);
  - пропавшие листья — ошибка `ErrLeavesMissing`, а не «истёкшие по сроку хранения»;
  - добавлены `ScanLeaves`, `ScanVerifiedLeaves`, `SignMessage`, `EncodeHash`;
  - 09.10: защёлка отказа записи, неудачный `Open` не флашит, порча середины файла — отказ вместо среза хвоста, отрезанный хвост откладывается рядом; удалены `InclusionProof`, `BuildProof`, `ForEachLeaf`, `FindLeaf`, `VerifyRange` (в продукте не вызывались, `InclusionProof.Verify` принимал выдуманный лист).
  - 12.10: `TrimToHead` — подъём из копии обрезает цепь по её подписанной голове (Z-07); чтение кадра вынесено в `nextFrame`; `SetSegmentBytes` — порог файлов листьев для тестов.
  - 13.10: `fdatasync` вынесен в `sync_linux.go` / `sync_other.go` (вне Linux — полный `fsync`): пакет нужен и `esverify` на macOS и Windows;
  - 17.10: сообщения об ошибках — на английском (P-03);
  - 25.10: `ReadLinks` — звенья from…to потоком, без всей цепи в памяти (P-06).
- `internal/wal` удалён: журнал улик — новый пакет `internal/evlog`.
- `internal/ship`: оставлен только транспорт `Remote`; `Shipper` (снапшоты, манифесты, удаление старых объектов) удалён вместе с `wal`, из `Remote` убран `Delete`. 25.10 (P-07): `OpenRemoteEnv` — ключи S3 из своих переменных (свидетель голов, `ES_WITNESS_*`); запись в S3 несёт `Content-MD5` (бакеты с Object Lock).
- `internal/monitoring` удалён: все три его метрики относились к `wal` и `Shipper`. С ним из `go.mod` ушла `VictoriaMetrics/metrics`, осталась одна зависимость — `golang.org/x/sys`.
- Новые пакеты: `evidence`, `evlog`, `tsa`, `proof`, `store`, `server`, `collector`, `config`, `pki`, `gateway`, `metrics`, `version` (13.10); команды `evidencestore`, `escollect`, `esverify`. Карта — `docs/ARCHITECTURE.md`, решения — `docs/DECISIONS.md`.

## Что осталось от старого проекта и ещё не вычищено

- `ship`: переменные окружения `KVSTORE_S3_*` и ссылка на `KVSTORE_REQUIREPASS` старого проекта в комментарии `s3_remote.go`.

## Чего нет и надо писать

У журнала Pipelock — подписи отдельных квитанций и файл `chain-link` между сессиями; приём syslog у сборщика, подписанные подтверждения, HSM как `RootStore`.
