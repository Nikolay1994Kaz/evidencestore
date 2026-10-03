# Происхождение кода

Ядро скопировано 25.09.2026 из `~/storage_in_memory` (модуль `kvstore`), коммит `bd60927`.

| Пакет | Откуда | Что делает |
|---|---|---|
| `internal/wal` | `kvstore/internal/wal` | WAL с групповым fsync, заголовок формата, LSN |
| `internal/auditchain` | `kvstore/internal/auditchain` | хэш-цепь, Merkle, подписанный экспорт Ed25519 |
| `internal/keyring` | `kvstore/internal/keyring` | KEK/DEK, уничтожение ключа |
| `internal/ship` | `kvstore/internal/ship` | копирование в S3 (SigV4 без aws-sdk) и в файл |
| `internal/monitoring` | новый файл | 3 метрики из исходных 20+ (`WalWriteDuration`, `ShipErrors`, `ShipBytes`), префикс `evidencestore_` |

Изменено при переносе: только пути импорта (`kvstore/kvstore/internal/` → `evidencestore/internal/`) и путь в комментарии fuzz-теста. Логика не менялась.

Версии зависимостей закреплены как в исходнике: `VictoriaMetrics/metrics v1.43.2`, `golang.org/x/sys v0.38.0`.

## Изменено после переноса (03.10.2026)

- `internal/keyring` переписан целиком: формат KRNG2 (файл заперт корнем `RootStore`), уничтожение поворотом корня, состояния ключа и двухэтапное уничтожение с подтверждениями. Причины — разборы 26.09 и 29.09: гонка `Seal`/`Destroy`, тихая потеря ключей при порче файла, воскрешение стёртого скоупа, «нет файла = всё стёрто», ключи в файле открытым текстом.
- `internal/auditchain`:
  - типы событий улик вместо событий памяти агентов;
  - домен подписи `evidencestore/statement/v1`;
  - читатели больше не обрезают файл (читатель во время записи мог отрезать недописанный кадр);
  - добавлены `ScanLeaves`, `SignMessage`, `EncodeHash`.
- `internal/wal` не используется: журнал улик — новый пакет `internal/evlog`.
- `internal/ship`: используется только транспорт `Remote`.
- Новые пакеты: `evlog`, `tsa`, `proof`, `store`, `server`, `collector`, `config`, `pki`; команды `evidencestore`, `escollect`, `esverify`. Карта — `docs/ARCHITECTURE.md`, решения — `docs/DECISIONS.md`.

## Что осталось от старого проекта и ещё не вычищено

- `auditchain/query.go`: `ForEachLeaf` считает пропавшие файлы листьев «сроком хранения», а не порчей. Движок его не использует (у него свой `ScanLeaves`, где дыра — ошибка).
- `ship`: переменные окружения `KVSTORE_S3_*`; `Shipper` со снапшотами и удалением старых объектов.
- `internal/wal` целиком (kv-формат `Op`/`Key`/`Value`, «сборка kvstore» в ошибках) — не используется.
- Удаление листьев по сроку, о котором говорилось 25.09, в перенесённом коде не нашлось: устаревшим был только комментарий в `carrier.go`, он исправлен.

## Чего нет и надо писать

Проверка подписей квитанций Pipelock при приёме, приём syslog у сборщика, `Policy` с проверкой подписей подтверждающих, HSM как `RootStore`, метрики.
