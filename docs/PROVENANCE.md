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

## Что осталось от старого проекта и ещё не вычищено

- `auditchain/export.go`: домен подписи `vmem-audit-statement-v1`.
- `auditchain/carrier.go`: файлы листьев (`leaves_*.log`) ротируются, сжимаются и удаляются по retention. Это противоречит правилу «файлы с уликами никогда не переписываются»; неизменны только `chain.log` и `chain.head`.
- `wal.Entry` — запись kv-стора (`Op`, `Key`, `Value`): формат не рассчитан на улики.
- Сообщения об ошибках в `wal/header.go` упоминают «сборку kvstore».

## Чего нет и надо писать

Сборщик, приём по mTLS с проверкой подписей, формат сегментов улик, заверение у внешних свидетелей, отчёт для проверяющего.
