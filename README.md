# git-remote-spiridus

Клиент Git для чтения проектов [Spiridus](https://spiridus.ru/): clone/fetch через
HTTPS и материализация ресурсов без git-lfs. Нужен установленный Git; push пока
не поддерживается. Доступ к проекту требует отдельного ключа Spiridus и включения
Git-доступа на сервере. Инструкция установки и проверки подписи выпуска —
[справка](https://doc.spiridus.ru/), раздел «Git-доступ к проекту».

Исходники клиента — Apache-2.0, см. LICENSE и NOTICE. Стандартная библиотека Go —
BSD-3-Clause, текст сохранён в THIRD_PARTY_NOTICES.txt. Сторонних модулей нет.

## Сборка

Закреплён Go 1.25.3. Для бинарника с параметрами подписанного выпуска:

```sh
GOTOOLCHAIN=local CGO_ENABLED=0 go build -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w' -o git-remote-spiridus .
GOTOOLCHAIN=local go test ./...
GOTOOLCHAIN=local go vet ./...
```

`build.sh` собирает шесть целей при заданных `TMPDIR` и `SPIRIDUS_GO_BIN` (путь к Go
1.25.3). Подписанный выпуск содержит Linux amd64 и Windows amd64; кросс-сборка
остальных целей не означает прохождения нативной приёмки.

После публикации тега и страницы обнаружения Go можно установить исходники:

```sh
GOPROXY=direct go install spiridus.ru/git-remote-spiridus@<tag>
```

Эта команда сама по себе не проверяет подпись бинарного выпуска.
`snapshot-manifest.json` закрепляет исходный коммит и SHA-256 файлов снимка.
Сопоставьте `sourceCommit` с `commit` из подписанного `RELEASE.json`, версию Go
с полем `go`, ОС/архитектуру с `platforms`. Соберите с приведёнными параметрами
и сравните SHA-256 с проверенным `SHA256SUMS`. Расхождение требует выяснения
причины до использования. История разработки основного проекта сюда не переносится.
