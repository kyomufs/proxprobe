# proxprobe — дизайн

Лёгкая Go-утилита: собирает серверы из разнородных подписок в один список,
проверяет их живость через ядро mihomo и умеет выгружать результат обратно
в форматы подписок.

## 1. Задача и критерий успеха

На входе — набор ссылок-подписок четырёх несовместимых форматов. На выходе —
один файл со всеми уникальными серверами, отсортированными по результату
реальной проверки через туннель.

Успех = одной командой получить `out/best.yaml`, где каждый узел реально
ответил на HTTP-запрос через себя, и рядом — замер задержки.

Границы первой версии:

- ядро одно — **mihomo** (бинарник из `$PATH`, не библиотека);
- проверка — TCP-connect и HTTP-запрос через локальный socks-инбаунд mihomo;
- **выгрузка только в форматы mihomo** (Clash YAML). Форматы xray и sing-box
  читаются на входе — иначе теряются источники pro1link-xray (440 узлов) и
  proxypool-singbox (59 узлов) — но обратно не генерируются;
- демона нет: утилита запускается руками, портов не держит.

## 2. Входные форматы

Проверено на живых источниках 2026-10-25.

| Формат | Источник-эталон | Что внутри | Узлов |
|---|---|---|---|
| `links` | `gitlab.com/avencores/goida-vpn-configs/raw/main/githubmirror/1.txt` | построчный текст: `vless://`, `vmess://`, `trojan://`, `ss://`, `socks5://`, `hysteria2://`, `tuic://` | 11182 |
| `links-b64` | `pro1link.ru/<id>/` с UA `v2rayN` | то же, но тело — base64 | 182 КБ |
| `clash` | `sunmiao4458.github.io/free-proxy-airport/clash.yaml` | YAML с `proxies: [{name,type,server,port,...}]` | 44 |
| `clash` | `pro1link.ru/<id>/` с UA `clash-verge/2.0` | то же, 413 узлов, все `vless` + `reality-opts` | 413 |
| `xray-bundles` | `pro1link.ru/<id>/` с UA `v2rayNG` + `Accept: application/json` | JSON-**массив** бандлов, каждый `{dns,routing,inbounds,outbounds,remarks}` | 428 бандлов |
| `singbox` | `snakem982/proxypool/main/source/sing-box-2.json` | объект с `outbounds[]`, узлы + служебные `selector/urltest/direct/block/dns` | 59 узлов из 83 |

### Отличия, которые ломают наивный парсер

- **`xray-bundles` — не конфиг, а массив конфигов.** Каждый бандл несёт свой
  `routing` и `inbounds` (`socks:10808`, `http`); из бандла берутся только
  `outbounds` с реальным протоколом, служебные `freedom`/`blackhole`/`dns`/
  `loopback` отбрасываются. `remarks` — имя узла.
- **Формат зависит от User-Agent.** Один и тот же URL отдаёт список ссылок,
  Clash YAML или Xray JSON. UA — часть описания источника, а не деталь
  транспорта.
- **Тело может быть base64-обёрткой.** Эвристика (подтверждена в
  `sunmiao4458/generator.py`): декодировать, если строка целиком из
  `[A-Za-z0-9+/=]`, длина кратна 4, и результат содержит `proxies:` или `://`.
- **Clash YAML бывает битым.** Тот же автор выгрызает секцию `proxies:`
  построчно, если `yaml.safe_load` падает. Повторяем этот приём.
- **`socks5://` в Clash и в sing-box описывается по-разному.** В Clash —
  `type: socks5`; в sing-box — `type: socks5` с `version: "5"`.

## 3. Каноническая модель

Единственный источник правды внутри утилиты. Всё входит в неё и всё выходит
из неё; форматы конвертируются только через неё.

```go
type Node struct {
    ID       string // "vless|host|443|<cred>|reality" — ключ дедупа
    Proto    string // vless|vmess|trojan|ss|socks5|hysteria2|tuic|anytls
    Name     string // человекочитаемое имя из источника
    Server   string // домен или IP
    Port     int

    // Учётные данные: заполняется то, что есть у протокола.
    UUID     string
    Password string
    Method   string // для ss: шифр
    Flow     string // vless: xtls-rprx-vision

    // Транспорт.
    Network  string // tcp|ws|grpc|h2|httpupgrade|xhttp
    Path     string
    Host     string
    ServiceName string // grpc
    Security string // none|tls|reality

    // TLS.
    SNI      string
    ALPN     []string
    Insecure bool
    Fingerprint string // fp
    PublicKey   string // pbk, reality
    ShortID     string // sid, reality
    SpiderX     string // spx, reality

    // Служебное.
    Source   []string       // из каких подписок пришёл
    Raw      map[string]any // исходное представление по формату
}
```

**Правило потери данных:** парсер обязан сохранить всё, что понял, в
`Raw[<формат>]`, и сохранить исходную share-ссылку в `Raw["link"]`, если она
была. Обратный экспорт предпочитает `Raw`, а общие поля — как fallback. Так
round-trip не теряет поля, которых нет в канонической модели.

**Неизвестный протокол** не выбрасывается молча: строка уходит в
`skip.log` с причиной.

## 4. Пайплайн

```
sources.yaml
   │
   ├─ fetch     → raw/<id>.<ext>          сырьё как пришло, + sha256
   ├─ detect    → формат на источник      по содержимому, не по расширению
   ├─ parse     → nodes/<id>.jsonl        []Node, по строке на узел
   ├─ merge     → merged/nodes.jsonl      дедуп по ID
   │
   ├─ ping      → probes/tcp.jsonl        TCP-connect, 200 горутин
   ├─ probe     → probes/http.jsonl       HTTP через socks-inbound mihomo
   │
   └─ export    → out/clash.yaml
                  out/xray.json
                  out/singbox.json
                  out/best.yaml          топ по задержке
                  out/report.md          сводка по источникам
```

Каждая фаза — отдельная подкоманда и отдельный файл-артефакт. Пайплайн
возобновляем: `probe` не перезапускает `fetch`, если сырьё на месте и
`--refresh` не задан.

### Дедуп

Ключ `ID` = `proto|server|port|credential|sniffing-hint`, где
`credential` — UUID/пароль/метод в зависимости от протокола, а
`sniffing-hint` — `sni` + тип security (у reality-узлов с одинаковым
адресом и разным `pbk` это разные серверы).

При конфликте выигрывает запись с большим числом заполненных полей; при
равенстве — та, чей источник раньше в `sources.yaml`. `Source`
объединяется списком.

### Проверка

Два уровня, оба дают число в отчёт:

1. **`ping`** — `net.DialTimeout("tcp", host:port, 2s)`, 200 горутин, отдельно
   фиксируется ошибка резолва. Дёшево, отсеивает мёртвое до запуска ядра.
2. **`probe`** — mihomo поднимается один раз на батч в режиме `global`,
   затем каждый узел проверяется HTTP-запросом через `mixed-port`:

   ```
   GET <TEST_URL> через socks5h://127.0.0.1:<mixed-port>
   → 204 за 113 мс   узел жив
   → timeout         мёртв или медленный
   ```

   **Встроенный `/proxies/{n}/delay` НЕ используется.** Проверено на живой
   машине с поднятым flclash: системный резолвер отдаёт fake-IP из
   `198.18.0.0/16`, mihomo резолвит имя узла в этот же адрес и получает
   ошибку — `{"message":"An error occurred in the delay test"}` при том, что
   `curl -x socks5h://` к тому же узлу отдаёт 204 за 0.12 с. Socks-путь этой
   проблемы лишён: имя узла уходит в ядро внутри SOCKS-запроса.
   Отключение DNS и переход на `redir-host` с явными nameserver не помогают —
   системный резолвер всё равно перехвачен.

   Режим `global` обязателен: при `rule` с `MATCH,DIRECT` ядро писало
   `[TCP] … match Match using DIRECT`, то есть проба мерила бы канал самого
   хоста, а не узел.

### Тестовый конфиг mihomo

Генерируется минимальный, без правил и DNS:

```yaml
mixed-port: 17890
allow-lan: false
mode: rule
log-level: warning
external-controller: 127.0.0.1:19090
unified-delay: true
tcp-concurrent: true
proxies: [...]      # все узлы батча
proxy-groups: []    # группы не нужны, обращаемся по имени узла
rules: ["MATCH,DIRECT"]
```

Узлы с протоколами, которые mihomo не принимает, в конфиг не попадают и
помечаются `skipped: unsupported-by-core`.

## 5. CLI

```
proxprobe fetch   [--config sources.yaml] [--refresh] [--workdir DIR]
proxprobe parse   [--workdir DIR] [--source ID]
proxprobe merge   [--workdir DIR]
proxprobe ping    [--workdir DIR] [--concurrency 200] [--timeout 2s]
proxprobe probe   [--workdir DIR] [--core mihomo] [--url URL] [--concurrency 16]
proxprobe export  [--workdir DIR] [--target clash|best|all]
proxprobe all     [--config sources.yaml] [--workdir DIR]
```

`--workdir` по умолчанию `./out`; сырьё, промежуточные и итоговые файлы
лежат внутри него, так что прогон полностью воспроизводим и удаляем.

`sources.yaml`:

```yaml
sources:
  - id: pro1link-clash
    url: https://pro1link.ru/fD-0xCC7_W5jdXM_/
    ua: clash-verge/2.0
  - id: pro1link-xray
    url: https://pro1link.ru/fD-0xCC7_W5jdXM_/
    ua: v2rayNG/1.9.16
    headers: {Accept: application/json}
  - id: goida
    url: https://gitlab.com/avencores/goida-vpn-configs/-/raw/main/githubmirror/1.txt
  - id: sunmiao
    url: https://sunmiao4458.github.io/free-proxy-airport/clash.yaml
  - id: proxypool-singbox
    url: https://raw.githubusercontent.com/snakem982/proxypool/main/source/sing-box-2.json
```

Формат не указывается — определяется по содержимому. `ua` и `headers`
подставляются при скачивании; `insecure: true` на источник нужен там, где
сертификат битый (pro1link на этой машине отдаёт невалидную цепочку).

## 6. Экспорт

| Target | Что генерируется | Проверка |
|---|---|---|
| `clash` | `proxies:` + `proxy-groups` (select по источникам) + `rules` | `mihomo -t -f out/clash.yaml` |
| `best` | Clash YAML только с узлами, прошедшими `probe`, по возрастанию задержки | `mihomo -t` |

Выгрузки в xray/sing-box нет: утилита целиком ориентирована на одно ядро.

## 7. Структура кода

```
proxprobe/
  cmd/proxprobe/main.go        точка входа, разбор подкоманд
  internal/model/node.go       Node, ID, нормализация
  internal/fetch/fetch.go      скачивание, UA, sha256, raw/
  internal/detect/detect.go    определение формата по содержимому
  internal/parse/
      links.go                 share-ссылки (7 протоколов)
      clash.go                 Clash YAML
      xray.go                  Xray-JSON (бандлы и одиночный)
      singbox.go               sing-box JSON
  internal/merge/merge.go      дедуп и слияние
  internal/probe/
      tcp.go                   TCP-connect
      mihomo.go                управление процессом ядра + REST delay
      socks.go                 прямой socks-запрос
  internal/emit/
      clash.go, xray.go, singbox.go, best.go, report.go
  internal/sources/sources.go  чтение sources.yaml
  testdata/                    фикстуры: по одному файлу на формат
```

Один файл — одна ответственность; `internal/parse/*` не знает про
`internal/probe/*`. Зависимость односторонняя: `model` ← `parse` ← `merge`
← `probe` ← `emit`.

## 8. Зависимости

- `gopkg.in/yaml.v3` — YAML (проверено: v3.0.1 доступна).
- Больше внешних модулей нет: JSON, base64, HTTP — стандартная библиотека.
- `github.com/metacubex/mihomo` как **библиотека не подключается**:
  это тянет весь proxy-stack (sing, quic-go, wireguard, gvisor) и делает
  бинарник 40–60 МБ вместо 8–12 МБ. Ядро — внешний бинарник в `$PATH`.

## 9. Сборка и распространение

**Пакет** — `pkgs/proxprobe/package.nix` в `~/.config/nixos-config`, по
образцу `pkgs/free-ai-router/package.nix`: `buildGoModule`, `src` из
`fetchFromGitHub` (репозиторий `kyomufs/proxprobe`), `CGO_ENABLED=0`,
`ldflags -X main.buildVersion=<version>`, `vendorHash`.

**Модуль** — `modules/services/proxprobe.nix`, по образцу
`modules/services/free-ai-router.nix`: плоский файл, header-комментарий с
`# gate: services.proxprobe.enable`, опции объявлены в самом файле через
`myLib.withDesc`, `config = lib.mkIf cfg.enable`.

Демона нет, поэтому нет `systemd.user.services`, нет `sops.secrets`, нет
`home-manager.users`. Модуль ставит только `environment.systemPackages`:
сам бинарь и ядро.

**Модуль mihomo** — `modules/services/mihomo.nix`, отдельно и независимо:
`services.mihomo.enable` кладёт ядро в `environment.systemPackages`.
`proxprobe` его не читает (кросс-модульное чтение `*.enable` запрещено
спекой §4.1) — утилита ищет `mihomo` в `$PATH` и падает с внятным
сообщением, если не нашла.

Опции `proxprobe`:

| Опция | Тип | Назначение |
|---|---|---|
| `enable` | bool | ставит `pkgs/proxprobe` |
| `workdir` | str | каталог по умолчанию, `~/.local/share/proxprobe` |
| `sourcesFile` | str | путь к `sources.yaml`; пусто — только синтетический пример |
| `installCore` | bool | тянуть ли `mihomo` вместе с утилитой |

Опции `mihomo`:

| Опция | Тип | Назначение |
|---|---|---|
| `enable` | bool | ядро в системный профиль |
| `channel`, `version` | через `mkChannelOpts` | stable/unstable или пин на коммит |

`configFile` в модуле proxprobe рендерится через `pkgs.writeText` и
копируется в `~/.config/proxprobe/sources.yaml` только если файла нет —
иначе Nix затирал бы пользовательские подписки при каждом switch.

## 10. Тестирование

Фикстуры — реальные ответы источников, урезанные до 20–30 узлов, в
`testdata/`. Тесты не ходят в сеть.

| Тест | Проверяет |
|---|---|
| `TestDetect` | все 6 фикстур определяются верным форматом |
| `TestParseLinks` | 7 протоколов, счётчики по типам, поля reality |
| `TestParseClash` | `reality-opts.public-key` → `PublicKey`, `servername` → `SNI` |
| `TestParseXrayBundles` | массив бандлов, `freedom` не попадает в узлы |
| `TestParseSingbox` | `selector/urltest/direct` не попадают в узлы |
| `TestNodeID` | одинаковые узлы из разных источников дают один ID |
| `TestMergePrefersComplete` | при конфликте побеждает запись с большим числом полей |
| `TestEmitRoundTrip` | `clash → Node → clash` не теряет `pbk`/`sid`/`fp` |
| `TestEmitXray` | вывод проходит `xray -test` (интеграционный, скипается без ядра) |

Проверка на живых данных — отдельный прогон, не в CI:
`proxprobe all --config sources.yaml --workdir /tmp/pp-run`.

## 11. Риски

| Риск | Смягчение |
|---|---|
| Источник меняет формат при смене UA | формат определяется по содержимому, UA лишь параметр скачивания |
| pro1link отдаёт битый сертификат | `insecure: true` на источник; проверено, что с этим флагом работает |
| mihomo не принимает часть протоколов | узел помечается `unsupported-by-core` и не проверяется, но остаётся в экспорте |
| Дублирующиеся имена узлов | ядро отвергает ВЕСЬ конфиг («is the duplicate name»); имена уникализируются при подаче в ядро и в экспорте |
| Один плохой узел роняет батч | обход идёт батчами по 500; упавший батч помечается, прогон продолжается |
| 428 бандлов × 11 МБ | потоковый разбор через `json.Decoder`, без загрузки всего массива в память |
| Пустой `merged` при недоступности всех источников | `fetch` не перезаписывает raw-файл нулевым ответом; пайплайн останавливается с сообщением |

## 12. Что осталось за границей версии

- выгрузка в форматы xray и sing-box (только чтение);
- HTTP-сервер для раздачи подписки (только файлы);
- обновление подписок по расписанию (только ручной запуск);
- Speedtest пропускной способности (только задержка).
