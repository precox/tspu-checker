# TSPU Checker

![Три промышленных монитора с движущимися осциллограммами](docs/tspu-checker-loop.webp)

Протокол-независимая диагностика доступности VPN и признаков фильтрации. TSPU Checker сопоставляет пробы из клиентских сетей, контроль входа и контроль выхода по времени. Отчёт показывает, где воспроизводится сбой и какие данные есть для его разбора.

Проект в стадии alpha. Для CLI нужен Python 3.11 или новее. Внешних Python-зависимостей нет.

## Быстрый старт

Запустите синтетический пример из клона репозитория:

```sh
git clone https://github.com/precox/tspu-checker.git
cd tspu-checker
python3 -m tspu_checker report --as-of 2030-01-01T10:02:00Z examples/observations.jsonl
```

Фрагмент ожидаемого вывода:

```json
[
  {
    "result": "client_path_issue_suspected",
    "attribution": "unestablished",
    "working_client_networks": ["mobile-isp"],
    "client_networks_with_failures": ["wifi-isp"]
  }
]
```

В этом примере VPN работает из мобильной сети. В Wi-Fi отказы повторяются при успешных контрольных проверках, поэтому отчёт выделяет клиентский путь из этой сети. Причина сбоя остаётся неустановленной.

## Установка команды

С установленным [pipx](https://pipx.pypa.io/latest/how-to/install-pipx.html) можно поставить CLI прямо из GitHub:

```sh
pipx install 'git+https://github.com/precox/tspu-checker.git'
tspu-checker --help
```

После установки вместо `python3 -m tspu_checker` в примерах можно использовать `tspu-checker`.

## Реальные замеры

Для реальных замеров используйте один `--run` и `--target` для инцидента. Для каждой новой попытки задайте новый `--attempt`. Фазы одной попытки должны иметь одну и ту же точку наблюдения, сеть и идентификатор. Одинаковую конфигурацию туннеля обозначайте одной меткой `--profile`.

После реального переподключения запишите результат установления свежей VPN-сессии. Затем проверьте выход, запустив HTTPS-запрос внутри этой сессии. Подставьте собственный адрес HTTPS-контроля, который возвращает наблюдаемый с его стороны IP простым текстом, и IP вашего выхода.

```sh
mkdir -p runs
python3 -m tspu_checker record --run incident-01 --target vpn-edge \
  --role client --vantage phone-wifi --network wifi-isp --profile demo-vpn \
  --attempt wifi-one --method https --stage session --outcome pass >> runs/incident-01.jsonl
python3 -m tspu_checker check-https --run incident-01 --target vpn-edge \
  --role client --vantage phone-wifi --network wifi-isp --profile demo-vpn \
  --attempt wifi-one --stage tunnel --url https://ip.example.org/ \
  --expect-ip 192.0.2.10 >> runs/incident-01.jsonl
python3 -m tspu_checker report runs/incident-01.jsonl
```

Для ручного подтверждения `tunnel` или `egress` передайте `--expect-ip` и `--observed-ip` со значениями, которые сверили. В JSONL попадает результат сопоставления, а не адреса. Для прямого HTTPS-контроля используйте `--stage baseline` и отключите VPN. TLS проверяется по доверенным сертификатам системы.

## Адаптер Hysteria2

Адаптер переводит результаты существующих Hysteria2- и HTTP/3-проб и UDP-счётчики из локального systemd journal. Явно укажите ожидаемый unit для каждого типа событий.

```sh
journalctl -u my-hysteria-check.service -u my-http3-check.service -o json --since '-10 min' |
  python3 -m tspu_checker import-hysteria2 --run incident-01 --target vpn-edge \
    --role server --vantage entry-node --network host-network --profile demo-vpn \
    --tunnel-unit my-hysteria-check.service --http3-unit my-http3-check.service \
    >> runs/incident-01.jsonl
```

Адаптер сверяет метаданные локального журнала и сообщает о выбранных службах без результатов. Запуск Hysteria2- и HTTP/3-проб остаётся задачей вашей установки. [Формат импорта](docs/methodology.md#адаптер-hysteria2)

## Разбор инцидента

Команда `incident` строит хронологию из клиентских и серверных проверок, окон UDP и выбранных событий журналов. В синтетическом примере с 10:01 до 10:06 UTC зафиксирован нулевой входящий UDP с исправным сбором. С 10:06 до 10:07 запись отсутствует. После возобновления трафика журнал показывает закрытие сессии и новое подключение.

```sh
python3 -m tspu_checker incident examples/incident/observations.jsonl \
  --run example-incident --target vpn-edge --local-vantage entry \
  --start 2030-01-01T10:00:00Z --end 2030-01-01T10:09:00Z \
  --journal examples/incident/server-journal.jsonl \
  --resource-unit example-resources.service --gateway-unit example-gateway.service \
  --hysteria-log examples/incident/hysteria2.log --hysteria-version 2.14.0
```

[Как собрать входные данные и читать хронологию](docs/methodology.md#хронология-инцидента).

## Методика и примеры

- [Порядок проверки, формат JSONL и интерпретация](docs/methodology.md).
- [Два узла с выделенным выходом и fail-closed](examples/two-node/README.md).

Выполняйте пробы против своих или разрешённых конечных точек. Для отчётов используйте условные метки операторов и узлов. CLI исключает из результата URL, IP, исходные сообщения журнала и содержимое ответа.

```sh
python3 -m unittest discover -s tests
```
