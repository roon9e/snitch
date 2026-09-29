# snitch

A Telegram bot that enforces one rule: **the users you list in `.env` may not
talk to each other** in your group. When one of them addresses another, the
message is deleted. Optionally the sender is muted for a configurable number of
hours. And there is a forum topic you nominate where the rule simply does not
apply.

Everything - who is restricted, which topic is exempt, how long the mute lasts -
lives in `.env`. No database, no dashboard, no inbound ports.

---

## How the rule works

For every message in the guarded group, in order:

| # | Check | If it fails |
|---|-------|-------------|
| 1 | Is this the configured group? | ignore |
| 2 | Is there a real human sender? (not a bot, not an anonymous admin, not a channel post) | ignore |
| 3 | Is the sender in `RESTRICTED_USERS`? | ignore |
| 4 | Is this a whitelisted topic? | **ignore - rule does not apply here** |
| 5 | Does the message address another restricted user? | ignore |
| 6 | Is the sender a chat admin? (`IGNORE_ADMINS`) | log only - bots cannot restrict admins anyway |
| 7 | **Violation** | delete, then optionally mute |

### What counts as "addressing another restricted user"

Any of the enabled detectors, and each one is a separate switch:

- **`DETECT_REPLIES`** - a reply to a restricted user, including a reply that
  crosses forum topics (Telegram's `external_reply` field).
- **`DETECT_MENTIONS`** - an `@username` mention or a tap-to-mention
  (`tg://user?id=...`) pointing at a restricted user.
- **`DETECT_BARE_USERNAMES`** - a restricted user's username appearing as plain
  text. This one is fuzzy on purpose: it catches `hey alice`, and it can be
  evaded by dropping the `@` or by renaming. Turn it off if you want only
  structured, unfakeable signals.

---

## Setup

### 1. Create the bot

1. Message [@BotFather](https://t.me/BotFather), send `/newbot`, keep the token.
2. **Disable privacy mode** - this is mandatory. Send `/setprivacy`, pick the
   bot, choose `Disable`.
   With privacy mode on, Telegram does not deliver other people's messages to
   your bot and the rule can never fire. This is the single most common reason
   a bot like this appears to do nothing.

### 2. Add the bot to your group as an administrator

Right-click the bot -> `Manage Chat` -> `Administrators` -> `Add Administrator`:

- **Delete messages** - required for the primary punishment.
- **Ban users** - required only if you enable `MUTE_ENABLED`, and for `/unmute`.

The group must be a **supergroup**. If you use `WHITELIST_TOPIC_IDS`, enable
`Topics` in the group settings too.

### 3. Configure

```bash
cp .env.example .env
```

Fill in at least:

```dotenv
BOT_TOKEN=123456789:AAyour_token
CHAT_ID=-1001234567890
RESTRICTED_USERS=111111111,222222222
WHITELIST_TOPIC_IDS=42
```

### 4. Find your ids

Add the bot to the group and send:

```
/id
```

It replies with `CHAT_ID`, your own user id, and the current
`message_thread_id`. **Run `/id` inside the topic you want to whitelist** to get
the right `WHITELIST_TOPIC_IDS` value.

To find another user's numeric id, forward a message from them to
[@userinfobot](https://t.me/userinfobot). Prefer numeric ids over usernames:
a user can change their username at any time.

#### "CHAT_ID is a basic group id, not a supergroup id"

`CHAT_ID` must start with `-100`. Two things cause this message:

- The group is still a **basic group**. snitch needs a supergroup, because
  `restrictChatMember` (the mute) and forum topics (`WHITELIST_TOPIC_IDS`) do
  not exist in a basic group. Enable **Topics** in the group settings to upgrade
  it.
- Your id is **stale**. Telegram assigns a brand new id when a group is
  upgraded to a supergroup, so any id copied before the upgrade no longer
  resolves. `/id` in the group gives you the current one.

#### "cannot read CHAT_ID ... chat not found"

Telegram returns this identical error for "no such chat" and "you are not a
member", so check both, in this order:

1. Is the bot actually a member of the group?
2. Is `CHAT_ID` the current id (see above)?

### 5. Check the rule before you punish anyone

```
/check
```

`/check` replays the current configuration over the last 50 messages and tells
you which of them would be blocked and why. Tune `RESTRICTED_USERS` and the
detector switches until the output looks right, and only then turn on
`MUTE_ENABLED`.

### 6. Run it

```bash
docker compose up -d
docker compose logs -f
```

The image is built from your checkout. If you would rather pull a prebuilt
image, see [Using a prebuilt image](#using-a-prebuilt-image).

### 7. If nothing happens

The single most common cause is that **privacy mode is still on**. It is not
queryable through the Bot API, and a bot that cannot see the group cannot be
asked about it, so snitch says so itself: it logs a reminder at startup, and if
ten minutes pass with no messages at all it logs the full checklist.

To confirm, message the bot **directly in private**:

```
@snitch_punish_bot  /id
```

Private chats ignore privacy mode. If that works but the group does not, privacy
mode is the cause - fix it via `@BotFather` -> `/setprivacy` -> your bot ->
`Disable`, then restart.

---

## Configuration

See [`.env.example`](.env.example) for the annotated full list. The essentials:

| Variable | Default | Meaning |
|---|---|---|
| `BOT_TOKEN` | *required* | Token from @BotFather |
| `CHAT_ID` | *required* | Supergroup id (`-100...`) or `@username` |
| `PROXY_URL` | empty | Route API calls through a proxy, e.g. `socks5://user:pass@host:1080` |
| `RESTRICTED_USERS` | *required* | Comma separated user ids and/or `@usernames` |
| `WHITELIST_TOPIC_IDS` | empty | Topic ids where the rule is off; `general` for the General topic |
| `DELETE_MESSAGE` | `true` | Delete the offending message |
| `MUTE_ENABLED` | `false` | Also mute the sender |
| `MUTE_HOURS` | `24` | Mute length, `1..8784` |
| `DETECT_REPLIES` | `true` | Catch replies |
| `DETECT_MENTIONS` | `true` | Catch mentions |
| `DETECT_BARE_USERNAMES` | `true` | Catch usernames in plain text |
| `IGNORE_ADMINS` | `true` | Never touch admins |
| `NOTICE_MODE` | `log` | `log`, `chat`, `dm` or `none` |
| `ADMIN_IDS` | empty | Extra users allowed to run `/unmute`, `/check`, `/status` |
| `LOG_LEVEL` / `LOG_FORMAT` | `INFO` / `text` | Set `LOG_FORMAT=json` for log shipping |
| `DATA_DIR` | `/app/data` | Where `violations.jsonl` is written |

Invalid configuration is rejected at startup, with the offending variable named.
`MUTE_HOURS` above 8784 is refused because Telegram silently turns any
restriction longer than 366 days into a **permanent** ban.

---

## Commands

| Command | Who | What |
|---|---|---|
| `/id` | anyone | Chat id, your user id, current topic id |
| `/help` | anyone | Short usage |
| `/status` | admins | Active config, each restricted user's current state, last violations |
| `/check` | admins | Replay the rule over recent messages |
| `/unmute <id\|@user>` | admins | Lift a restriction early |

---

## Proxy

If the host cannot reach `api.telegram.org` directly, set one variable:

```dotenv
PROXY_URL=socks5://127.0.0.1:1080
PROXY_URL=socks5://user:password@proxy.example.com:1080
PROXY_URL=http://user:password@proxy.example.com:3128
```

Empty (the default) means connect directly.

**Supported schemes:** `socks5`, `socks4`, `http`, `https`.

**Use `socks5`, not `socks5h`.** `aiohttp_socks` rejects `socks5h` outright, and
it would gain nothing here anyway: aiogram hardcodes `rdns=True`, so **DNS is
always resolved by the proxy** and your local resolver never sees
`api.telegram.org`. That is what makes the connection work on a network with a
hijacked or blocked resolver.

| Gotcha | What to do |
|---|---|
| Port omitted | Fine. Defaults to `1080` for socks, `8080` for http. |
| Password contains `@ : / ? #` | Percent-encode it: `%40 %3A %2F %3F %23`. An unencoded `@` makes the parser read the rest of the URL as the hostname. |
| Proxy runs on the Docker **host** | `127.0.0.1` is the *container*. Use `host.docker.internal` or the host's LAN IP. |
| Username without a password (or the reverse) | Rejected at startup. Most SOCKS servers refuse it, and it is nearly always a typo. |
| Proxy goes down | Treated as a network error, not a config error: retried in-process with backoff, and the message names the proxy (never its password). |

The password is treated as a secret. It is not logged, it is masked in
`/status`, it is hidden from `repr(settings)`, and both its percent-decoded and
percent-encoded spellings are scrubbed from log output and tracebacks.

The proxy is verified at startup like everything else. `snitch` opens a short TCP
connection to it and completes a real SOCKS handshake, so a bad proxy produces a
**specific** verdict in a few seconds rather than an opaque 30-second request
timeout raised from inside aiogram:

| Verdict | What it means | What to do |
|---|---|---|
| `ok` | Reachable, and it answered a SOCKS greeting | Nothing |
| `refused` | Host answered, nothing listening | Wrong port, proxy not running, or it binds to `127.0.0.1` only |
| `timed_out` | Nothing answered — a **silent drop** | No route, a firewall discarding packets, or the host is down |
| `dns_failed` | Proxy hostname unresolvable | Use the IP, or fix the container's DNS |
| `not_socks` | Port open, no SOCKS handshake | Wrong service on the port, or the proxy requires credentials |

`refused` vs `timed_out` is the distinction that matters: *refused* means
something answered; *timed out* means packets are being discarded somewhere on
the way. Every failure message ends with an `nc -vz` command to run **on the
host**, where Docker is not in the way.

A dead proxy is treated as transient rather than as a config error, so the bot
retries with backoff instead of giving up - the proxy may well come back.

---

## Using a prebuilt image

Multi-arch images (`linux/amd64`, `linux/arm64`) are published to ghcr.io on
every `v*` tag:

```bash
IMAGE=ghcr.io/roon9e/snitch:1.0.0 docker compose up -d
```

Available tags: `1.0.0` (and `1.0` for the minor series), plus `latest`.

To publish a new one, from a clean checkout:

```bash
git tag v1.1.0 && git push origin v1.1.0
```

`release.yml` builds, pushes, then pulls the image back and runs it, so a broken
build fails the release rather than shipping. It needs the repository set to
*Settings -> Actions -> General -> Workflow permissions -> Read and write
permissions*; the workflow itself only uses the automatic `GITHUB_TOKEN`.

`docker compose up` with no `IMAGE` set builds from your checkout instead, which
is the better default while you are changing anything. `pull_policy: build` is
what stops compose resolving the unqualified `snitch:1.0.0` as
`docker.io/library/snitch` and printing `pull access denied` before quietly
building anyway.

## The mute caveat, in full

Telegram's `restrictChatMember` **has no topic parameter.** Permissions are
strictly chat-wide - there is no way to mute somebody in one forum topic and not
another.

That is why deletion is the primary punishment: `deleteMessage` acts on a single
message, so the whitelist works exactly as you would expect. The mute is opt-in
(`MUTE_ENABLED=false` by default) because with it enabled:

> A muted user is silenced in **every** topic of the group, including the
> whitelisted one. The whitelist then means "no *new* punishments are started
> from this topic", not "this topic stays usable while you are muted".

If you need the whitelisted topic to remain a usable safe room *during* a mute,
that requires a different mechanism (the bot would have to delete messages
instead of restricting the user), which is not implemented here. It is also
weaker: the message stays visible for a moment before deletion, and the
punishment evaporates whenever the bot is down.

Two more limits worth knowing:

- **Deletion is not instant.** The bot reacts to the update after Telegram
  delivers it, so a violating message is briefly visible. This is inherent to
  the Bot API - there is no pre-send hook.
- **Bare-username detection is bypassable.** Dropping the `@` or renaming defeats
  it. `DETECT_BARE_USERNAMES=false` gives you only the unfakeable signals.

---

## Development

```bash
uv sync                 # or: python -m venv .venv && pip install -e ".[dev]"
uv run pytest           # unit tests, no network or token required
uv run ruff check .
uv run ruff format .
uv run mypy
```

The rule engine in `src/snitch/detection.py` is deliberately pure - it turns a
message plus configuration into a decision and touches nothing else - so the
interesting logic is tested without a network, a token, or an event loop.
`tests/` builds real `aiogram` `Message` objects and asserts on the outcomes.

Layout:

```
src/snitch/
  config.py            validated .env settings
  detection.py         the rule engine (pure)
  directory.py         RESTRICTED_USERS -> ids + usernames, with refresh
  preflight.py         startup checks; fails fast on missing admin rights
  proxy_probe.py       pinpointing an unreachable proxy
  liveness.py          warns when the bot has seen nothing (privacy mode)
  permissions.py       the exact mute / unmute permission payloads
  bot.py               dependency graph, middleware, background tasks
  __main__.py          config, logging, signals, startup retry, shutdown
  handlers/
    watch.py           the pipeline above
    commands.py        /id /status /check /unmute
  services/
    moderator.py       delete, then mute; locks, cooldowns, no stacking
    notifier.py        NOTICE_MODE
    audit.py           append-only violations.jsonl
```

`preflight.py` refuses to start if the bot is missing the admin rights the
configured punishment needs, or if no `RESTRICTED_USERS` entry resolves, rather
than pretending to guard the group. It also tells permanent problems (a wrong
`CHAT_ID`, a revoked admin right) apart from transient ones (a Telegram 5xx, a
rate limit, a dropped connection):

- **Permanent** -> the process exits with the message and the container stops
  (`restart: on-failure:3`), so the one useful error is not buried under an
  endless restart loop.
- **Transient** -> retried in-process with backoff (5s, 15s, 30s, 60s) before
  giving up, so a momentary Telegram outage does not kill a running bot.

Checks run in dependency order - local config, then token, then chat, then
restricted users, then rights - so the first line you see is the real problem
rather than a screen of consequences.

## License

MIT
