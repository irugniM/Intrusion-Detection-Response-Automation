# Intrusion Detection and Response Automation

Pi Guard Bot is a small Python agent for a Raspberry Pi running Suricata. Suricata inspects traffic on the home network and writes events to `/var/log/suricata/eve.json`. The agent tails that file, keeps records whose `event_type` is `alert`, and sends a Telegram message for each one. Message text follows the Suricata priority: priority 1 is a high severity alert, priority 2 is a medium severity alert, and priority 3 or higher is a low priority notice. Each message includes the category, signature, and source IP.

The agent runs as a systemd service and reads the Telegram bot token and chat ID from an environment file.

## How it works

```mermaid
flowchart LR
    lan[Home network traffic] --> suricata[Suricata IDS]
    suricata --> eve["/var/log/suricata/eve.json"]
    eve --> agent[Pi Guard Bot]
    agent --> telegram[Telegram Bot API]
    telegram --> chat[Telegram chat]
```

1. Suricata watches a network interface and matches packets against its rules.
2. Matching rules are appended to `eve.json`, one JSON object per line.
3. On startup the agent seeks to the end of `eve.json` and waits for new lines. Alerts already in the file are left alone.
4. Invalid JSON lines are skipped. Other event types, such as `flow`, `dns`, and `stats`, are ignored.
5. For each alert, the agent POSTs the message body to `sendMessage`. The text is form-encoded, so signatures with spaces and punctuation are sent intact.
6. If `eve.json` is replaced or truncated by log rotation, the agent reopens it and continues from the new contents.

A failed send is logged and the agent keeps tailing. At startup the process exits if the token, chat ID, or log file is missing. systemd restarts it. If the log disappears after startup, the agent waits for the path to return.

## Prerequisites

- A Raspberry Pi on the network path you want to inspect, running Raspberry Pi OS (Debian). A Pi 4 with at least 2 GB of RAM is a practical host for Suricata plus this agent.
- The Pi must see the traffic. That means it is the gateway, or a switch mirror (SPAN) port sends a copy of the traffic to the Pi. Packets that never cross the capture interface produce no alerts.
- A Telegram account.
- `sudo` on the Pi.

Commands below use the account name `user` and the install directory `/home/user/pi_guard_bot`, matching `piguard.service`. Replace both if your account name is different.

## 1. Install Suricata

```bash
sudo apt update
sudo apt install suricata suricata-update jq python3
```

`suricata-update` installs and refreshes rules. `jq` is only used when you want to read `eve.json` from the shell.

Enable the service and confirm it is running:

```bash
sudo systemctl enable --now suricata
sudo systemctl status suricata
```

## 2. Configure Suricata for eve.json alerts

The Debian package ships `/etc/suricata/suricata.yaml` with EVE JSON output. Confirm the `eve-log` output is enabled and that `alert` is one of its types:

```bash
grep -n -A 30 "eve-log:" /etc/suricata/suricata.yaml
```

The relevant block should look like this (other event types may be listed too):

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
```

`filename` is relative to `default-log-dir`, which should be `/var/log/suricata/`. The agent then reads `/var/log/suricata/eve.json`.

Set the capture interface to the NIC that actually sees the traffic. Find the name with:

```bash
ip -br link
```

On Raspberry Pi OS that is often `eth0`, `end0`, or `wlan0`. In `suricata.yaml`, set `af-packet` to that name:

```yaml
af-packet:
  - interface: eth0
```

Check `HOME_NET` under `vars.address-groups`. It should include your LAN, for example:

```yaml
HOME_NET: "[192.168.1.0/24]"
```

The packaged default already covers the RFC 1918 ranges. Set it explicitly when the LAN uses a different range.

Validate the file before restarting:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
sudo systemctl restart suricata
```

`-T` loads the config and exits. Fix any reported path or YAML error before continuing.

## 3. Install and update rules

Fetch the default Emerging Threats Open ruleset and restart so Suricata loads it:

```bash
sudo suricata-update
sudo systemctl restart suricata
```

Rules are written to `/var/lib/suricata/rules/suricata.rules`. Run `suricata-update` again whenever you want fresh signatures, then restart Suricata.

To refresh rules every day, enable the timer if the package provides one:

```bash
systemctl list-unit-files 'suricata-update*'
sudo systemctl enable --now suricata-update.timer
```

If no timer is installed, a root cron job does the same work:

```cron
15 2 * * * /usr/bin/suricata-update && /bin/systemctl restart suricata
```

## 4. Create a Telegram bot

1. In Telegram, open a chat with [@BotFather](https://t.me/BotFather).
2. Send `/newbot` and follow the prompts for a display name and a username that ends in `bot`.
3. BotFather replies with an HTTP API token. That value is `TELEGRAM_BOT_TOKEN`. Keep it in the env file on the Pi only.
4. Open a chat with your new bot and send a message such as `hello`. Telegram only delivers bot messages to a user who has started the chat.
5. On the Pi, after the token is in your shell environment, ask Telegram for the chat id:

```bash
curl -s "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates"
```

In the JSON, find `"chat":{"id":` followed by a number. That number is `TELEGRAM_CHAT_ID`.

For a group, add the bot to the group, send a message in the group, run `getUpdates` again, and use the group id (it is a negative number).

If `getUpdates` returns `"result":[]`, send the bot another message and retry. A token that Telegram rejects produces a 401 response; request a new token from BotFather with `/token` if that happens.

## 5. Install the agent

Clone this repository into the directory named by the systemd unit:

```bash
sudo apt install git
git clone https://github.com/irugniM/Intrusion-Detection-Response-Automation.git /home/user/pi_guard_bot
sudo chown -R user:user /home/user/pi_guard_bot
```

The service uses `/usr/bin/python3`. Install Requests for that interpreter from the distro package, which matches the pin in `requirements.txt` on Raspberry Pi OS Bookworm:

```bash
sudo apt install python3-requests
```

Alternatively, install the pinned dependency with pip:

```bash
python3 -m pip install --user -r /home/user/pi_guard_bot/requirements.txt
```

On Debian 12 and later, system-wide pip may refuse the install unless you pass `--break-system-packages`. Prefer the apt package so the systemd service can import `requests` with `/usr/bin/python3`.

`eve.json` is usually mode `640` and group `suricata`. Add the service account to that group so it can read the log:

```bash
sudo usermod -aG suricata user
sudo -u user test -r /var/log/suricata/eve.json && echo readable
```

If that prints nothing, check `ls -l /var/log/suricata/eve.json` and adjust the group or ACL. Restart the agent after changing group membership.

## 6. Configure the environment file

```bash
cp /home/user/pi_guard_bot/.env.example /home/user/pi_guard_bot/.env
chmod 600 /home/user/pi_guard_bot/.env
```

Edit `.env`:

```bash
TELEGRAM_BOT_TOKEN=123456789:replace-with-the-real-token
TELEGRAM_CHAT_ID=123456789
```

Leave values unquoted. systemd's `EnvironmentFile` treats `#` as a comment.

`SURICATA_EVE_PATH` is optional. Set it only when Suricata writes `eve.json` somewhere other than `/var/log/suricata/eve.json`.

`.env` is listed in `.gitignore`. Do not commit it.

## 7. Install and enable the systemd service

If the Linux account or install path is not `user` and `/home/user/pi_guard_bot`, edit `User`, `WorkingDirectory`, `EnvironmentFile`, and `ExecStart` in `piguard.service` first.

```bash
sudo cp /home/user/pi_guard_bot/piguard.service /etc/systemd/system/piguard.service
sudo systemctl daemon-reload
sudo systemctl enable --now piguard.service
sudo systemctl status piguard.service
```

A healthy start logs `Pi Guard Bot online. Monitoring /var/log/suricata/eve.json`. The unit restarts on failure after 5 seconds. It waits for the network and is ordered after `suricata.service`.

## 8. Send a test alert

Start the agent before generating the test, because it only reports lines appended after it opens the file.

From the Pi, request the well-known Suricata test page over plain HTTP. The response body contains `uid=0(root)`, which matches Emerging Threats signature `2100498`, `GPL ATTACK_RESPONSE id check returned root`. HTTPS hides that payload, so use `http://`.

```bash
curl -s http://testmynids.org/uid/index.html
```

Confirm Suricata recorded it:

```bash
sudo tail -n 50 /var/log/suricata/eve.json | jq 'select(.event_type=="alert") | {signature:.alert.signature, priority:.alert.priority, src_ip:.src_ip}'
```

You want signature `GPL ATTACK_RESPONSE id check returned root` and priority `2`. The classification for that rule is `Potentially Bad Traffic`.

Telegram should then show:

```text
MEDIUM SEVERITY ALERT
Priority: 2
Type: Potentially Bad Traffic
Signature: GPL ATTACK_RESPONSE id check returned root
Source IP: <address Suricata observed>
```

The same formatting is covered by `python3 -m unittest discover -s tests -v` on a machine that has Python 3 and `requests` installed. Those tests do not call the network.

## 9. View logs

```bash
journalctl -u piguard.service -f
journalctl -u piguard.service -n 100 --no-pager
journalctl -u suricata.service -n 50 --no-pager
```

Suricata's one-line alert log is a useful cross-check:

```bash
sudo grep 2100498 /var/log/suricata/fast.log
```

## Troubleshooting

**The service will not start and journalctl says the environment file could not be read.** Create `/home/user/pi_guard_bot/.env` from `.env.example`. The path must match `EnvironmentFile` in the unit. `chmod 600` is fine; systemd reads the file as root before dropping to `User`.

**The log says `TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set`.** One of the variables is missing or empty. Names are case-sensitive, and the file cannot use the `export` keyword.

**The log says it could not find `/var/log/suricata/eve.json`.** Suricata is not running, or `default-log-dir` / `filename` point elsewhere. Set `SURICATA_EVE_PATH` to the real file, or fix the Suricata output path and restart both services.

**Permission denied while opening the log.** Add the service user to the `suricata` group (step 5) and restart `piguard.service`.

**Status is active, but Telegram stays quiet.** The agent ignores everything already in the file at startup. Generate the test alert after the service is up, and confirm a new `event_type: alert` line landed in `eve.json`. A `Failed to send Telegram message: HTTPError (HTTP 401)` line means the token was rejected. `HTTP 400` usually means the chat id is wrong, or you have not opened a chat with the bot yet.

**`eve.json` has flow or stats events, but no alert for the test URL.** Check each of these:

- `curl` used `http://testmynids.org/uid/index.html`, not `https://`.
- `sudo suricata-update` has been run and Suricata was restarted afterward.
- `af-packet.interface` is the NIC that carried the curl traffic. Traffic generated on the Pi is visible only if that NIC is the one Suricata is watching.
- `suricata -T` succeeds and `systemctl status suricata` is active.

**Alerts stop after log rotation.** The agent reopens `eve.json` when the inode changes or the file shrinks. If a rotation tool moves the file aside for a long time before creating a new one, the agent waits for the path to reappear. `sudo systemctl restart piguard.service` resumes from the end of the current file.

## Project layout

| File | Purpose |
| --- | --- |
| `bot.py` | Agent: tail `eve.json`, format alerts, send Telegram messages |
| `piguard.service` | systemd unit, including `EnvironmentFile` |
| `requirements.txt` | Python dependency pin (`requests==2.28.1`) |
| `.env.example` | Placeholder token, chat id, and optional log path |
| `tests/test_alerts.py` | Unit tests for parsing and priority formatting |
