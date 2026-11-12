<div align="center">

# staytun

**VPN dropped? So did the internet. Your IP stays home.**

A VPN kill switch for macOS and Linux. If the tunnel blinks for even a second,
not a single packet leaves your machine from your real IP.

[Русская версия](README.md)

</div>

---

## Why

VPNs drop: the router reconnects, the server restarts, Wi‑Fi hiccups, the laptop wakes from sleep.
In a split second the system falls back to your regular connection, and every open app —
Claude, ChatGPT, Cursor, Gemini, Telegram — **immediately pings its servers from your home IP**.

To services that watch your region, that looks like "this account keeps jumping between countries".
The result: verification checks, restrictions, bans.

Built-in "kill switches" in VPN clients work at the app level and often react too late.
**staytun blocks traffic in the OS kernel** (pf on macOS, nftables on Linux): anything not going through
the tunnel simply never gets out. VPN down — internet gone. VPN back — everything works again.

## Quick start

```sh
curl -fsSL https://raw.githubusercontent.com/k1y0miiii/staytun/main/install.sh | sh
```

1. Connect your VPN as usual.
2. `staytun doctor` — checks that everything is detected.
3. `staytun on` — turns protection on (asks for your admin password).

Turn off: `staytun off`. Check status: `staytun status`.

## Features

- **Protects the whole system at once** — browser, apps, terminal, Docker. No per-app setup.
- **Auto-detects your VPN client**, its servers and tunnel — no typing IPs by hand.
- **Understands your client's routing.** If your VPN sends local sites in your country direct (e.g. `geoip:ru`),
  staytun lets them through too — government portals and banking sites keep working.
- **Knows all your servers**, not just the current one: switch locations freely, protection won't get in the way.
- **Refuses to launch** Claude Code, Cursor and other CLIs without protection (optional).
- **Breaks nothing**: rules last until reboot or `staytun off`, and the stock macOS firewall is restored exactly as it was.
- Zero dependencies besides python3. staytun itself never touches the network — it only resolves server domains via DNS.

## Supported VPN clients

| Client | OS | Auto-detects |
|---|---|---|
| **V2Box** | macOS | servers, direct rules (geoip, IP), geoip.dat |
| **v2RayTun** | macOS | all servers from profiles and subscriptions, direct rules |
| **Streisand** | macOS | all servers from profiles |
| **Happ** | macOS | server — from the live connection (`staytun sync`) |
| **Hiddify** | macOS, Linux | servers and direct rules from config (experimental) |
| **WireGuard / AmneziaWG** | macOS, Linux | endpoint — from the live connection; on Linux also from `/etc/wireguard` |
| **Anything else** | macOS, Linux | manual mode: tunnel is auto-detected, servers via `staytun allow add` |

Client not listed? Manual mode works (see below), and you can add an adapter (see "Adding a client").

## Installation

**Requirements**
- macOS 12+ or Linux with nftables (Ubuntu 20.04+, Debian 11+, Fedora, Arch).
- python3 3.9+. On macOS you get it with `xcode-select --install`.

**One-liner** (installs to `~/.local/bin`, no sudo):

```sh
curl -fsSL https://raw.githubusercontent.com/k1y0miiii/staytun/main/install.sh | sh
```

**From source:**

```sh
git clone https://github.com/k1y0miiii/staytun && cd staytun && ./install.sh
```

**With pipx:**

```sh
pipx install git+https://github.com/k1y0miiii/staytun
```

## Usage

```sh
staytun on        # turn on (VPN must be connected)
staytun off       # turn off
staytun status    # is it on, which tunnel, what's allowed through
staytun doctor    # diagnostics: what's detected and whether it's safe to turn on
```

Dashes work too: `staytun --on`, `staytun --off`, `staytun --status`.

### Verify it works

1. `staytun on`
2. Check your IP: `curl https://ifconfig.me` — it should be your VPN server's IP.
3. Disconnect the VPN in your client.
4. Repeat: `curl -m 5 https://ifconfig.me`

**Expected result:** an error or a timeout. If your home IP shows up, protection isn't working —
run `staytun doctor` and open an issue with its output.

5. Reconnect the VPN — the internet comes back on its own. If not, run `staytun on` again
   (sometimes the client brings the tunnel up under a different name).

## Exceptions: what bypasses the VPN

By default, only these are allowed outside the tunnel:
- your VPN servers (otherwise it couldn't reconnect);
- whatever your VPN client itself routes direct (e.g. `geoip:ru`);
- your local network: router, printer, NAS.

Add your own — an IP, subnet or domain:

```sh
staytun allow add 203.0.113.7               # single IP
staytun allow add 198.51.100.0/24           # subnet
staytun allow add vpn2.example.com          # domain (resolved on staytun on)
staytun allow list                          # show what's added
staytun allow rm 203.0.113.7                # remove
```

Changes apply instantly if protection is on. The list lives in `~/.config/staytun/allow.txt` —
feel free to edit it by hand.

> **Tip.** Add *all* the servers from your VPN subscription to exceptions. Then switching
> locations works with protection on, even if your client isn't auto-supported.

## Settings

```sh
staytun config                 # show all
staytun set <key> <value>      # change
```

| Key | Default | Meaning |
|---|---|---|
| `interface` | `auto` | The tunnel. `auto` — whichever one currently carries internet traffic. Or a name: `utun4`, `wg0`, `tun0` |
| `clients` | `auto` | Which clients to consider: `auto`, `none` or a list like `v2box,happ` |
| `direct` | `yes` | Let through what the client itself routes direct |
| `lan` | `yes` | Local network access |
| `geoip` | — | Extra countries to bypass the tunnel, e.g. `ru,by` |
| `geoip_file` | — | Path to `geoip.dat` if no client provides one |
| `protect` | `claude cursor cursor-agent` | Commands that won't start without protection |

Examples:

```sh
staytun set direct no          # strict mode: absolutely everything through the VPN
staytun set geoip ru           # Russian IPs go direct, even if the client can't do that
staytun set interface wg0      # set the tunnel explicitly
staytun set clients none       # manual mode only
```

### Picking a tunnel

```sh
staytun interfaces
```

Lists all VPN tunnels and marks the one currently carrying internet traffic. Usually there's nothing to pick:
`auto` grabs exactly that one. Set it explicitly only if you run several VPNs at once.

## Don't launch apps without protection

Add to `~/.zshrc` or `~/.bashrc`:

```sh
eval "$(staytun shell-init)"
```

Now `claude`, `cursor` and `cursor-agent` refuse to start if protection is off or the VPN is down.
Change the list: `staytun set protect "claude cursor gemini codex"`. Bypass it: `command claude`.

One-off: `staytun run claude` — launches only if protection is active.

## FAQ

**Internet died after turning it on.**
Your VPN isn't connected right now, or it reconnected under a different tunnel name. Connect the VPN and run
`staytun on` again. Emergency off: `staytun off`. A reboot also resets everything.

**Local sites in my country won't open.**
staytun only lets through what your client routes direct *by IP*. Domain-based rules
(`geosite:category-ru`) can't be checked by a firewall — such sites hosted on foreign CDNs will be blocked.
Fix: `staytun set geoip ru` (your country code) or add the address with `staytun allow add`.

**Switched servers in my VPN client — no internet.**
The new server isn't in exceptions yet. Run `staytun on` (it'll find it again) or add
all subscription servers upfront: `staytun allow add ...`.

**Happ / WireGuard: "server not found".**
Their servers are only visible while the connection is live. Connect and run `staytun sync`.
staytun will remember the address for next time.

**Does protection survive a reboot?**
No — by design, so staytun can never leave you permanently offline.
If apps launch at startup (Claude, Cursor, Telegram), remove them from login items or
make `staytun on` the first thing you run.

**I have a custom /etc/pf.conf (macOS).**
While staytun is on, it uses Apple's stock ruleset + staytun rules. Your rules come back after
`staytun off`.

**Docker / VMs on Linux?**
Covered: staytun filters both host traffic and forwarded traffic.

**What staytun does NOT do.**
It only prevents IP leaks. Time zone, system language, browser fingerprint and DNS queries
to your ISP (without VPN) are separate stories.

## How it works

```
app ──► kernel ──┬─► VPN tunnel (utun / wg / tun) ──► internet            ✓
                 ├─► VPN server directly (handshake) ──► internet         ✓
                 ├─► client's direct routes, LAN                          ✓
                 └─► everything else                                      ✗ drop
```

- **macOS:** pf. The main ruleset is replaced with a copy of the stock `/etc/pf.conf` plus staytun rules.
  The block sits before Apple's anchors, `state-policy if-bound` keeps old connections from leaking over Wi‑Fi,
  and pf is enabled via a token without breaking other programs' rules.
- **Linux:** nftables, a dedicated `inet staytun` table, atomic replacement, output and forward chains.
- Servers come from client configs (they're VPN servers — letting them through directly is safe).
  Direct rules are read only from a running client. Live connections are read only for Happ and WireGuard,
  whose process talks to nothing but its own server.
- State is stored in `/var/run/staytun.state` (macOS) or `/run/staytun.state` (Linux), written by root.

Preview the rules without applying anything: `staytun rules`.

## Adding a client

An adapter is a class in [`src/staytun/clients.py`](src/staytun/clients.py). For xray-core based clients
specifying the paths is usually enough:

```python
class MyClient(XrayClient):
    id, title, platforms = "myclient", "MyClient", ("darwin",)
    homes = ("~/Library/Group Containers/group.com.example.myclient",)  # where the data lives
    procs = ("MyClient.app/Contents/PlugIns",)                          # how to tell it's running
    configs = ("profiles/*.json",)                                      # all servers
    active = ("current.json",)                                          # current config with routing
```

Add it to the `ALL` list, add a test in `tests/` — and send a pull request.

## Uninstall

```sh
curl -fsSL https://raw.githubusercontent.com/k1y0miiii/staytun/main/install.sh | sh -s -- --uninstall
```

## License

[MIT](LICENSE)
