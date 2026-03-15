# 0DAYS — XSS Console

> A blind XSS callback receiver, dashboard, and payload generator.
> Hosted free for everyone as a Cloudflare Worker.

**[→ Use it now: aged-cloud-b431.0days.workers.dev](https://aged-cloud-b431.0days.workers.dev/)**

---

## What is Blind XSS?

Cross-Site Scripting (XSS) is when an attacker injects JavaScript into a web page that another user's browser then executes. **Blind XSS** is a variant where you never see the execution happen directly — your payload gets stored somewhere (a support ticket, a log viewer, an admin panel) and fires later, often in a completely different application or browser session that you have no direct access to.

Because you can't observe it happening, you need an **out-of-band callback** — a URL your payload phones home to when it fires. That's what this tool is.

```
You inject a payload → Someone opens a page containing it →
Their browser executes your script → Your callback URL receives the hit →
You see their cookies, IP, URL, user-agent, and more
```

---

## Features

- **Persistent payload URLs** — your callback URL is tied to your username and never expires. Deploy a payload today, receive the callback months later with zero reconfiguration.
- **Per-account isolation** — every user gets a completely separate workspace. No data leakage between accounts.
- **Ready-made payloads** — standard fetch exfil, image beacons, CSS probes, Cloudflare WAF evasion, ModSecurity evasion, and more.
- **URL encoding toggle** — switch payloads between raw and URL-encoded with one click.
- **Full callback data** — captures IP, geolocation, cookies, user-agent, referer, request body, query params, and more.
- **Export** — download all captured callbacks as JSON.
- **No email required** — sign up with just a username and password.

---

## Hosted Instance

Publicly available, free to use, no setup required:

```
https://aged-cloud-b431.0days.workers.dev/
```

Create an account and your persistent callback base URL is immediately:

```
https://aged-cloud-b431.0days.workers.dev/x/yourusername
```

This URL is stable forever. Embed it in a payload, walk away, and check back whenever.

---

## Self-Hosting

This runs as a single Cloudflare Worker with a KV namespace. No servers, no databases, no bills.

**Requirements**
- Cloudflare account (free tier works)
- Wrangler CLI

**Setup**

```bash
# Clone
git clone https://github.com/TheEmperorsPath/0days-xss-console
cd 0days-xss-console

# Install Wrangler
npm install -g wrangler

# Create KV namespace
wrangler kv:namespace create XSS_CALLBACKS

# Add to wrangler.toml
# [[kv_namespaces]]
# binding = "XSS_CALLBACKS"
# id = "<your-namespace-id>"

# Set session secret
wrangler secret put SESSION_SECRET

# Deploy
wrangler deploy
```

---

## Payload Types

| Type | Method | Use Case |
|---|---|---|
| Full Exfil Script | `POST` fetch | Richest data, fires on DOM load |
| Image Beacon | `GET` img src | Bypasses many CSP restrictions |
| Fetch API JSON | `POST` fetch | Clean JSON body exfil |
| CSS Probe | `GET` link href | No-JS environments |
| Pixel Probe | `GET` img src | Silent, low-noise |
| Navigator Fingerprint | `POST` fetch | Full browser fingerprint |
| CF WAF Evasion | `onerror` img | Bypass Cloudflare WAF |
| ModSecurity Evasion | SVG `onload` | Bypass CRS ruleset |

---

## Security

- Passwords hashed with PBKDF2 (100,000 iterations, SHA-256)
- Sessions signed with HMAC-SHA256, 30-day expiry
- CSRF double-submit cookie pattern on all mutating endpoints
- Timing-safe comparison for password verification
- Accounts are fully isolated — users can only access their own callbacks

---

## Legal

This tool is intended for **authorized security testing, CTF competitions, bug bounty research, and educational use only**. Do not use it against systems you do not have explicit permission to test.

---

<div align="center">

**[YouTube](https://youtube.com/@0dayscyber)** · **[GitHub](https://github.com/TheEmperorsPath)**

</div>
