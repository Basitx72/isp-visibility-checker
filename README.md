# ISP Visibility Checker

A small app that runs on your own computer and answers two questions:

- **On the internet:** what can my internet provider (ISP) see of my traffic right now?
- **At home:** what does my router answer to on my own network?

![The app window, showing sample data](docs/screenshot.png)

The picture shows sample data, not a real network.

## What it checks

**On the internet.** These tests run in your browser.

| Check | What it answers |
| --- | --- |
| Address websites see | Do sites see you, or a VPN server? |
| Site name lookups (DNS) | Who looks up site names for you? Whoever does it can list the sites you open. |
| Second route (IPv6) | Does IPv6 traffic go around the VPN? |
| Browser calls (WebRTC) | Can calls and video chats reveal your address? |

The answer is one word:

- **Hidden**: websites see a VPN address, and nothing leaks past the VPN.
- **Partly visible**: the VPN is on, but DNS, IPv6 or WebRTC leaks past it.
- **Visible**: there is no VPN, so your provider can see which sites you visit.

**At home.** This part is done by `scanner.js`.

| Check | What it does |
| --- | --- |
| Ports 22, 23, 80 and 7547 | Connects to your router and closes again. It sends no data. |
| UPnP | Reads whether it is on and which port mappings exist. It changes nothing. |
| Wi-Fi | Reads the security mode and how crowded the channel is, as your system reports them. |
| DNS | Uses your own answer: encrypted, not encrypted, or unknown. |

The router scan gives a provisional score, says how much evidence the score rests on, and compares each scan with the one before.

## Run it

You need [Node.js](https://nodejs.org). The project was written for Node 26. On another version, npm prints a warning.

```
git clone https://github.com/Basitx72/isp-visibility-checker.git
cd isp-visibility-checker
npm install
node app.js
```

The terminal prints the app's address, usually `http://localhost:4747`. On macOS the app opens in your browser by itself. On other systems, open that address yourself. Keep the terminal window open while you use the app, and press Control-C to stop it.

Scan the router with your VPN off. With a VPN on, your computer's default gateway is the VPN, not your router.

Other ways to use it:

- Open `ISP Visibility Checker.html` directly to run only the internet tests.
- Run `node scanner.js --dns unknown` for the router scan in the terminal.
- Run `node watch.js` to repeat the scan every 30 minutes and hear about it only when something changes.

## Safety rules

- It looks only at the private default gateway of the computer it runs on. There is no way to give it another target.
- Port checks connect and close. UPnP is read-only.
- It never tests, or claims to know, what the internet can reach. A port that answers is "open on your home network". Missing evidence is reported as "Unknown".
- The app's server listens on your own computer only, and answers only its own window.
- The full rules are in `CLAUDE.md`.

## Privacy

- The router scan saves two files, `sanitized-report.json` and `previous-sanitized-report.json`. They hold no network names, hardware addresses, device names or complete private addresses. Git ignores both.
- The internet tests save nothing. They ask public services which address they see: ipquery.io, ipwho.is, geojs.io, Cloudflare, ipify.org, icanhazip.com, ip-api.com and ipleak.net, plus call servers at Cloudflare, Twilio, Google and Sipnet. Each one sees what any website would see.
- The window shows your own addresses. Hide them before you share a screenshot, and don't paste "Copy report" text in public.

## Limits

- The internet tests cover this browser at this moment. They can't test a VPN's kill switch or other apps.
- The router scan sees your router from inside your network only. The score is a learning guide, not a certificate.
- It was built and used on macOS. Other systems are untested.

## About

This started as a NextWork project and was built with Claude, Anthropic's AI assistant.
