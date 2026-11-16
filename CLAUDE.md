# Project rules

## Safety rules

These rules come first. If a rule further down conflicts with them, these win.

Project safety rules: inspect only the private default gateway detected by the operating system; never add a target, host, CIDR, public-IP, banner-grabbing, credential, brute-force, exploit, or remote-login option; TCP checks may only connect and immediately close without sending application data; UPnP code may call only getGateway() and getMappings(); never call mapping creation, deletion, external-IP, connection-control, or router-configuration methods; never print or save SSIDs, BSSIDs, MAC addresses, device names, raw UPnP descriptions, or complete private IP addresses; save only sanitized-report.json and previous-sanitized-report.json; never label a locally reachable router port as internet-exposed; return Unknown when evidence is incomplete.

## Research-First Gate (MANDATORY)

Always inspect the workspace (`git status`, `git diff`, file tree) before modifying code. Before building any new tool or feature from scratch, ALWAYS search GitHub/npm/PyPI/web for existing open-source solutions first, present a comparison table (`Existing Open-Source Tool | License | What It Already Covers | What Our Project Uniquely Adds`), and ask for confirmation before writing code if an existing open-source repo already solves 80%+ of the problem.

## Connected Stack & UI Standards

- *UI Components:* Query the `@react-bits` registry via the `shadcn` MCP server instead of hand-coding complex backgrounds, text animations, or shaders.
- *Animations:* Use the `/motion` skill and Motion MCP (`motion-ai`) for spring physics, scroll triggers, and layout transitions. Always respect `prefers-reduced-motion` and avoid layout-thrashing properties.
- *AI / Fine-Tuning Tooling:* Use the connected Unsloth skill/tooling whenever the project involves model fine-tuning, LoRA/QLoRA optimization, or local GGUF model integration.

## SEO & Discoverability Defaults

Every public page/route must include semantic HTML5 (`<main>`, `<article>`, `<header>`, `<nav>`), proper `<h1>`–`<h3>` hierarchy, descriptive `<title>` (50–60 chars), meta description (140–160 chars), Open Graph / Twitter cards, canonical URLs, `robots.txt`, `sitemap.xml`, and JSON-LD structured data (`SoftwareApplication` or `WebApplication`).
