# TBH-SSTI

<p align="center">
  <a href="https://github.com/TulungagungBlackHat/TBH-SSTI/actions/workflows/ci.yml"><img src="https://github.com/TulungagungBlackHat/TBH-SSTI/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-MIT-red.svg" alt="License">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/payload-safe-green.svg" alt="Safe payloads">
</p>

Server-Side Template Injection detector. Injects a harmless arithmetic expression and checks whether the template engine evaluates it.

Part of the [Tulungagung Black Hat](https://github.com/TulungagungBlackHat) toolset.

## What It Checks

- Reflection of evaluated math payloads (`7*7` → `49`) across common template syntaxes: Jinja2/Twig/Smarty-style expressions
- Status code changes from the probe

The payload computes a number — **no OS commands, no file reads, no SSTI-to-RCE escalation**. That escalation is a manual, in-scope step if the program allows it.

## Install

```bash
git clone https://github.com/TulungagungBlackHat/TBH-SSTI
cd TBH-SSTI
pip install -r requirements.txt
```

## Usage

```
usage: ssti.py [-h] -u URL [--json JSON]

options:
  -u, --url URL     Target URL with a reflected parameter
  --json JSON       Save result as JSON
```

```bash
python3 ssti.py -u "https://example.com/render?name=test" --json result.json
```

## Sample Output

```
[*] Testing https://example.com/render?name=test
[!] SSTI: math payload evaluated (49) -> confirm engine & report
[✓] JSON: result.json
```

## Authorized Use Only

Only against scopes you own or are authorized to test. See [SECURITY.md](SECURITY.md).

## Related Tools

- [TBH-XSS](https://github.com/TulungagungBlackHat/TBH-XSS) — client-side sibling (reflection without encoding)
- [TBH-AllScan](https://github.com/TulungagungBlackHat/TBH-AllScan) — SSTI plus 9 other modules

## License

[MIT](LICENSE) — Tulungagung Black Hat, East Java, Indonesia. Always Smile :)
