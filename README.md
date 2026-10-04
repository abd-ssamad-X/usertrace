# USERTRACE (CLI Edition)

USERTRACE is a pure Python command-line utility that checks a username against a bundled catalog of **189 public profile URL patterns**. It runs HTTP checks concurrently and prints each result in the terminal as it completes. It does not start a web server, open a browser, or use localhost.

> Use only for lawful, authorized research. USERTRACE is a best-effort availability checker—not identity verification, proof of account ownership, or a guarantee that a username belongs to a particular person.

## Limitations and responsible use

- A `FOUND` result means only that the configured response rule suggests a public profile may exist. It can be a false positive (for example, a site's generic page or soft-404); **verify manually**.
- `UNCERTAIN` means the site blocked, challenged, redirected, failed, or did not provide a reliable profile signal. It is not a negative result.
- Websites change URL structures and response behavior. Catalog entries are community-maintained guesses and may become stale. Some sites require an account, JavaScript, or additional verification and cannot be checked reliably by this tool.
- USERTRACE sends unauthenticated public HTTP requests with a descriptive User-Agent, at most 10 at a time, and a 5.5-second request timeout. Respect each platform's terms, robots guidance, and rate limits. Stop if a service objects; do not use this tool to evade access controls or harass people.
- Only use usernames you are authorized to research. Do not use findings to dox, stalk, discriminate, or make consequential decisions about a person.

## Requirements

- Python 3.9 or newer
- Internet connection

## Install and run

### Windows CMD

```bat
cd path\to\usertrace
py -m pip install -r requirements.txt
py usertrace.py johndoe
```

Optional editable install (adds the `usertrace` command to your Python scripts path):

```bat
py -m pip install -e .
usertrace johndoe
```

### Windows PowerShell

```powershell
Set-Location path\to\usertrace
py -m pip install -r requirements.txt
py .\usertrace.py johndoe
```

### macOS / Linux

```sh
cd /path/to/usertrace
python3 -m pip install -r requirements.txt
python3 usertrace.py johndoe
```

Optional editable install:

```sh
python3 -m pip install -e .
usertrace johndoe
```

## Usage

```text
python usertrace.py <username> [options]
```

Examples:

```sh
python usertrace.py johndoe
python usertrace.py johndoe --found-only
python usertrace.py johndoe --category developer
python usertrace.py johndoe --export json
python usertrace.py johndoe --export csv --no-color
python usertrace.py --list-categories
```

Username validation accepts 1–30 characters: letters, digits, `.`, `_`, and `-`; the first character must be a letter or digit. This is an input-safety rule, not a guarantee that a platform allows that username.

| Option | Description |
|---|---|
| `--found-only` | During the scan, print only FOUND result lines (the progress line and final summary remain). |
| `--category NAME` | Limit the scan to one category; use `--list-categories` to see available values. |
| `--export json` | Export completed results to a timestamped JSON file in the current directory. |
| `--export csv` | Export completed results to a timestamped CSV file in the current directory. |
| `--no-color` | Disable ANSI colors (useful for logs and pipes). |
| `--list-categories` | Print available categories and exit. |
| `-h`, `--help` | Show command help. |

Exports are named `usertrace_<username>_<UTC timestamp>.json` or `.csv`. Exports include a manual-verification recommendation for each completed check. Press `Ctrl+C` to stop; completed results are summarized and exported if an export option was supplied.

## Detection and privacy notes

USERTRACE distinguishes `FOUND`, `NOT FOUND`, and `UNCERTAIN`. HTTP 429, access restrictions, server errors, anti-bot pages, and sign-in redirects are treated as uncertain. HTTP 404 and configured not-found text become not-found. Error-message platforms require an explicit positive marker; because the catalog has no confirmed positive marker for most such services, they normally report `UNCERTAIN` rather than guess. The scanner does not authenticate, submit forms, or try to bypass challenges. It sends only the requested username in public profile URLs.

## Catalog

The catalog is bundled in `data/platforms.json` for direct script use and included inside the installable package. Each entry contains a platform name, category, URL template, detection method, HTTP error code, not-found strings, optional positive strings, and a `high_difficulty` flag. The catalog count is checked by the test suite.

## Development / tests

```sh
python -m unittest discover -s tests -v
```

## License

MIT. See `LICENSE`.
