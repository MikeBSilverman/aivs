# Security policy

AIVS holds embargoed, unpatched vulnerability intelligence for an ISAC and its
members. A defect in it can expose exactly the content it exists to protect, so
reports are welcome and treated as urgent.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting**:
<https://github.com/MikeBSilverman/aivs/security/advisories/new>.

Please do not open a public issue, pull request or discussion for a
vulnerability. A private report reaches the maintainers only, and lets a fix
and an advisory be prepared before details are public.

Include what you can of: the affected component or file, the property that
fails (for example "a member can read content outside its circles"), steps or a
test that shows it, and the commit you tested against.

## What to expect

- Acknowledgement within three business days.
- An initial assessment, including whether we agree it is a vulnerability and
  how severe, within ten business days.
- Fix, advisory and credit (if you want it) coordinated with you.

## Scope

In scope: everything in this repository -- the server, schemas, client, the
deployment configuration (`docker-compose*.yml`, `deploy/`), and the CI
workflows.

Out of scope: deployments run by an ISAC on its own infrastructure. Report
those to the ISAC that runs them; we will help if they ask.

## How we look for problems ourselves

The gates in `CLAUDE.md` section 2 run on every change: type checking, lint,
bandit, semgrep, CodeQL, pip-audit against the lockfile, gitleaks over the full
history, workflow linting, and a test suite in which each security control is
tested as a pair and proven by re-applying the defect. `docs/threat-model.md`
records what the system defends against and what it does not.
