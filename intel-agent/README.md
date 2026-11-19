# Intel brief

The six-hourly Global Threat Intercept email. Not upstream World Monitor.

It reads World Monitor through the members gate exactly as a member's browser
does, builds a reduced digest, asks Claude for a prioritized brief, and sends
it through Resend. Read-only: it writes nothing, anywhere.

## Environment

| Variable | Required | Notes |
|---|---|---|
| `MAP_SSO_SECRET` | yes | Must match the value on thesurvivalsummit.com and on the `worldmonitor` service |
| `ANTHROPIC_API_KEY` | yes | |
| `BRIEF_RECIPIENTS` | yes | Comma separated. No default: a wrong address baked into source is how a brief quietly goes to the wrong person for months |
| `RESEND_API_KEY` | yes in practice | Without it the brief is printed to the log instead of sent |
| `BRIEF_FROM` | no | Verified Resend sender |
| `WM_BASE_URL` | no | Defaults to the public map hostname |
| `ANTHROPIC_MODEL` | no | Defaults to `claude-sonnet-4-6` |
| `RUN_ONCE` | no | `1` by default: one cycle then exit, because Railway runs this on a cron. `0` restores the in-process sleep loop for local work |

## Running it once, locally

    MAP_SSO_SECRET=... ANTHROPIC_API_KEY=... BRIEF_RECIPIENTS=you@example.com python -u agent.py

Leave `RESEND_API_KEY` unset to print the brief instead of emailing it.

## When the brief goes quiet

The log says which half failed. `[fatal] gate refused the service token` means
`MAP_SSO_SECRET` has drifted from the site's value. `[digest] built, N feed(s)
empty` with a high N means the data keys are missing, not that the world is
calm; the brief says so in its own Data health section.
