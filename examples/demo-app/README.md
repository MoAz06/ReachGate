# ReachGate Demo App

A minimal Flask app with two planted vulnerabilities of the same class (unsafe `yaml.load`), designed to demonstrate the ReachGate flip:

| Finding | Location | Call chain | Expected verdict |
|---|---|---|---|
| A | `utils/config_loader.py` | `app.py -> routes/orders.py -> services/parser.py -> utils/config_loader.py` | REACHABLE |
| B | `scripts/legacy/migrate.py` | none (imported by nothing) | NOT_REACHABLE |

Same scanner output, different graph context, different verdict.

## Setup

Push this directory as its own GitLab project. The included `.gitlab-ci.yml` runs GitLab SAST, which flags both `yaml.load` calls. Once Orbit indexes the project, run ReachGate against it with the included `reachgate.yml`.
