# GitLab CI Setup

Add ReachGate to your project as an **advisory** merge-request triage job. It
runs on every MR, walks the live GitLab Orbit graph for each finding, and posts
a deterministic, fingerprint-idempotent reachability receipt. It is non-blocking
by default (`allow_failure: true`), so it never blocks a merge on its own.

This is the **live** workflow (it needs a token and network). To verify the
captured evidence offline afterwards, use `reachgate verify` / `python
tools/verify_proof.py`.

## Prerequisites

1. A GitLab project whose code is indexed by **GitLab Orbit**.
2. A **`GITLAB_TOKEN`** CI/CD variable with `api` scope, **masked** (and
   ideally **protected**). Create it under
   *Settings → CI/CD → Variables*.
3. A `reachgate.yml` in your repo declaring your attack surface (entry points).
   ReachGate never guesses what is externally reachable — you declare the
   boundary.

```yaml
# reachgate.yml
version: "1"
entrypoints:
  files:
    - "src/routes/**/*"
    - "app/controllers/**/*"
    - "cmd/**/main.*"
```

Validate it before you trust any verdict:

```bash
export GITLAB_TOKEN="glpat-xxxxx"
python tools/reachgate_doctor.py --config reachgate.yml
```

A glob matching **zero** indexed files is the most dangerous failure mode (it
makes everything look `NOT_REACHABLE`). The doctor catches exactly that.

## Option A — copy the job into your `.gitlab-ci.yml`

```yaml
stages:
  - security-triage

# Runs automatically on every merge request.
# Requires GITLAB_TOKEN set as a masked CI/CD variable (api scope).
reachgate-triage:
  stage: security-triage
  image: python:3.11-slim
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
  variables:
    GITLAB_URL: "https://gitlab.com"
    GITLAB_PROJECT_ID: $CI_PROJECT_ID
    GITLAB_MR_IID: $CI_MERGE_REQUEST_IID
  before_script:
    - pip install --quiet httpx pyyaml
  script:
    - python tools/mr_triage.py
  artifacts:
    paths:
      - reachgate-receipts.json
    when: always
    expire_in: 30 days
  allow_failure: true
```

This uploads `reachgate-receipts.json` — the machine-readable artifact with
every verdict, basis, fingerprint, and full reachability certificate — on every
run, so verdicts can be diffed, audited, and replayed outside GitLab.

## Option B — include this project's CI file

```yaml
# .gitlab-ci.yml
include:
  - project: 'gitlab-ai-hackathon/transcend/39037247'
    file: '.gitlab-ci.yml'
    ref: main
```

## Option C — drop-in template (just the triage job)

A standalone, copy-paste template with only the advisory triage job lives at
`templates/gitlab/reachgate.yml`:

```yaml
# .gitlab-ci.yml
include:
  - local: templates/gitlab/reachgate.yml
```

Or include it straight from this project:

```yaml
include:
  - project: 'gitlab-ai-hackathon/transcend/39037247'
    file: 'templates/gitlab/reachgate.yml'
    ref: main
```

> **Important — the template needs ReachGate's tooling in the running repo.**
> `include` only pulls the *YAML*; the job still runs `python tools/mr_triage.py`
> in **your** project's checkout. A bare `include` does **not** magically make
> `tools/mr_triage.py` appear. So you must make ReachGate available in the job,
> one of:
>
> - **Vendor it:** copy ReachGate's `tools/` and `src/reachgate/` (plus
>   `reachgate.yml`) into your repo, so `python tools/mr_triage.py` resolves.
> - **Install it:** `pip install` ReachGate in `before_script` (e.g. from a Git
>   URL or an internal package index) and adjust the `script:` to call the
>   installed entry point instead of `python tools/mr_triage.py`.
> - **Fork/submodule:** run the job from a checkout that already contains
>   ReachGate's `tools/`.
>
> Options A and B above are self-contained because the job runs inside this
> project's own repository, where `tools/` exists. Option C is the portable
> form and carries this requirement.

## Bring your own findings

By default the demo path uses two live GitLab docs-site findings. For a
project-owned run, point the job at a GitLab SAST report or a native findings
JSON:

```yaml
  variables:
    REACHGATE_FINDINGS_FILE: "gl-sast-report.json"
    REACHGATE_CONFIG: "reachgate.yml"
```

In that mode ReachGate loads the attack surface from `reachgate.yml` (or
`REACHGATE_CONFIG`) instead of demo entry-point discovery.

## Make it a blocking gate (optional)

The receipts are gate-ready evidence. Turn a receipt diff into a blocking check
only when you choose to enforce it:

```bash
python tools/diff_receipts.py OLD.json NEW.json --fail-on-new-reachable
```

This exits non-zero only when a finding **became** `REACHABLE` (a new reachable
finding, or a changed finding whose new verdict is `REACHABLE`). `UNKNOWN` and
`NOT_REACHABLE` never count as reachable.

## After the run: verify offline

The CI job is the live half. Anyone can verify the captured evidence offline,
standard library only, no token, no network:

```bash
reachgate verify          # or: python tools/verify_proof.py
reachgate coverage        # verdict + UNKNOWN-reason + blind-spot report
```

## Notes and limits

- `NOT_REACHABLE` is scoped to the **configured search bounds** recorded in the
  certificate — it is not a global safety claim.
- The MR CI path is **comment-only** and fingerprint-idempotent: reruns update
  in place and never duplicate comments; it creates no work items.
- This is advisory by default. Treat it as evidence to review, not a certified
  gate.
