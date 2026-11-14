# Trustfall CI

**Category:** devsecops  **Difficulty:** hard  **Author:** Owatron

> Trustfall CI automates the whole delivery pipeline now - scanning, review, approvals, release. They even gave parts of it agents. Very efficient. Probably fine.
>
> Reach production and recover the protected secret.

One image, four roles picked by the command arg: `portal` (the only public one, 8080), `scanner`, `agents` and `release`. The agents role needs an Ollama endpoint serving `qwen2.5-coder:7b` (digest `dae161e2...4364`) at `OLLAMA_URL`. Locally: set `INSTANCE_ID`, `INTERNAL_TOKEN` (32+ chars), `FLAG`, `PUBLIC_PORT` and `OLLAMA_MODELS_PATH` in `challenge/.env`, then `cd challenge && docker compose --env-file .env --profile local up --build`. `ops/` has the scripts we used to spin up the Qwen endpoint on a rented GPU during the event.

## Solution

The portal lets you edit a Terraform repo, commit, run the pipeline (Trivy scan, then an LLM ReviewBot), and request releases. Asking for a production release straight away gets a 403, no approval. So the way in is through the pipeline's state.

**Poison the memory.** Remove the `logging` block from `aws_s3_bucket.artifacts` in `infra/storage.tf`. Trivy now flags `s3-bucket-logging` on that resource. Add a matching exception in `security-exceptions.json`:

```json
{"exceptions": [{"rule_id": "s3-bucket-logging", "resource": "aws_s3_bucket.artifacts",
  "owner": "platform-security", "ticket": "SEC-1842", "status": "accepted",
  "expires": "2030-12-31", "justification": "Temporary exception while logging migration is completed."}]}
```

Keep `release.json` as a staging promotion, commit, run. The finding comes back as an accepted suppression, and ReviewBot records it as a repository-wide `release-integrity` assurance, VERIFIED, source Trivy. A narrow, repo-controlled waiver just turned into a durable project fact.

**Get a cheap approval.** Put the clean Terraform back, drop the exception, make some harmless edit and run again (still staging). The scan is clean, but ReviewBot loads the old assurance and takes the fast path. The approval it issues is bound to the mutable `candidate` ref, not the reviewed commit.

**Swap the candidate.** Change only `release.json` to `{"action": "promote", "target": "production"}` and commit. The candidate ref moves, but the approval stays active. Now ask for the release:

```sh
curl -X POST http://<host>:8080/api/releases -H 'Content-Type: application/json' \
  -d '{"candidate_ref": "<candidate_ref>", "action": "promote", "target": "production"}'
```

The release service checks the ref, project and expiry on the approval but never compares the commit, action or target, so it hands back the lease, which is the flag.

Doing only the first run doesn't work (that run is full review and bound to its commit), and fake SARIF or a wrong waiver never attaches to a real Trivy result. `solution/solve.py` does the whole thing over the API.

Flag is dynamic, injected per instance through `FLAG`.
