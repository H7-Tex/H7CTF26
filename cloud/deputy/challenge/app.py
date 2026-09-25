#!/usr/bin/env python3
"""
Deputy — a small, faithful simulated AWS control plane for a confused-deputy / IAM privesc chain.

Players point real `awscli --endpoint-url http://host:port` (and Pacu) at it. We speak enough of the
IAM/STS query protocol (form-in, XML-out), the Lambda REST-JSON protocol, and S3 path-style GET to
drive the intended chain and to reject the near-miss paths.

We do NOT verify SigV4 signatures (like LocalStack) — we only parse the Credential= access-key-id out
of the Authorization header to identify the caller, and the credential scope's service to route. That
is enough: players still `aws configure` real-looking keys, and temporary keys minted by AssumeRole /
Lambda behave like real session creds.

Kill chain (4 flags):
  1. recon        analyst reads its own scratch bucket                    -> FLAG1
  2. passrole     analyst has lambda:CreateFunction + iam:PassRole on
                  ci-runner-role -> create a fn AS that role, invoke it
                  (the fn hands back the role's creds) -> read runner logs -> FLAG2
  3. assume-admin ci-runner-role may sts:AssumeRole partner-admin-role,
                  which over-trusts the whole account root with NO ExternalId
                  -> admin creds -> read the flag vault -> FLAG3 (+ leaks an ExternalId)
  4. externalid   partner-secure-role trusts the account root but REQUIRES the
                  right sts:ExternalId; using the leaked id -> FLAG4
                  (assuming it without / with a wrong ExternalId is denied)
"""
import datetime
import json
import os
import secrets
import time
from urllib.parse import parse_qs, unquote
from fnmatch import fnmatch

from flask import Flask, request, Response

app = Flask(__name__)

ACCOUNT = "111111111111"
PARTNER_ACCOUNT = "999999999999"
ARNP = f"arn:aws:iam::{ACCOUNT}"

FLAG1 = os.environ.get("FLAG1", "H7CTF{recon_the_sim_aws_analyst}")
FLAG2 = os.environ.get("FLAG2", "H7CTF{passrole_lambda_stole_the_runner_role}")
FLAG3 = os.environ.get("FLAG3", "H7CTF{confused_deputy_no_externalid_is_admin}")
FLAG4 = os.environ.get("FLAG4", "H7CTF{externalid_gates_the_real_crown_jewel}")
EXTERNAL_ID = os.environ.get("PARTNER_EXTERNAL_ID", "Dc-2026-8f31a97c4b2e")

# ---- seed identities ---------------------------------------------------------
# Long-term keys players are handed for the starting identity.
ANALYST_AK = os.environ.get("ANALYST_ACCESS_KEY", "AKIAANALYST0000000000")
ANALYST_SK = os.environ.get("ANALYST_SECRET_KEY", "wJalrAnalystSecretKeyEXAMPLEbPxRfiCY")

USERS = {
    ANALYST_AK: {
        "type": "user", "name": "analyst",
        "arn": f"{ARNP}:user/analyst",
        "statements": [
            {"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": ["*"]},
            {"Effect": "Allow", "Action": ["iam:Get*", "iam:List*"], "Resource": ["*"]},
            {"Effect": "Allow",
             "Action": ["lambda:CreateFunction", "lambda:InvokeFunction", "lambda:GetFunction",
                        "lambda:ListFunctions"],
             "Resource": ["*"]},
            {"Effect": "Allow", "Action": ["iam:PassRole"],
             "Resource": [f"{ARNP}:role/ci-runner-role"]},
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
             "Resource": ["arn:aws:s3:::deputy-analyst-scratch",
                          "arn:aws:s3:::deputy-analyst-scratch/*"]},
        ],
    },
}

# Roles: trust doc (who can assume) + permission statements.
ROLES = {
    "ci-runner-role": {
        "arn": f"{ARNP}:role/ci-runner-role",
        "trust": {"Service": "lambda.amazonaws.com"},   # assumed by the lambda service (via invoke)
        "statements": [
            {"Effect": "Allow", "Action": ["sts:AssumeRole"],
             "Resource": [f"{ARNP}:role/partner-admin-role"]},
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
             "Resource": ["arn:aws:s3:::deputy-runner-logs",
                          "arn:aws:s3:::deputy-runner-logs/*"]},
            {"Effect": "Allow", "Action": ["logs:*"], "Resource": ["*"]},
        ],
    },
    # VULNERABLE: trusts the whole account root with NO ExternalId condition (confused deputy).
    "partner-admin-role": {
        "arn": f"{ARNP}:role/partner-admin-role",
        "trust": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},   # <-- no Condition/ExternalId
        "statements": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
             "Resource": ["arn:aws:s3:::deputy-flag-vault", "arn:aws:s3:::deputy-flag-vault/*"]},
            {"Effect": "Allow", "Action": ["sts:AssumeRole"],
             "Resource": [f"{ARNP}:role/partner-secure-role"]},
        ],
    },
    # SECURE (near-miss): trusts the account root but REQUIRES the right sts:ExternalId.
    "partner-secure-role": {
        "arn": f"{ARNP}:role/partner-secure-role",
        "trust": {"AWS": f"arn:aws:iam::{ACCOUNT}:root",
                  "Condition": {"StringEquals": {"sts:ExternalId": EXTERNAL_ID}}},
        "statements": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
             "Resource": ["arn:aws:s3:::deputy-crown-vault", "arn:aws:s3:::deputy-crown-vault/*"]},
        ],
    },
}

# S3 objects: bucket -> key -> content
S3 = {
    "deputy-analyst-scratch": {
        "welcome.txt": (
            "Welcome, analyst. Onboarding note:\n"
            f"{FLAG1}\n"
            "Our CI runs deploys through a Lambda that assumes ci-runner-role.\n"
            "You have permission to create+invoke functions.\n"
        ),
    },
    "deputy-runner-logs": {
        "build.log": f"[ci-runner-role] nightly build ok\ninternal marker: {FLAG2}\n",
    },
    "deputy-flag-vault": {
        "flag": f"{FLAG3}\n",
        "partner-config.json": json.dumps(
            {"partner": "DeputyCorp", "secure_role": f"{ARNP}:role/partner-secure-role",
             "external_id": EXTERNAL_ID,
             "note": "partner-secure-role is our HARDENED role — it requires this ExternalId."},
            indent=2),
    },
    "deputy-crown-vault": {
        "flag": f"{FLAG4}\n",
    },
}

LAMBDAS = {}     # name -> {role_arn}
SESSIONS = {}    # temp access-key-id -> {"role": name, "arn": ..., "exp": ts}


# ---- helpers -----------------------------------------------------------------
def now_iso(plus=3600):
    return datetime.datetime.utcfromtimestamp(time.time() + plus).strftime("%Y-%m-%dT%H:%M:%SZ")


def caller_from_auth():
    """Return (principal_dict, access_key_id) or (None, akid). Principal has type/name/arn/statements."""
    auth = request.headers.get("Authorization", "")
    akid = None
    if "Credential=" in auth:
        try:
            akid = auth.split("Credential=", 1)[1].split("/", 1)[0]
        except Exception:
            akid = None
    if not akid:
        # awscli always signs; but allow X-Ak header as a fallback for curl testing
        akid = request.headers.get("X-Ak")
    if akid in USERS:
        return USERS[akid], akid
    if akid in SESSIONS:
        s = SESSIONS[akid]
        role = ROLES[s["role"]]
        return {"type": "assumed-role", "name": s["role"], "arn": s["arn"],
                "statements": role["statements"]}, akid
    return None, akid


def allowed(principal, action, resource, ctx=None):
    ctx = ctx or {}
    stmts = principal.get("statements", [])
    decision = False
    for st in stmts:
        acts = st.get("Action", [])
        if not any(fnmatch(action, a) for a in acts):
            continue
        res = st.get("Resource", ["*"])
        if not any(r == "*" or fnmatch(resource, r) for r in res):
            continue
        if st.get("Effect") == "Deny":
            return False
        decision = True
    return decision


# ---- XML helpers -------------------------------------------------------------
def xml(body, code=200):
    return Response(body, status=code, content_type="text/xml")


def rid():
    return secrets.token_hex(8)


def err_query(code, msg, http=403, kind="Sender"):
    return xml(f'<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
               f'<Error><Type>{kind}</Type><Code>{code}</Code><Message>{msg}</Message></Error>'
               f'<RequestId>{rid()}</RequestId></ErrorResponse>', http)


def mint_session(role_name):
    akid = "ASIA" + secrets.token_hex(8).upper()
    SESSIONS[akid] = {"role": role_name, "arn": ROLES[role_name]["arn"], "exp": time.time() + 3600}
    return akid, "sk/" + secrets.token_urlsafe(24), "tok/" + secrets.token_urlsafe(48)


# ---- service detection + dispatch --------------------------------------------
def service_from_auth():
    auth = request.headers.get("Authorization", "")
    if "Credential=" in auth:
        parts = auth.split("Credential=", 1)[1].split(",", 1)[0].split("/")
        if len(parts) >= 5:
            return parts[3]   # akid/date/region/SERVICE/aws4_request
    return None


@app.route("/", methods=["POST", "GET"])
def root():
    svc = service_from_auth()
    body = request.get_data(as_text=True)
    params = {k: v[0] for k, v in parse_qs(body).items()}
    action = params.get("Action")
    if svc == "sts" or action in ("GetCallerIdentity", "AssumeRole"):
        return sts_dispatch(action, params)
    if svc == "iam" or (action and action.startswith(("Get", "List"))):
        return iam_dispatch(action, params)
    return err_query("InvalidAction", f"unsupported action {action}", 400)


# ---- STS ---------------------------------------------------------------------
def sts_dispatch(action, params):
    principal, akid = caller_from_auth()
    if action == "GetCallerIdentity":
        if not principal:
            return err_query("InvalidClientTokenId", "unknown access key", 403)
        return xml(
            f'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
            f'<GetCallerIdentityResult><Arn>{principal["arn"]}</Arn>'
            f'<UserId>AIDA{principal["name"].upper()}</UserId><Account>{ACCOUNT}</Account>'
            f'</GetCallerIdentityResult><ResponseMetadata><RequestId>{rid()}</RequestId>'
            f'</ResponseMetadata></GetCallerIdentityResponse>')
    if action == "AssumeRole":
        if not principal:
            return err_query("InvalidClientTokenId", "unknown access key", 403)
        role_arn = params.get("RoleArn", "")
        role_name = role_arn.rsplit("/", 1)[-1]
        role = ROLES.get(role_name)
        if not role:
            return err_query("NoSuchEntity", f"role {role_name} not found", 404)
        # 1) does the caller's identity policy allow sts:AssumeRole on this role?
        if not allowed(principal, "sts:AssumeRole", role_arn):
            return err_query("AccessDenied",
                             f'{principal["arn"]} is not authorized to perform sts:AssumeRole on {role_arn}')
        # 2) does the role's TRUST policy allow this principal (+ ExternalId condition)?
        ok, why = trust_allows(role, principal, params.get("ExternalId"))
        if not ok:
            return err_query("AccessDenied", why)
        ak, sk, tok = mint_session(role_name)
        arn = f"arn:aws:sts::{ACCOUNT}:assumed-role/{role_name}/sess"
        return xml(
            f'<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>'
            f'<Credentials><AccessKeyId>{ak}</AccessKeyId><SecretAccessKey>{sk}</SecretAccessKey>'
            f'<SessionToken>{tok}</SessionToken><Expiration>{now_iso()}</Expiration></Credentials>'
            f'<AssumedRoleUser><Arn>{arn}</Arn><AssumedRoleId>AROA{role_name.upper()}:sess</AssumedRoleId>'
            f'</AssumedRoleUser></AssumeRoleResult><ResponseMetadata><RequestId>{rid()}</RequestId>'
            f'</ResponseMetadata></AssumeRoleResponse>')
    return err_query("InvalidAction", f"unsupported sts action {action}", 400)


def trust_allows(role, principal, external_id):
    trust = role["trust"]
    # service-trust roles are assumed only via the lambda path, not sts:AssumeRole
    if "Service" in trust:
        return False, "role can only be assumed by a service"
    aws = trust.get("AWS", "")
    if aws != f"arn:aws:iam::{ACCOUNT}:root":
        return False, "principal not trusted by role"
    cond = trust.get("Condition", {})
    req = cond.get("StringEquals", {}).get("sts:ExternalId")
    if req is not None:
        if external_id != req:
            return False, ("trust policy requires a matching sts:ExternalId"
                           if external_id else
                           "trust policy requires sts:ExternalId; none provided")
    return True, "ok"


# ---- IAM ---------------------------------------------------------------------
def iam_dispatch(action, params):
    principal, akid = caller_from_auth()
    if not principal:
        return err_query("InvalidClientTokenId", "unknown access key", 403)
    res = "*"
    if not allowed(principal, f"iam:{action}", res):
        return err_query("AccessDenied",
                         f'{principal["arn"]} is not authorized to perform iam:{action}')
    if action == "ListRoles":
        items = "".join(
            f'<member><RoleName>{n}</RoleName><Arn>{r["arn"]}</Arn><RoleId>AROA{n.upper()}</RoleId>'
            f'<Path>/</Path><AssumeRolePolicyDocument>{escape(json.dumps(trust_doc(r)))}'
            f'</AssumeRolePolicyDocument></member>'
            for n, r in ROLES.items())
        return xml(
            f'<ListRolesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListRolesResult>'
            f'<Roles>{items}</Roles><IsTruncated>false</IsTruncated></ListRolesResult>'
            f'<ResponseMetadata><RequestId>{rid()}</RequestId></ResponseMetadata></ListRolesResponse>')
    if action == "GetRole":
        n = params.get("RoleName", "")
        r = ROLES.get(n)
        if not r:
            return err_query("NoSuchEntity", f"role {n} not found", 404)
        return xml(
            f'<GetRoleResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GetRoleResult>'
            f'<Role><RoleName>{n}</RoleName><Arn>{r["arn"]}</Arn><RoleId>AROA{n.upper()}</RoleId>'
            f'<Path>/</Path><AssumeRolePolicyDocument>{escape(json.dumps(trust_doc(r)))}'
            f'</AssumeRolePolicyDocument></Role></GetRoleResult><ResponseMetadata>'
            f'<RequestId>{rid()}</RequestId></ResponseMetadata></GetRoleResponse>')
    if action == "ListAttachedUserPolicies":
        return xml(
            f'<ListAttachedUserPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
            f'<ListAttachedUserPoliciesResult><AttachedPolicies>'
            f'<member><PolicyName>AnalystInline</PolicyName>'
            f'<PolicyArn>{ARNP}:policy/AnalystInline</PolicyArn></member>'
            f'</AttachedPolicies><IsTruncated>false</IsTruncated></ListAttachedUserPoliciesResult>'
            f'<ResponseMetadata><RequestId>{rid()}</RequestId></ResponseMetadata>'
            f'</ListAttachedUserPoliciesResponse>')
    if action == "GetUser":
        return xml(
            f'<GetUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GetUserResult>'
            f'<User><UserName>{principal.get("name","analyst")}</UserName>'
            f'<Arn>{principal["arn"]}</Arn><UserId>AIDAANALYST</UserId><Path>/</Path></User>'
            f'</GetUserResult><ResponseMetadata><RequestId>{rid()}</RequestId></ResponseMetadata>'
            f'</GetUserResponse>')
    # generic empty-ish OK for other Get*/List* so enumeration doesn't hard-fail
    return xml(f'<{action}Response xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
               f'<{action}Result/><ResponseMetadata><RequestId>{rid()}</RequestId>'
               f'</ResponseMetadata></{action}Response>')


def trust_doc(role):
    t = role["trust"]
    if "Service" in t:
        princ = {"Service": t["Service"]}
    else:
        princ = {"AWS": t["AWS"]}
    stmt = {"Effect": "Allow", "Principal": princ, "Action": "sts:AssumeRole"}
    if "Condition" in t:
        stmt["Condition"] = t["Condition"]
    return {"Version": "2012-10-17", "Statement": [stmt]}


def escape(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


# ---- Lambda (REST-JSON) ------------------------------------------------------
@app.route("/2015-03-31/functions", methods=["POST"])
def lambda_create():
    principal, _ = caller_from_auth()
    if not principal:
        return jsonerr("UnrecognizedClientException", "unknown access key", 403)
    body = request.get_json(force=True, silent=True) or {}
    name = body.get("FunctionName", "fn")
    role_arn = body.get("Role", "")
    if not allowed(principal, "lambda:CreateFunction", "*"):
        return jsonerr("AccessDeniedException", "not authorized: lambda:CreateFunction")
    # the PassRole control: you can only set a role you may iam:PassRole
    if not allowed(principal, "iam:PassRole", role_arn):
        return jsonerr("AccessDeniedException",
                       f"not authorized to iam:PassRole on {role_arn}")
    role_name = role_arn.rsplit("/", 1)[-1]
    if role_name not in ROLES:
        return jsonerr("InvalidParameterValueException", f"role {role_name} not found", 400)
    LAMBDAS[name] = {"role": role_name, "arn": role_arn}
    return Response(json.dumps({"FunctionName": name, "Role": role_arn,
                                "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{name}",
                                "State": "Active"}),
                    status=201, content_type="application/json")


@app.route("/2015-03-31/functions/<name>/invocations", methods=["POST"])
def lambda_invoke(name):
    principal, _ = caller_from_auth()
    if not principal:
        return jsonerr("UnrecognizedClientException", "unknown access key", 403)
    if not allowed(principal, "lambda:InvokeFunction", "*"):
        return jsonerr("AccessDeniedException", "not authorized: lambda:InvokeFunction")
    fn = LAMBDAS.get(name)
    if not fn:
        return jsonerr("ResourceNotFoundException", f"function {name} not found", 404)
    # model code-exec inside the function: it can read its execution role's credentials
    ak, sk, tok = mint_session(fn["role"])
    payload = {
        "message": "function executed; environment credentials for the execution role follow",
        "AWS_ACCESS_KEY_ID": ak, "AWS_SECRET_ACCESS_KEY": sk, "AWS_SESSION_TOKEN": tok,
        "role": ROLES[fn["role"]]["arn"],
        "hint": "configure these as a profile; this role can sts:AssumeRole partner-admin-role",
    }
    return Response(json.dumps(payload), status=200, content_type="application/json")


@app.route("/2015-03-31/functions", methods=["GET"])
def lambda_list():
    return Response(json.dumps({"Functions": [
        {"FunctionName": n, "Role": f["arn"]} for n, f in LAMBDAS.items()]}),
        content_type="application/json")


def jsonerr(code, msg, http=403):
    return Response(json.dumps({"__type": code, "message": msg}), status=http,
                    content_type="application/json",
                    headers={"x-amzn-ErrorType": code})


# ---- S3 (path-style GET) -----------------------------------------------------
@app.route("/<bucket>", methods=["GET"])
@app.route("/<bucket>/<path:key>", methods=["GET"])
def s3_get(bucket, key=None):
    principal, _ = caller_from_auth()
    if not principal:
        return s3err("InvalidAccessKeyId", "unknown access key", 403)
    if bucket not in S3:
        return s3err("NoSuchBucket", f"no such bucket {bucket}", 404)
    if key is None:
        # ListBucket
        if not allowed(principal, "s3:ListBucket", f"arn:aws:s3:::{bucket}"):
            return s3err("AccessDenied", "not authorized: s3:ListBucket")
        contents = "".join(f"<Contents><Key>{k}</Key></Contents>" for k in S3[bucket])
        return xml(f'<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                   f'<Name>{bucket}</Name>{contents}</ListBucketResult>')
    key = unquote(key)
    if not allowed(principal, "s3:GetObject", f"arn:aws:s3:::{bucket}/{key}"):
        return s3err("AccessDenied", f"not authorized: s3:GetObject on {bucket}/{key}")
    if key not in S3[bucket]:
        return s3err("NoSuchKey", f"no such key {key}", 404)
    return Response(S3[bucket][key], status=200, content_type="text/plain")


def s3err(code, msg, http=403):
    return Response(f'<?xml version="1.0"?><Error><Code>{code}</Code><Message>{msg}</Message></Error>',
                    status=http, content_type="application/xml")


@app.route("/_health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), threaded=True)
