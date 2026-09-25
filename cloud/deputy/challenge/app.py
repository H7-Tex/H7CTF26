#!/usr/bin/env python3
"""
Deputy — a small, faithful simulated AWS control plane for a cross-account trust / IAM privesc chain.

Players point real `awscli --endpoint-url http://host:port` (and Pacu) at it. We speak enough of the
IAM/STS query protocol (form-in, XML-out), the Lambda REST-JSON protocol, and S3 path-style GET/list to
drive the intended chain and to reject the near-miss paths.

We do NOT verify SigV4 signatures (like LocalStack) — we only parse the Credential= access-key-id out
of the Authorization header to identify the caller, and the credential scope's service to route. This
is an explicitly isolated per-team emulator, not an auth boundary; the secret/signature are irrelevant.

Two accounts:
  111111111111  "ours"     — analyst (start) + ci-runner-role
  999999999999  "DeputyCorp" (the partner) — partner-admin-role + partner-secure-role
The analyst's own-account IAM enumeration cannot see the partner account's roles (as in real AWS), so
the ExternalId that gates the crown role is NOT discoverable at recon — only via the stage-3 loot.

Kill chain (4 flags):
  1. recon        list buckets -> read own scratch bucket; read own inline policy               -> FLAG1
  2. passrole     analyst may lambda:CreateFunction + iam:PassRole ONLY ci-runner-role; create a
                  function as that role + invoke it (the fn returns the role's creds); the runner's
                  role policy reveals it may assume the partner's admin role -> read runner logs   -> FLAG2
  3. crossacct    ci-runner-role assumes partner-admin-role (999), which over-trusts OUR account
                  root with NO ExternalId -> admin -> read the partner flag vault (+ leaked
                  ExternalId + the secure role's arn)                                              -> FLAG3
  4. externalid   assume partner-secure-role (999) WITH the leaked ExternalId (without/ wrong = denied) -> FLAG4
"""
import datetime
import json
import os
import secrets
import threading
import time
from urllib.parse import parse_qs, quote, unquote
from fnmatch import fnmatch

from flask import Flask, request, Response

app = Flask(__name__)

ACCOUNT = "111111111111"
PARTNER = "999999999999"

FLAG1 = os.environ.get("FLAG1", "H7CTF{recon_the_sim_aws_analyst}")
FLAG2 = os.environ.get("FLAG2", "H7CTF{passrole_lambda_stole_the_runner_role}")
FLAG3 = os.environ.get("FLAG3", "H7CTF{cross_account_overtrust_no_externalid_is_admin}")
FLAG4 = os.environ.get("FLAG4", "H7CTF{externalid_gates_the_real_crown_jewel}")
EXTERNAL_ID = os.environ.get("PARTNER_EXTERNAL_ID", "Dc-2026-8f31a97c4b2e")

ANALYST_AK = os.environ.get("ANALYST_ACCESS_KEY", "AKIAANALYST0000000000")

USERS = {
    ANALYST_AK: {
        "type": "user", "name": "analyst", "account": ACCOUNT,
        "arn": f"arn:aws:iam::{ACCOUNT}:user/analyst",
        "inline": "analyst-permissions",
        "statements": [
            {"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["iam:Get*", "iam:List*"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["s3:ListAllMyBuckets"], "Resource": "*"},
            {"Effect": "Allow",
             "Action": ["lambda:CreateFunction", "lambda:InvokeFunction", "lambda:GetFunction",
                        "lambda:ListFunctions"],
             "Resource": "*"},
            {"Effect": "Allow", "Action": ["iam:PassRole"],
             "Resource": f"arn:aws:iam::{ACCOUNT}:role/ci-runner-role"},
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
             "Resource": ["arn:aws:s3:::deputy-analyst-scratch",
                          "arn:aws:s3:::deputy-analyst-scratch/*"]},
        ],
    },
}

ROLES = {
    "ci-runner-role": {
        "account": ACCOUNT, "arn": f"arn:aws:iam::{ACCOUNT}:role/ci-runner-role",
        "inline": "ci-runner-permissions",
        "trust": {"Service": "lambda.amazonaws.com"},
        "statements": [
            {"Effect": "Allow", "Action": ["sts:AssumeRole"],
             "Resource": f"arn:aws:iam::{PARTNER}:role/partner-admin-role"},
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
             "Resource": ["arn:aws:s3:::deputy-runner-logs", "arn:aws:s3:::deputy-runner-logs/*"]},
            {"Effect": "Allow", "Action": ["logs:*"], "Resource": "*"},
        ],
    },
    # VULNERABLE: the partner's role over-trusts OUR whole account root with NO ExternalId condition.
    "partner-admin-role": {
        "account": PARTNER, "arn": f"arn:aws:iam::{PARTNER}:role/partner-admin-role",
        "inline": "partner-admin-permissions",
        "trust": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},   # <-- no Condition/ExternalId
        "statements": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
             "Resource": ["arn:aws:s3:::deputy-flag-vault", "arn:aws:s3:::deputy-flag-vault/*"]},
            {"Effect": "Allow", "Action": ["sts:AssumeRole"],
             "Resource": f"arn:aws:iam::{PARTNER}:role/partner-secure-role"},
        ],
    },
    # SECURE (near-miss): trusts the partner account root but REQUIRES the right sts:ExternalId.
    "partner-secure-role": {
        "account": PARTNER, "arn": f"arn:aws:iam::{PARTNER}:role/partner-secure-role",
        "inline": "partner-secure-permissions",
        "trust": {"AWS": f"arn:aws:iam::{PARTNER}:root",
                  "Condition": {"StringEquals": {"sts:ExternalId": EXTERNAL_ID}}},
        "statements": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
             "Resource": ["arn:aws:s3:::deputy-crown-vault", "arn:aws:s3:::deputy-crown-vault/*"]},
        ],
    },
}

S3 = {
    "deputy-analyst-scratch": {
        "welcome.txt": (
            "Welcome, analyst.\n"
            f"{FLAG1}\n"
            "Onboarding: our deploys run through a Lambda that executes as ci-runner-role.\n"
            "Check what YOU can do (get your inline policy) and what the runner can do.\n"
        ),
    },
    "deputy-runner-logs": {
        "build.log": f"[ci-runner-role] nightly deploy ok\ninternal marker: {FLAG2}\n",
    },
    "deputy-flag-vault": {
        "flag": f"{FLAG3}\n",
        "partner-config.json": json.dumps(
            {"partner": "DeputyCorp", "secure_role": f"arn:aws:iam::{PARTNER}:role/partner-secure-role",
             "external_id": EXTERNAL_ID,
             "note": "partner-secure-role is our HARDENED role — callers must pass this ExternalId."},
            indent=2),
    },
    "deputy-crown-vault": {"flag": f"{FLAG4}\n"},
}

LAMBDAS = {}
SESSIONS = {}
LOCK = threading.Lock()


def now_iso(plus=3600):
    return datetime.datetime.utcfromtimestamp(time.time() + plus).strftime("%Y-%m-%dT%H:%M:%SZ")


def as_list(v):
    return v if isinstance(v, list) else [v]


def caller_from_auth():
    auth = request.headers.get("Authorization", "")
    akid = None
    if "Credential=" in auth:
        akid = auth.split("Credential=", 1)[1].split("/", 1)[0]
    if not akid:
        akid = request.headers.get("X-Ak")
    if akid in USERS:
        return USERS[akid]
    with LOCK:
        s = SESSIONS.get(akid)
        if s and time.time() < s["exp"]:
            role = ROLES[s["role"]]
            return {"type": "assumed-role", "name": s["role"], "account": role["account"],
                    "arn": s["arn"], "statements": role["statements"]}
    return None


def allowed(principal, action, resource):
    a = action.lower()
    decision = False
    for st in principal.get("statements", []):
        if not any(fnmatch(a, pat.lower()) for pat in as_list(st.get("Action", []))):
            continue
        if not any(r == "*" or fnmatch(resource, r) for r in as_list(st.get("Resource", ["*"]))):
            continue
        if st.get("Effect") == "Deny":
            return False
        decision = True
    return decision


def service_from_auth():
    auth = request.headers.get("Authorization", "")
    if "Credential=" in auth:
        parts = auth.split("Credential=", 1)[1].split(",", 1)[0].split("/")
        if len(parts) >= 5:
            return parts[3]
    return None


def rid():
    return secrets.token_hex(8)


def xml(body, code=200):
    return Response(body, status=code, content_type="text/xml")


def query_err(code, msg, http=403, ns="https://sts.amazonaws.com/doc/2011-06-15/"):
    return xml(f'<ErrorResponse xmlns="{ns}"><Error><Type>Sender</Type><Code>{code}</Code>'
               f'<Message>{esc(msg)}</Message></Error><RequestId>{rid()}</RequestId></ErrorResponse>',
               http)


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def policy_doc(stmts):
    # IAM Query returns policy documents URL-encoded; botocore decodes them back.
    return quote(json.dumps({"Version": "2012-10-17", "Statement": stmts}))


def trust_doc_xml(role):
    t = role["trust"]
    princ = {"Service": t["Service"]} if "Service" in t else {"AWS": t["AWS"]}
    stmt = {"Effect": "Allow", "Principal": princ, "Action": "sts:AssumeRole"}
    if "Condition" in t:
        stmt["Condition"] = t["Condition"]
    return quote(json.dumps({"Version": "2012-10-17", "Statement": [stmt]}))


def mint_session(role_name, session_name):
    role = ROLES[role_name]
    akid = "ASIA" + secrets.token_hex(8).upper()
    arn = f"arn:aws:sts::{role['account']}:assumed-role/{role_name}/{session_name}"
    with LOCK:
        SESSIONS[akid] = {"role": role_name, "arn": arn, "exp": time.time() + 3600}
    return akid, "sk/" + secrets.token_urlsafe(24), "tok/" + secrets.token_urlsafe(48), arn


# ---- dispatch ----------------------------------------------------------------
@app.route("/", methods=["POST", "GET"])
def root():
    svc = service_from_auth()
    if request.method == "GET" and svc == "s3":
        return s3_list_buckets()
    body = request.get_data(as_text=True)
    params = {k: v[0] for k, v in parse_qs(body).items()}
    params.update({k: v for k, v in request.args.items()})
    action = params.get("Action")
    if svc == "sts" or action in ("GetCallerIdentity", "AssumeRole"):
        return sts_dispatch(action, params)
    if svc == "iam" or (action and (action[:3] in ("Get", "Lis"))):
        return iam_dispatch(action, params)
    return query_err("InvalidAction", f"unsupported action {action}", 400)


# ---- STS ---------------------------------------------------------------------
def sts_dispatch(action, params):
    p = caller_from_auth()
    if not p:
        return query_err("InvalidClientTokenId", "The security token included in the request is invalid.")
    if action == "GetCallerIdentity":
        uid = ("AROA" + p["name"].upper().replace("-", "") + ":sess") if p["type"] == "assumed-role" \
              else ("AIDA" + p["name"].upper())
        return xml(
            f'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
            f'<GetCallerIdentityResult><Arn>{esc(p["arn"])}</Arn><UserId>{uid}</UserId>'
            f'<Account>{p["account"]}</Account></GetCallerIdentityResult>'
            f'<ResponseMetadata><RequestId>{rid()}</RequestId></ResponseMetadata>'
            f'</GetCallerIdentityResponse>')
    if action == "AssumeRole":
        role_arn = params.get("RoleArn", "")
        sess = params.get("RoleSessionName", "")
        if len(sess) < 2:
            return query_err("ValidationError", "RoleSessionName must be at least 2 characters", 400)
        name = role_arn.rsplit("/", 1)[-1]
        role = ROLES.get(name)
        if not role or role["arn"] != role_arn:
            return query_err("AccessDenied", f"Not authorized to perform sts:AssumeRole on {esc(role_arn)}")
        if not allowed(p, "sts:AssumeRole", role_arn):
            return query_err("AccessDenied",
                             f'User {esc(p["arn"])} is not authorized to perform sts:AssumeRole on {esc(role_arn)}')
        ok, why = trust_allows(role, p, params.get("ExternalId"))
        if not ok:
            return query_err("AccessDenied", why)
        ak, sk, tok, arn = mint_session(name, sess)
        return xml(
            f'<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>'
            f'<Credentials><AccessKeyId>{ak}</AccessKeyId><SecretAccessKey>{sk}</SecretAccessKey>'
            f'<SessionToken>{tok}</SessionToken><Expiration>{now_iso()}</Expiration></Credentials>'
            f'<AssumedRoleUser><Arn>{esc(arn)}</Arn>'
            f'<AssumedRoleId>AROA{name.upper().replace("-","")}:{esc(sess)}</AssumedRoleId>'
            f'</AssumedRoleUser></AssumeRoleResult><ResponseMetadata><RequestId>{rid()}</RequestId>'
            f'</ResponseMetadata></AssumeRoleResponse>')
    return query_err("InvalidAction", f"unsupported sts action {action}", 400)


def trust_allows(role, principal, external_id):
    trust = role["trust"]
    if "Service" in trust:
        return False, "This role can only be assumed by an AWS service, not by sts:AssumeRole."
    expected = f"arn:aws:iam::{principal['account']}:root"
    if trust.get("AWS") != expected:
        return False, "The role's trust policy does not permit this principal to assume it."
    req = trust.get("Condition", {}).get("StringEquals", {}).get("sts:ExternalId")
    if req is not None and external_id != req:
        return False, ("The trust policy requires a matching sts:ExternalId." if external_id
                       else "The trust policy requires an sts:ExternalId but none was provided.")
    return True, "ok"


# ---- IAM ---------------------------------------------------------------------
IAM_NS = "https://iam.amazonaws.com/doc/2010-05-08/"


def iam_wrap(action, inner):
    return xml(f'<{action}Response xmlns="{IAM_NS}"><{action}Result>{inner}</{action}Result>'
               f'<ResponseMetadata><RequestId>{rid()}</RequestId></ResponseMetadata></{action}Response>')


def visible_role(p, name):
    """A role is visible via IAM to a caller only if it lives in the caller's account."""
    r = ROLES.get(name)
    return r if (r and r["account"] == p["account"]) else None


def iam_dispatch(action, params):
    p = caller_from_auth()
    if not p:
        return query_err("InvalidClientTokenId", "The security token included in the request is invalid.",
                         ns=IAM_NS)
    if not allowed(p, f"iam:{action}", "*"):
        return query_err("AccessDenied", f'User {esc(p["arn"])} is not authorized to perform iam:{action}',
                         ns=IAM_NS)
    if action == "GetUser":
        n = p.get("name", "analyst")
        return iam_wrap("GetUser", f'<User><UserName>{n}</UserName><Arn>{esc(p["arn"])}</Arn>'
                        f'<UserId>AIDA{n.upper()}</UserId><Path>/</Path>'
                        f'<CreateDate>2026-01-02T00:00:00Z</CreateDate></User>')
    if action == "ListRoles":
        items = "".join(
            f'<member><RoleName>{n}</RoleName><Arn>{r["arn"]}</Arn>'
            f'<RoleId>AROA{n.upper().replace("-","")}</RoleId><Path>/</Path>'
            f'<CreateDate>2026-01-02T00:00:00Z</CreateDate><MaxSessionDuration>3600</MaxSessionDuration>'
            f'<AssumeRolePolicyDocument>{trust_doc_xml(r)}</AssumeRolePolicyDocument></member>'
            for n, r in ROLES.items() if r["account"] == p["account"])
        return iam_wrap("ListRoles", f'<Roles>{items}</Roles><IsTruncated>false</IsTruncated>')
    if action == "GetRole":
        n = params.get("RoleName", "")
        r = visible_role(p, n)
        if not r:
            return query_err("NoSuchEntity", f"Role {esc(n)} cannot be found.", 404, ns=IAM_NS)
        return iam_wrap("GetRole", f'<Role><RoleName>{n}</RoleName><Arn>{r["arn"]}</Arn>'
                        f'<RoleId>AROA{n.upper().replace("-","")}</RoleId><Path>/</Path>'
                        f'<CreateDate>2026-01-02T00:00:00Z</CreateDate><MaxSessionDuration>3600</MaxSessionDuration>'
                        f'<AssumeRolePolicyDocument>{trust_doc_xml(r)}</AssumeRolePolicyDocument></Role>')
    if action == "ListRolePolicies":
        n = params.get("RoleName", "")
        r = visible_role(p, n)
        if not r:
            return query_err("NoSuchEntity", f"Role {esc(n)} cannot be found.", 404, ns=IAM_NS)
        return iam_wrap("ListRolePolicies",
                        f'<PolicyNames><member>{r["inline"]}</member></PolicyNames>'
                        f'<IsTruncated>false</IsTruncated>')
    if action == "GetRolePolicy":
        n = params.get("RoleName", "")
        r = visible_role(p, n)
        if not r:
            return query_err("NoSuchEntity", f"Role {esc(n)} cannot be found.", 404, ns=IAM_NS)
        return iam_wrap("GetRolePolicy", f'<RoleName>{n}</RoleName><PolicyName>{r["inline"]}</PolicyName>'
                        f'<PolicyDocument>{policy_doc(r["statements"])}</PolicyDocument>')
    if action == "ListUserPolicies":
        return iam_wrap("ListUserPolicies",
                        f'<PolicyNames><member>{USERS[ANALYST_AK]["inline"]}</member></PolicyNames>'
                        f'<IsTruncated>false</IsTruncated>')
    if action == "GetUserPolicy":
        u = USERS[ANALYST_AK]
        return iam_wrap("GetUserPolicy", f'<UserName>{u["name"]}</UserName>'
                        f'<PolicyName>{u["inline"]}</PolicyName>'
                        f'<PolicyDocument>{policy_doc(u["statements"])}</PolicyDocument>')
    if action == "ListAttachedUserPolicies":
        return iam_wrap("ListAttachedUserPolicies",
                        '<AttachedPolicies/><IsTruncated>false</IsTruncated>')
    if action == "ListAttachedRolePolicies":
        return iam_wrap("ListAttachedRolePolicies",
                        '<AttachedPolicies/><IsTruncated>false</IsTruncated>')
    return iam_wrap(action, "")


# ---- Lambda (REST-JSON) ------------------------------------------------------
def jerr(code, msg, http=403):
    return Response(json.dumps({"__type": code, "message": msg}), status=http,
                    content_type="application/json", headers={"x-amzn-ErrorType": code})


def lambda_arn(name):
    return f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{name}"


@app.route("/2015-03-31/functions", methods=["POST"])
def lambda_create():
    p = caller_from_auth()
    if not p:
        return jerr("UnrecognizedClientException", "invalid security token", 403)
    body = request.get_json(force=True, silent=True) or {}
    name = body.get("FunctionName", "")
    role_arn = body.get("Role", "")
    if not name or not role_arn:
        return jerr("InvalidParameterValueException", "FunctionName and Role are required", 400)
    if not allowed(p, "lambda:CreateFunction", lambda_arn(name)):
        return jerr("AccessDeniedException", "not authorized: lambda:CreateFunction")
    if not allowed(p, "iam:PassRole", role_arn):
        return jerr("AccessDeniedException", f"not authorized to iam:PassRole on {role_arn}")
    role = ROLES.get(role_arn.rsplit("/", 1)[-1])
    if not role or role["arn"] != role_arn:
        return jerr("InvalidParameterValueException", "the role does not exist", 400)
    if role["trust"].get("Service") != "lambda.amazonaws.com":
        return jerr("InvalidParameterValueException",
                    "The role defined for the function cannot be assumed by Lambda.", 400)
    with LOCK:
        if name in LAMBDAS:
            return jerr("ResourceConflictException", f"Function already exist: {name}", 409)
        if len(LAMBDAS) > 200:
            return jerr("TooManyRequestsException", "function limit reached", 429)
        LAMBDAS[name] = {"role": role_arn.rsplit("/", 1)[-1], "arn": role_arn}
    return Response(json.dumps({"FunctionName": name, "FunctionArn": lambda_arn(name),
                                "Role": role_arn, "Runtime": body.get("Runtime", "python3.12"),
                                "Handler": body.get("Handler", "index.handler"), "State": "Active"}),
                    status=201, content_type="application/json")


@app.route("/2015-03-31/functions/<name>", methods=["GET"])
@app.route("/2015-03-31/functions/<name>/configuration", methods=["GET"])
def lambda_get(name):
    p = caller_from_auth()
    if not p:
        return jerr("UnrecognizedClientException", "invalid security token", 403)
    if not allowed(p, "lambda:GetFunction", lambda_arn(name)):
        return jerr("AccessDeniedException", "not authorized: lambda:GetFunction")
    fn = LAMBDAS.get(name)
    if not fn:
        return jerr("ResourceNotFoundException", f"Function not found: {name}", 404)
    cfg = {"FunctionName": name, "FunctionArn": lambda_arn(name), "Role": fn["arn"], "State": "Active"}
    if request.path.endswith("/configuration"):
        return Response(json.dumps(cfg), content_type="application/json")
    return Response(json.dumps({"Configuration": cfg, "Code": {"RepositoryType": "S3"}}),
                    content_type="application/json")


@app.route("/2015-03-31/functions/<name>/invocations", methods=["POST"])
def lambda_invoke(name):
    p = caller_from_auth()
    if not p:
        return jerr("UnrecognizedClientException", "invalid security token", 403)
    if not allowed(p, "lambda:InvokeFunction", lambda_arn(name)):
        return jerr("AccessDeniedException", "not authorized: lambda:InvokeFunction")
    fn = LAMBDAS.get(name)
    if not fn:
        return jerr("ResourceNotFoundException", f"Function not found: {name}", 404)
    ak, sk, tok, _ = mint_session(fn["role"], f"awslambda-{name}")
    payload = {
        "message": "function executed; the execution role's environment credentials follow",
        "AWS_ACCESS_KEY_ID": ak, "AWS_SECRET_ACCESS_KEY": sk, "AWS_SESSION_TOKEN": tok,
        "role": ROLES[fn["role"]]["arn"],
    }
    return Response(json.dumps(payload), status=200, content_type="application/json")


@app.route("/2015-03-31/functions", methods=["GET"])
def lambda_list():
    p = caller_from_auth()
    if not p:
        return jerr("UnrecognizedClientException", "invalid security token", 403)
    if not allowed(p, "lambda:ListFunctions", "*"):
        return jerr("AccessDeniedException", "not authorized: lambda:ListFunctions")
    with LOCK:
        fns = [{"FunctionName": n, "FunctionArn": lambda_arn(n), "Role": f["arn"]}
               for n, f in LAMBDAS.items()]
    return Response(json.dumps({"Functions": fns}), content_type="application/json")


# ---- S3 ----------------------------------------------------------------------
def s3err(code, msg, http=403):
    return Response(f'<?xml version="1.0"?><Error><Code>{code}</Code><Message>{esc(msg)}</Message>'
                    f'<RequestId>{rid()}</RequestId></Error>', status=http, content_type="application/xml")


def s3_list_buckets():
    p = caller_from_auth()
    if not p:
        return s3err("InvalidAccessKeyId", "The AWS access key Id you provided does not exist.", 403)
    if not allowed(p, "s3:ListAllMyBuckets", "*"):
        return s3err("AccessDenied", "not authorized: s3:ListAllMyBuckets")
    buckets = "".join(f"<Bucket><Name>{b}</Name><CreationDate>2026-01-02T00:00:00Z</CreationDate></Bucket>"
                      for b in S3)
    return xml('<?xml version="1.0"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
               f'<Owner><ID>deputy</ID></Owner><Buckets>{buckets}</Buckets></ListAllMyBucketsResult>')


@app.route("/<bucket>", methods=["GET"])
@app.route("/<bucket>/<path:key>", methods=["GET"])
def s3_get(bucket, key=None):
    p = caller_from_auth()
    if not p:
        return s3err("InvalidAccessKeyId", "The AWS access key Id you provided does not exist.", 403)
    if bucket not in S3:
        return s3err("NoSuchBucket", f"The specified bucket does not exist: {bucket}", 404)
    if key is None:
        if not allowed(p, "s3:ListBucket", f"arn:aws:s3:::{bucket}"):
            return s3err("AccessDenied", "not authorized: s3:ListBucket")
        contents = "".join(f"<Contents><Key>{k}</Key></Contents>" for k in S3[bucket])
        return xml('<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                   f'<Name>{bucket}</Name><KeyCount>{len(S3[bucket])}</KeyCount>'
                   f'<IsTruncated>false</IsTruncated>{contents}</ListBucketResult>')
    if not allowed(p, "s3:GetObject", f"arn:aws:s3:::{bucket}/{key}"):
        return s3err("AccessDenied", f"not authorized: s3:GetObject on {bucket}/{key}")
    if key not in S3[bucket]:
        return s3err("NoSuchKey", f"The specified key does not exist: {key}", 404)
    return Response(S3[bucket][key], status=200, content_type="text/plain")


@app.route("/_health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), threaded=True)
