# ITMS 544 – Lab01: Identity Lifecycle Management on the AWS Free Tier

**Student:** Tarun Sara

**AWS account:** 649838682635 (region us-east-2)

**Repository:** https://github.com/tsara-cyberforensics/ITMS_544/tree/main/Lab01

**Date of my run:** November 16, 2026 (times are UTC unless I say otherwise)

**AI use disclosure:** As permitted by the instructor, I used Claude (Anthropic) as an assistant in this lab. It helped me rebuild the lab files from the manual, troubleshoot problems during setup, and draft and edit these answers. I ran every step of the lab myself in my own AWS account, and all the results, timestamps and screenshots are from my run.

---

## What went differently in my run

The following deviations from the manual are referenced in several answers below.

1. **Workstation.** I used AWS CloudShell instead of a local container on my M1 Mac. CloudShell already includes the AWS CLI, git, Python and jq so no local Docker setup was required. I uploaded the 72 lab files and checked them: 72 files, every script passed `bash -n`, and every JSON file parsed. Both test runs passed (256 unit tests and 13 integration tests).

2. **Free-plan restrictions.** My account was created through the new "free plan / project" sign-up, which applies AWS-managed service control policies (SCPs). Two of them blocked parts of the lab:
   - `04-detection.sh` failed on `sns:CreateTopic` in us-east-1 with "explicit deny in a service control policy". The free plan only allows a short list of services in us-east-1, and SNS was not on it.
   - `01-groups-and-policies.sh` (and later onboarding) failed on `iam:CreateGroup`. The free-plan SCP called `DenyIAMRestrictedActions` blocks creating groups, adding users to groups and login profiles.

   To resolve this, I upgraded to the paid plan (my credits still apply) and turned on "advanced features", which removed the IAM block. Then, in the management account, I edited the region policy and added only `sns:*` and `events:*` to the us-east-1 allow list. I saved a backup of the original first. This gave me a first-hand view of the concept behind Q23: an SCP is a guardrail that even the account administrator cannot override.

3. **Security group sources.** The launch script opens port 8443 only to the IP of the machine running it, which for me was CloudShell, not my Mac. So I added my Mac's IP as a /32. CloudShell's IP also changed partway through, so I added that too. In the end the security group had three /32 addresses on 8443 and nothing else inbound.

4. **Boot failures.** The server failed to start twice before succeeding. The first time I typed the repo URL wrong (I left out the `/` before `Lab01`). The second time my GitHub repo was empty because my first push had gone to the wrong username. With no SSH, the only way I could see what happened was the serial console (`aws ec2 get-console-output`). It showed `fatal: repository ... not found` the first time and `open /opt/nimbus/docker-compose.yml: no such file or directory` the second. The third launch (`i-0a7b2591d9ef53201`) printed `lab01 ready`, and its SHA-256 fingerprint (`ED:00:F2:AA:…:2A:FF:F1:65`) matched what Safari showed me.

---

## Part A: Run the Tests Locally

**Q1 (explore). Tests as security controls.**
I would run the unit and policy tests (`test_policies.py`, `test_free_tier_guard.py`) on every pull request as a required check, and again in the build stage before anything gets deployed. If they fail, branch protection stops the merge. The integration tests are slower, so I would run them later, before deploying to a staging account. The nice thing about these tests is that a rule like "never open port 22" or "onboarding can only attach the MFA guard" becomes something the pipeline enforces, instead of something a reviewer has to remember to check.

There are two kinds of problems they cannot catch. First, **anything changed outside of git.** They test the files, not the live account. When I created mallory straight in IAM in G3, no test would ever have noticed. The free-plan SCP that broke my lab is another example: it lives completely outside the repo. Second, **problems nobody wrote a test for.** A test only checks what it says. A new risky permission that no test mentions just passes.

Tools like **IAM Access Analyzer policy validation**, **cfn-guard** and **Open Policy Agent** work differently. Access Analyzer checks policies against AWS's own grammar and best practices (for example, flagging `iam:PassRole` on `*`), and its custom checks can tell you whether a change grants new access. cfn-guard and OPA let you write one rule that applies to every resource, instead of one test per file. So my tests are precise but narrow, and those tools are broader. A **secret scanner**, like the credential check in `create_repo.sh` (it looks for `AKIA…`, private keys and `ghp_…` tokens), solves a different problem: secrets leaking into the repo. It has to run before the push, because once a key is in a public repo you have to treat it as stolen, even if you delete it later. A mature pipeline uses all three.

---

## Part B: IAM Groups and Policies

**Q2. Why does Nimbus-RequireMFA use BoolIfExists rather than Bool?**
Because `aws:MultiFactorAuthPresent` is not present on requests made with access keys, since long-term keys never carry MFA info. With plain `Bool`, a missing key does not match `"false"`, so the deny would not apply, and anyone with a stolen access key could bypass the MFA guard completely. `BoolIfExists` treats "missing" as a match, so the deny covers both "MFA is false" and "no MFA info at all". I observed this in G2: the access key I planted on william got `AccessDenied` on `s3 ls`, and the error named `Nimbus-RequireMFA` as the explicit deny.

**Q3. In TechTeam-DevScoped, why is a Deny still useful when no Allow grants IAM access?**
Right now nothing in that group allows IAM actions, but a user's permissions are the combination of every policy that applies to them. Later someone might attach a broader policy, put the user in another group, or add an inline policy with `iam:*`. The explicit Deny on privilege escalation actions (`CreatePolicyVersion`, `AttachUserPolicy`, `PassRole`, `AddUserToGroup` and so on) and on billing always wins in IAM. So instead of "nobody has given them this yet", it becomes "they cannot get this through any identity policy". It is a safeguard against future misconfiguration.

**Q4 (explore). Group membership as an escalation path.**
The most valuable group for an attacker is **SecurityTeam**. Its policy lets members create policies and new policy versions for anything under `policy/nimbus/*`. An attacker who controlled the onboarding service could create a user, add it to SecurityTeam (the onboarding role is allowed to add users to any `/nimbus/` group), and then use that user to publish a new default version of `TechTeam-DevScoped` or even `Nimbus-RequireMFA` that allows everything. That amounts to full administrator access, and it could disable the MFA guard for everyone. TechTeam and BusinessTeam offer far less by comparison.

Three ways to fix it:
- **Permissions boundary.** Every user created by onboarding gets a boundary that caps what they can ever do, no matter which group they end up in. It is strong, but it must be enforced it at creation time.
- **Condition on the group name.** Limit `iam:AddUserToGroup` in the onboarding role to TechTeam and BusinessTeam only. Then SecurityTeam membership needs a separate, human-approved process.
- **SCP.** Deny `AddUserToGroup` on SecurityTeam for everyone except a break-glass role. Even an account admin could not remove it.

I would do the **group-name condition** first, because it is a one-line least-privilege fix, and add a **permissions boundary** as a backup. In a bigger company I would add the SCP as well.

---

## Part C: Buckets, Secrets and Data Protection

**Q5. Where could the admin password have ended up without Secrets Manager?**
1. **In the git repo** (in `.env`, docker-compose or the code). My repo is public because the server clones it, so the password would be visible to anyone, forever, since git history keeps it even after you delete it.
2. **In the EC2 user data.** Anyone with `ec2:DescribeInstanceAttribute` can read user data, and so can anything on the instance through the metadata service. It also tends to show up in the serial console, which in this lab was the main thing I used to debug. And you could not rotate it without relaunching.
3. **Baked into a container image or environment variable.** You'd see it with `docker inspect`, in the image layers and in process listings, and every service would share the same copy.

All three spread copies of the secret to places with wider access and no record of who read it. With Secrets Manager it stays in one encrypted place, only specific roles can read it, every read shows up in CloudTrail, and I rotated it in G5 without touching any code.

**Q6. What does the TLS-only bucket policy stop that Block Public Access does not?**
Block Public Access stops anonymous or public access. It does not care how an authorized user connects. The TLS-only policy denies any request over plain HTTP or TLS older than 1.2, even from someone who's fully allowed in. That protects data and request signatures from being intercepted or downgraded on the network. In G5, as the account's full-access role, `list-objects-v2` over `http://` failed with "explicit deny in a resource-based policy", and the same call over HTTPS worked fine.

**Q7 (explore). Customer managed keys.**
With the default keys (SSE-S3, and the AWS-managed key for Secrets Manager), anyone with `s3:GetObject` or `GetSecretValue` can read the data. The encryption mostly protects against things like stolen disks. A **customer managed KMS key** adds a second check: you also need `kms:Decrypt` in the **key policy**. That gives you several things:
- An overly broad IAM or bucket policy alone is not enough to read the data anymore.
- You can cut off all access instantly by disabling the key.
- Every decrypt is logged with who did it.
- You can limit use to certain services with conditions like `kms:ViaService`.

To separate duties, the key policy has two statements. **Key admins** get management actions (`Create*`, `Enable*`, `Put*`, `ScheduleKeyDeletion` and so on) but **not** Decrypt or Encrypt. **Key users** (the service roles) get only `Encrypt`, `Decrypt`, `GenerateDataKey*` and `DescribeKey`. Admins can manage the key but cannot read data, and users can read data but cannot change who has access.

The cost is about **$1 per key per month** plus a small charge per request (S3 Bucket Keys cut that down). The failure modes are serious. If you lock every admin out of the key policy, disable the key or delete it, the data becomes unreadable, and after deletion it is gone for good. KMS can also throttle very busy workloads.

---

## Part D: One IAM Role per Microservice

**Q8. The three simulator results.**
All three use the same **principal**: `arn:aws:iam::649838682635:role/nimbus/nimbus-onboarding-svc`. [CHECK: confirm these decisions match your Part D screenshot.]

**1. Can onboarding attach AdministratorAccess to a user?** Action `iam:AttachUserPolicy`, resource `user/nimbus/alice`, context `iam:PolicyARN = …:aws:policy/AdministratorAccess`. **Result: implicitDeny.** The only statement that allows this action, `AttachOnlyTheMFAGuardPolicy`, has a condition (`ArnEquals iam:PolicyARN = …/Nimbus-RequireMFA`). AdministratorAccess does not match, so nothing allows it, and IAM's default deny applies.

**2. Same action, but attaching the MFA guard.** Action `iam:AttachUserPolicy`, resource `user/nimbus/alice`, context `iam:PolicyARN = arn:aws:iam::649838682635:policy/nimbus/Nimbus-RequireMFA`. **Result: allowed**, by `AttachOnlyTheMFAGuardPolicy`: the user is under `/nimbus/` and the condition matches.

**3. Can onboarding touch my lab user?** Action `iam:CreateLoginProfile`, resource `user/lab-user` (path `/`), no context. **Result: implicitDeny.** `CreateAndTagNimbusUsersOnly` only covers `user/nimbus/*`, and lab-user is not under that path.

None of these of these is an *explicit* deny. Least privilege here comes entirely from narrow allows, scoped by path and by condition.

**Q9 (explore). Four containers, one host.**
All four containers run on one EC2 instance, and the only identity on it is the instance role `nimbus-ec2-instance`. That role can assume any `role/nimbus/nimbus-*-svc`. IMDSv2 hands out a token in response to a PUT, and the hop limit is the TTL on that reply. With a hop limit of 1, the reply would die at the Docker bridge and containers could not get credentials. The lab sets it to 2 so containers can reach it, get the instance role's credentials, and then assume their own service role. The consequence is that a compromised *web* container can do exactly the same thing and assume the **onboarding** or **offboarding** role. The separation between services is therefore a convention, not something the platform enforces.

Three redesigns:
- **One instance per service.** Each gets its own instance role and hop limit 1, so isolation is strong. But it is four times the compute (more than the free tier's one instance) and four servers to patch.
- **ECS task roles.** Credentials are handed out per task by the ECS agent, and ECS can block containers from reaching the host's metadata service. You get per-task isolation, and on Fargate there is no server to manage. Moderate cost; the main effort is learning ECS.
- **Kubernetes pod identity** (EKS Pod Identity or IRSA). It offers similar isolation, but EKS has a control-plane fee and is considerably more complex. It is only justified if you already use Kubernetes.

For an app this size I would go with **ECS task roles on Fargate**.

---

## Part E: Logging and Alerts

**Q10. Which two kinds of event does the lab alert on, and why alert instead of just storing them?**
1. **`lab01-risky-iam`:** IAM changes that create persistence or raise privileges: `CreateAccessKey`, `PutUserPolicy`, `PutGroupPolicy`, `PutRolePolicy`, `CreatePolicyVersion`, `UpdateAssumeRolePolicy`, `DeleteUserPermissionsBoundary`, and attaching `AdministratorAccess`.
2. **`lab01-signin-without-mfa`:** a successful console login where `MFAUsed = No`.

Stored logs only help if someone reviews them. These events are rare normally and usually mean someone is setting up access, so the time to detection determines the impact. An alert reaches a person within minutes. In my run, I got the emails for james's no-MFA login and for the `CreateAccessKey` calls while I was still in the console. CloudTrail still keeps the full history for investigating afterwards.

**Q11 (explore). Blind spots in detection.**
Two things these rules would miss:
1. **`CreateLoginProfile` or `UpdateLoginProfile` on an existing user**, which is how you give a dormant account a password. When I reset james's password in G1 (`UpdateLoginProfile` at 23:29:40), there was no alert.
2. **Using stolen credentials from somewhere unusual.** Calls like `ListBuckets` or `GetSecretValue` from a new country are just normal API calls, so no rule matches. Creating a user does not alert either: mallory in G3 only showed up as UNTRACKED on the dashboard. Neither do `AddUserToGroup` to SecurityTeam or `StopLogging`.

A pattern for the first one:

```json
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": ["CreateLoginProfile", "UpdateLoginProfile", "CreateUser", "AddUserToGroup"]
  }
}
```

The main risk is **alert fatigue**. Onboarding legitimately calls `CreateLoginProfile` ten times, so this rule would generate frequent, expected alerts and analysts would begin to ignore them. You'd exclude the onboarding role (with an `anything-but` on the caller ARN) and send low-priority events to a daily summary instead. **GuardDuty** does this differently. Instead of fixed patterns, it learns what's normal for each user from CloudTrail, VPC Flow Logs and DNS logs, and flags anomalies, for example credentials used from a new location, from Tor, or from a known bad IP. That catches the "stolen credentials" case, which a static rule cannot express.

---

## Part F: Launch the Hardened Server

**Q12. Why no SSH and no key pair, and how do you debug without them?**
SSH is an exposed management port that must be protected, and a key pair is a long-lived credential that can leak. My flow logs showed random internet scanners trying **port 22** on my instances within minutes of launch, and all of them were rejected because there was no rule for it. The server is built entirely by `user-data.sh` and deletes itself after 8 hours, so no interactive login is needed. Changes are made in code and deployed by relaunching.

I debugged in three ways. The **serial console output** (`aws ec2 get-console-output`) is how I found both of my boot failures. **CloudWatch Logs** (`/lab01/app`) has every container's logs. **CloudTrail** shows what the services did in AWS. The boot log even said `SSM Agent unable to acquire credentials`, which confirms that Session Manager access is also not enabled.

**Q13. If the web container were compromised, what does egress filtering stop and what does not it stop?**
Outbound is only allowed on **TCP 443 and 80**. That **stops** reverse shells or command-and-control on other ports, exfiltration over SSH, SMTP or random TCP/UDP ports, and scanning out on other ports. It **does not stop** sending data out over HTTPS to any server on 443, downloading malware over 80 or 443, DNS tunneling (security groups do not filter the VPC DNS resolver), or reaching the metadata service. The last point is the most significant: the attacker could still obtain the instance role credentials (see Q9) and call AWS APIs over 443. To close those gaps you would need something domain-aware, like a filtering proxy or AWS Network Firewall.

**Q14 (explore). Certificates and trust on first use.**
Comparing the fingerprint protects against a **man-in-the-middle** on the first connection. An attacker on the network path (a rogue Wi-Fi network, a compromised router, DNS spoofing) could present their own self-signed certificate, and the browser would show the same "not private" warning for theirs as for mine. Only an out-of-band check of the fingerprint proves the certificate belongs to my server. I compared the one from the console output with the one in Safari's certificate view. Most users skip this step because the warning is common, the fingerprint is long and tedious to compare, and clicking through gives them immediate access. Self-signed certificates effectively train users to ignore the warning.

An **ACM certificate** on a load balancer is issued by a CA that browsers already trust, renews itself, and keeps the private key inside AWS, so there is no warning. It needs a domain name and a load balancer, which cost money. A **public CA** like Let's Encrypt gives you the same browser trust for free, but you handle the key and renewals yourself. **HSTS** tells the browser to only ever use HTTPS for the site and not to let users click through cert errors, which stops SSL-stripping. **Certificate Transparency** makes CAs publish every cert they issue in public logs, so if a fraudulent certificate is issued for my domain by a compromised CA, it can be detected by watching the logs.

---

## Part H, G4: Network proofs

**Q15. Which checks proved encryption in transit, a smaller attack surface, and protection against password guessing?**
[CHECK: match these with your G4 screenshot.]
- **Encryption in transit:** check 1 (`https: 200` while plain `http://` on 8443 failed) and check 2 (the security headers, especially `Strict-Transport-Security`, which keeps the browser on HTTPS).
- **Smaller attack surface:** check 3 (ports **22** and **8080** closed) and check 5. The security group had inbound **8443 only**, outbound **80 and 443 only**, and the S3 endpoint showed `Gateway available`. My flow logs also showed probes to 22 and 8080 being `REJECT`ed. `X-Frame-Options` and `Content-Security-Policy` from check 2 help too, on the browser side.
- **Password guessing:** check 4. Six wrong passwords returned `200 200 200 200 200 429`: after five failures from the same IP, the login gives *429 Too Many Requests* for five minutes.

---

## Part H, G1 to G3: Identity experiments

**Q16. Why does the same user and action get denied without MFA and allowed with it?**
The simulator gave `explicitDeny` for jennifer calling `ce:GetCostAndUsage` with `aws:MultiFactorAuthPresent = false`, and `allowed` with `true`. Same user, same action, same policies. Only the request context changed. `Nimbus-RequireMFA` has a Deny with `NotAction` (everything except setting up MFA and changing your password) and this condition:

```json
"Condition": { "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" } }
```

Without MFA, that explicit deny beats the Cost Explorer allow from BusinessTeam-ReadOnly. With MFA, the condition is false, the deny does not apply, and the group's allow works. I saw this for real when I signed in as **james** without MFA: the console could not even load his own login profile (`iam:GetLoginProfile … explicit deny … Nimbus-RequireMFA`). After he enrolled MFA at **23:34:55** (CloudTrail shows `EnableMFADevice by james from 104.194.107.195`, which is my Mac), the dashboard moved him from MFA PENDING to OK. [CHECK: time the lab01-signin-without-mfa email arrived.]

**Q17. Who created mallory and how did you find out? Why does not the S3 audit trail show it?**
CloudTrail showed **`CreateUser` at 23:42:53** by the session `6448c428-b031-70a3-fda5-0f3d9c8fd573`. That is my own `AccountFullAccessRole` session, the admin I was using in CloudShell. It is a different principal from `nimbus-onboarding-svc`, which created all the real employees. I identified it in three steps:
1. The **dashboard** marked mallory **UNTRACKED**: she existed in IAM under `/nimbus/` but had no registry record.
2. `08-investigate.sh mallory` said **"no audit entries for mallory"** for the S3 audit trail.
3. The script's CloudTrail section came back empty, which I investigated further. IAM is a global service, so its events show up in CloudTrail event history in **us-east-1**, and the script searches us-east-2. When I ran `aws cloudtrail lookup-events --region us-east-1 …` the event appeared. Adding `--region us-east-1` to the script would fix it.

The S3 audit trail is written by the **app**: only the onboarding and offboarding services write to `audit/`. I created mallory directly with the IAM API, so the app never knew about her. That is exactly why the dashboard checks the registry against **live IAM**, and why CloudTrail is the source of truth.

**Q18 (explore). Replacing IAM users with single sign-on.**
With IAM Identity Center connected to an identity provider (Entra ID, Okta, Google), people log in through the IdP and get **short-lived role sessions** through permission sets.

**What becomes unnecessary:** creating IAM users, console passwords and one-time passwords, per-user access keys, the IAM parts of the onboarding and offboarding services, and the per-user MFA guard. MFA and joining or leaving the company move into the IdP, so disabling one account there cuts access everywhere.

**What still matters:**
- **Enforcing MFA**, now in the IdP, with Identity Center and SCPs as a backup.
- **A kill switch.** Disabling someone in the IdP does not end sessions that are already active, so you still need a way to revoke them, for example a deny on the role based on `aws:TokenIssueTime`, or Identity Center's session revocation.
- **Drift detection.** It matters even more, because under SSO *any* IAM user or access key is suspicious, like mallory.
- **Least-privilege permission sets, CloudTrail and alerts.**

**New risks:** if the **IdP gets compromised**, the attacker has the keys to every AWS account. Other risks are misconfigured SAML or OIDC trust, group mappings that give a big group too much access, and the IdP being a single point of failure (so you need offline break-glass credentials). You also end up relying on the IdP's logs during an investigation.

---

## Part H, G5 and G6: Data proofs and incident drill

**Q19. Why is token rotation safe with no restart, and what would break if services only accepted the current token?**
`07-rotate-token.sh` saved a new value. Secrets Manager labeled it **AWSCURRENT** and kept the old one as **AWSPREVIOUS** (I checked with `--version-stage AWSPREVIOUS`). Each service caches the token for 60 seconds and accepts **either** label. So during the minute when one service has the new token and another still has the old one, calls still work. If a token matches neither cached value, the service refreshes its cache once (and logs `internal_token_refreshed`) before rejecting the call. No restart is needed, and my dashboard kept working after the rotation. I did not see an `internal_token_refreshed` line in the logs. When I looked at the code, it only logs that when a request arrives while the caches disagree, and in my case both services just picked up the new token on their own when their caches expired.

If services accepted only the **current** token, any call between a service that had refreshed and one that hadn't would get a 401, for up to 60 seconds. Onboarding and the dashboard would fail during every rotation. To avoid that you would have to restart all the containers together, which is an outage, so rotation would happen less often, which weakens security.

**Q20. Which control would have prevented the incident, and which only limited it? One more free control?**

My drill timeline (November 16, UTC):

| Phase | What I did | Time |
|---|---|---|
| Preparation | Trail, alerts, roles, kill switch, investigation script | n/a |
| Detection | Planted backdoor key `AKIAZOTLHMIF5LE5R7YH` on james (T0) | **23:49:19** |
|  | `lab01-risky-iam` email arrived | [CHECK] |
| Analysis | Looked up james in CloudTrail (us-east-1): every step of his lifecycle, with caller and source IP | [CHECK] (about 23:50) |
| Containment | Offboarded james (DenyAll attached, keys deactivated) | [CHECK] |
| Eradication | Deleted the backdoor key | **23:51:00** |
| Recovery | Onboarded replacement account `james2` | [CHECK] |
| Post-incident | Read the REJECT records in `/lab01/flow` | **23:51:18** |

**What would have prevented it:** the attacker used the admin's stolen credentials to call `CreateAccessKey`. What stops that call is requiring **MFA on the admin** (no long-lived admin keys) and least privilege, so the everyday admin cannot create keys for other users. An **SCP** denying `iam:CreateAccessKey` on `user/nimbus/*` (except a break-glass role) would have blocked it even with admin credentials.

**What only limited it:** `Nimbus-RequireMFA` and `Nimbus-DenyAll`. The planted key was useless while james had no MFA (G2 showed that), and after offboarding DenyAll blocks it too. The alert, the DRIFT badge and the investigation script made it faster to notice and respond, but none of them stopped the key from being created.

**One more free control:** an **SCP that blocks access-key creation for `/nimbus/` users entirely**, since employees only need the console with MFA. SCPs are free, and this one would have prevented the backdoor. Another option is an EventBridge rule that automatically sets any new `/nimbus/` access key to Inactive and notifies security.

**Q21 (explore). Mapping the drill to MITRE ATT&CK and a control set.**

| Drill step | MITRE ATT&CK (Cloud / IaaS) |
|---|---|
| Attacker uses the admin's stolen credentials | **T1078.004** Valid Accounts: Cloud Accounts |
| `CreateAccessKey` on james (backdoor) | **T1098.001** Account Manipulation: Additional Cloud Credentials |
| Creating mallory (G3) | **T1136.003** Create Account: Cloud Account |
| Testing the key (`get-caller-identity`, `s3 ls`) | **T1087.004** Account Discovery: Cloud Account / **T1526** Cloud Service Discovery |
| Internet scanners hitting 22 and 8080 (flow logs) | **T1595** Active Scanning |

My side of the drill (detect, analyze, contain, eradicate, recover) follows the NIST SP 800-61 incident-handling life cycle.

Three controls from the lab mapped to the **CIS AWS Foundations Benchmark (v3.0)** and **NIST SP 800-53 Rev. 5**:
1. **Nimbus-RequireMFA**: CIS 1.10 (MFA for IAM users with a console password); NIST **IA-2(1)**.
2. **CloudTrail with log file validation**: CIS 3.1 and 3.2; NIST **AU-2** and **AU-9**.
3. **TLS-only, encrypted buckets with Block Public Access**: CIS 2.1.1 and 2.1.4; NIST **SC-8** and **SC-28**.

**Something the lab does not meet:** CIS 3.1 wants a **multi-region** trail, and the lab makes a single-region one (`--no-is-multi-region-trail`) to keep things simple. It also skips AWS Config in all regions and only keeps logs for 7 to 30 days, which would not meet NIST **AU-11** (audit record retention).

---

## Part I: From 10 to 100 People

**Q22. Which limit do you hit first in each row, and what would you change?**

| Concern | What I would hit first | What I would change |
|---|---|---|
| **Permissions** | Not the AWS quotas (10 groups per user, 5,000 users). First, three groups get too coarse: finance and HR need different access, so people end up in multiple groups or getting exceptions. | Move to SSO permission sets with tag-based access (ABAC), and keep groups only for broad roles. |
| **Registry** | The dashboard lists S3 objects and reads one per employee on every refresh. Fine at 100, but it gets slow and costs more at thousands. | Keep an index, or move the registry to DynamoDB (free tier) with conditional writes. |
| **Dashboard** | **I already hit this at 10 people.** It makes about 6 IAM calls per user (around 60 per refresh), and on a t3.micro that sometimes took longer than the web container's 20-second timeout (`dashboard service unavailable: ReadTimeout`). Reloading worked because of the 15-second cache. At 100 people it would be about 600 calls, plus IAM throttling. | Use the **IAM credential report** (one call for all users), build the report in a scheduled background job, and serve the cached result. |
| **Service identity** | A security limit more than a scale one: all four containers share one host, so one compromised container can become any service role (Q9). | ECS task roles or separate instances. |
| **Sign-in** | One shared admin password does not work with several admins: there is no individual accountability, and rotating it affects everyone. | SSO with per-person MFA, and stop creating IAM users. |
| **Logging** | 7 to 30 days of retention and a single-region trail stop being acceptable long before the volume becomes a problem. Event volume also becomes too large to review manually. | An organization trail into a separate log-archive account with Object Lock, plus a SIEM (or Security Lake with GuardDuty). |

**Q23 (explore). Controls even an administrator cannot remove.**
I encountered this directly in the lab: the free-plan SCPs blocked my *admin* role from SNS in us-east-1 and from IAM groups, and no IAM permission could override them until I edited the SCP from the management account. The following SCP that would protect three of the lab's controls, with a break-glass exception:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProtectTrail",
      "Effect": "Deny",
      "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors"],
      "Resource": "arn:aws:cloudtrail:*:*:trail/lab01-trail",
      "Condition": {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassSecurity"}}
    },
    {
      "Sid": "ProtectKillSwitchAndMfaGuard",
      "Effect": "Deny",
      "Action": ["iam:DeletePolicy", "iam:CreatePolicyVersion", "iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion"],
      "Resource": ["arn:aws:iam::*:policy/nimbus/Nimbus-DenyAll", "arn:aws:iam::*:policy/nimbus/Nimbus-RequireMFA"],
      "Condition": {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassSecurity"}}
    },
    {
      "Sid": "ProtectBlockPublicAccess",
      "Effect": "Deny",
      "Action": ["s3:PutAccountPublicAccessBlock", "s3:PutBucketPublicAccessBlock", "s3:DeleteBucketPolicy", "s3:PutBucketPolicy"],
      "Resource": "*",
      "Condition": {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassSecurity"}}
    }
  ]
}
```

**What an SCP does not protect against:** it only limits principals *inside member accounts*, and it never grants anything. It does not apply to the **management account**. It does not control access through resource policies from outside the organization (resource control policies, RCPs, address that). It cannot stop someone misusing permissions they're still allowed to have: a user with S3 read access can still copy data out. The management account is exempt so the organization can never lock itself out completely. It is the root of trust that creates accounts and edits SCPs, so it should hold no workloads, have very few users, and use strong MFA. I had to set a root password for exactly that account when I turned on advanced features.

---

## Part J: Clean Up

Before cleaning up, `06-usage-report.sh` showed one running t3.micro (`i-0a7b2591d9ef53201`), one 8 GB gp3 volume, 26 S3 objects (10,279 bytes), two secrets, and 11 IAM users under `/nimbus/`. Then I ran `99-cleanup.sh` and `00-preflight-freetier.sh` again. [CHECK: cleanup result and the preflight PASSED line.] I kept `scp-backup.json` in the management account so I can put the original SCP back.

**Q24 (explore). Can you trust the logs?**
With **log file validation** on, CloudTrail writes a **digest file** every hour. It contains the SHA-256 hash of each log file from that hour and the hash of the **previous** digest, and it is signed with CloudTrail's private key. That makes a chain. It proves each log file really came from CloudTrail, that it hasn't been **changed**, and that nothing has been **deleted** from the middle, because a missing link breaks the chain. To check it:

```bash
aws cloudtrail validate-logs \
  --trail-arn arn:aws:cloudtrail:us-east-2:649838682635:trail/lab01-trail \
  --start-time 2026-11-16T21:00:00Z --verbose
```

It downloads the digests and logs, checks the signatures with CloudTrail's public key, and tells you whether each file is valid, invalid or missing.

**What an admin could still do in this lab:** the trail and the log bucket are in the **same account** as the attacker. They could call `StopLogging` or `DeleteTrail` (although those calls get logged too), change what gets logged, or **delete the whole log bucket with all the digests**, which is exactly what `99-cleanup.sh` does. Validation can prove tampering *inside* a chain that still exists, but it cannot bring back evidence that was deleted entirely. They could also delete the CloudWatch log groups and flow logs.

**How the extra controls would change that:**
- A **separate log-archive account** receiving an organization trail means the workload account's admin has no permissions on the log bucket at all, and an SCP (Q23) stops them turning off the trail.
- **S3 Object Lock in compliance mode** makes each log file impossible to delete or change for the retention period, even by the root user.
- **MFA Delete** means permanently deleting versions needs the root user's MFA device.

With all three, a compromised administrator in the workload account could at most stop *new* logging, which would itself raise an alert, and the old evidence would stay safe and verifiable.

---

## References

1. AWS. *IAM JSON policy elements: Condition operators* and *Global condition context keys (aws:MultiFactorAuthPresent)*. https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
2. AWS. *Policy evaluation logic*. https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
3. AWS. *IAM Access Analyzer policy validation*. https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html
4. AWS. *Permissions boundaries for IAM entities*. https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
5. AWS. *Service control policies (SCPs)*. https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
6. AWS. *Managed policies for your organization (projects)* and *Activate advanced AWS features*. https://docs.aws.amazon.com/accounts/latest/reference/scps-and-rcps-for-projects.html
7. AWS. *Key policies in AWS KMS*. https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
8. AWS. *Configure the instance metadata service options*. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html
9. AWS. *Amazon ECS task IAM role*. https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
10. AWS. *Amazon GuardDuty finding types*. https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html
11. AWS. *Validating CloudTrail log file integrity*. https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
12. AWS. *Using S3 Object Lock*. https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
13. Center for Internet Security. *CIS Amazon Web Services Foundations Benchmark v3.0.0*. https://www.cisecurity.org/benchmark/amazon_web_services
14. NIST. *SP 800-53 Rev. 5*. https://doi.org/10.6028/NIST.SP.800-53r5
15. NIST. *SP 800-61 Rev. 2, Computer Security Incident Handling Guide*. https://doi.org/10.6028/NIST.SP.800-61r2
16. MITRE. *ATT&CK Cloud Matrix (IaaS)*. https://attack.mitre.org/matrices/enterprise/cloud/iaas/
17. IETF. *RFC 6797 (HSTS)* and *RFC 9162 (Certificate Transparency v2.0)*.
