# Cloud Security Audit — Simulated AWS Environment


## Executive Summary

This report presents the findings of an automated security audit conducted against a simulated AWS environment consisting of S3 buckets, EC2 instances, and IAM roles. Activity logs spanning a single day were analyzed alongside static resource configurations. The audit detected **18 findings across 7 rule categories**, with 8 classified as HIGH severity. The environment exhibits a pattern of over-provisioned IAM roles, publicly exposed storage and compute resources, and active credential-based attack attempts — a combination that, in a real environment, would represent a credible and exploitable attack surface.

---

## Environment Overview

| Resource Type | Count |
|---------------|-------|
| S3 Buckets | 5 |
| EC2 Instances | 6 |
| IAM Roles | 4 |
| CloudTrail Log Events | 26 |
| Unique Users | 6 |

The audit ingested raw CloudTrail JSON and AWS Describe API output, normalized it through a parser layer, and ran it through a deterministic rule engine. No machine learning was used — all findings are based on explicit, auditable conditions.

---

## Summary Dashboard

![dashboard summary cards](./dashboard/summary_cards.png)

---

## Key Findings

### 🔴 HIGH — Public S3 Buckets (Rules 1)

Two S3 buckets — `R102` (`dev-public-uploads`) and `R104` (`staging-data-dump`) — have public access enabled with no server-side encryption configured. `R102` is set to `public-read`, meaning any unauthenticated user can enumerate and download its contents. `R104` is set to `public-read-write`, which additionally allows unauthenticated writes — a significantly worse posture that enables data injection, content replacement, and storage of malicious payloads at the bucket owner's cost.

Neither bucket has logging enabled, which means access by unauthorized parties would leave no trace in this environment.

**Risk:** Data exfiltration, unauthorized writes, compliance violation (PII exposure).

---

### 🔴 HIGH — EC2 Instances with Port 22 Open to the Internet (Rule 2)

Three EC2 instances — `R106`, `R108`, and `R110` — have port 22 (SSH) open to `0.0.0.0/0` and are publicly reachable via a routable IP address. This means any host on the internet can initiate an SSH connection attempt against these instances.

This finding is made more severe by the fact that `R106` and `R110` are also assigned admin-level IAM instance profiles (see Rule 3 below). A successful SSH brute-force or credential compromise on either instance would grant the attacker not just shell access, but full AWS API permissions through the attached role.

**Risk:** Remote code execution, privilege escalation, lateral movement to AWS control plane.

---

### 🔴 HIGH — Brute Force Login Attempts (Rule 5)

Two users — `charlie` and `frank` — triggered the brute force detection rule, each recording 5+ consecutive failed `ConsoleLogin` events within a 1-minute window. Both attempts originated from static IPs, suggesting automated credential stuffing tools rather than manual attempts.

`charlie` subsequently achieved a successful login later in the day from the same IP (`198.51.100.7`). Whether this represents a legitimate user who forgot their password or a successful attack is ambiguous without MFA logs — but the pattern warrants investigation either way.

**Risk:** Unauthorized account access, privilege abuse if targeted accounts hold admin roles.

---

### 🔴 HIGH — Suspicious Multi-IP Login (Rule 6)

User `eve` authenticated from 4 distinct IP addresses within a 2-minute window: `185.220.101.1`, `45.33.32.156`, `91.108.4.100`, and `103.21.244.0`. The first three attempts failed; the fourth succeeded.

The IPs span multiple geographic regions and include addresses associated with anonymization infrastructure. This pattern is consistent with a credential stuffing attack where the actor rotates IPs to evade rate limiting, eventually succeeding on the fourth attempt. The account `eve` was targeting `R112`, an admin-level IAM role. The successful login from `103.21.244.0` should be treated as a potential account compromise.

**Risk:** Active credential compromise, admin-level access gained by external actor.

---

### 🟡 MEDIUM — Pervasive Admin Role Assignment (Rule 3)

Admin-level IAM roles are assigned to 6 of the 15 audited resources: `R103`, `R104`, `R106`, `R109`, `R110`, `R112`, and `R113`. This constitutes 40% of the audited resource pool running with full administrative permissions — a significant violation of the principle of least privilege.

Of particular concern is `R112`, the admin IAM role targeted by the `eve` multi-IP attack described above, and `R106` and `R110`, which combine an admin instance profile with a publicly exposed SSH port. Any of these three resources represents a single point of failure that, if compromised, grants an attacker full control over the AWS account.

**Risk:** Maximum blast radius on any single resource compromise.

---

### 🟡 MEDIUM — Admin Account High-Activity Session (Rule 7)

The `admin` user executed 9 distinct API actions within a 9-minute window between 09:00 and 09:09 UTC. Actions included `AttachRolePolicy`, `CreateUser`, `DeleteBucketPolicy`, `PutBucketAcl`, and `CreateAccessKey` — a sequence that, taken together, describes the behavior of either a misconfigured automation script or a threat actor performing privilege escalation and persistence operations.

Notably, `CreateAccessKey` was called for user `alice` during this session. Issuing new access keys for another user is a common attacker technique for establishing persistent programmatic access that survives a password reset.

**Risk:** Potential persistence mechanism established; policy changes may have expanded attack surface.

---

### 🟡 MEDIUM — Encryption Disabled on Multiple Resources (Rule 4)

Five resources have encryption disabled: `R102`, `R104` (S3 buckets), `R106`, `R108`, `R109` (EC2 EBS volumes). Three of these are also either publicly accessible or assigned admin roles, meaning the lack of encryption compounds the risk of other findings rather than existing in isolation.

**Risk:** Plaintext data exposure if storage volumes are accessed outside the application layer.

---

## Findings Breakdown Charts

![screenshot of the two bar charts (severity breakdown on the left, findings by rule on the right)](./dashboard/charts_breakdown.png)


---

## Attack Scenarios

The findings above do not exist in isolation. When read together, two realistic breach paths emerge from this environment.

### Scenario A — Credential Compromise → Admin Escalation

```
eve attempts login from 4 IPs (Rule 6)
    └──▶ succeeds on 4th attempt → gains access to R112 (admin role)
              └──▶ R112 has AdministratorAccess policy attached (Rule 3)
                        └──▶ full AWS account control: can read R102/R104
                                  (public + unencrypted S3 buckets, Rule 1 + Rule 4)
```

The `eve` account compromise, combined with the admin role assigned to `R112`, means a single successful login gives an attacker unrestricted access to all resources in the account — including the two publicly exposed, unencrypted S3 buckets. This is a complete account takeover path requiring no additional exploitation steps.

---

### Scenario B — SSH Brute Force → AWS Control Plane

```
Internet-facing EC2 instances R106 / R110 have port 22 open (Rule 2)
    └──▶ SSH brute force succeeds (consistent with charlie/frank pattern, Rule 5)
              └──▶ shell access on instance with admin IAM profile (Rule 3)
                        └──▶ attacker calls AWS CLI using instance role credentials
                                  └──▶ CreateUser, AttachPolicy, exfiltrate S3 data
```

An attacker who gains SSH access to `R106` or `R110` does not need to steal IAM credentials separately — the EC2 instance metadata service (IMDS) provides temporary AWS credentials for the attached role automatically. Combined with the admin instance profile on both machines, shell access is equivalent to console access.

---

## Findings Table - Filtered to high severity

![Findings table filtered to HIGH severity only.](./dashboard/findings_high_only.png)

---

## Recommendations Summary

| # | Rule Triggered | Priority | Recommended Fix |
|---|---------------|----------|-----------------|
| 1 | Public Storage | Immediate | Enable S3 Block Public Access on R102 and R104; remove public-read-write ACL |
| 2 | Open SSH Port | Immediate | Restrict Security Groups on R106, R108, R110 to known IP ranges; evaluate Session Manager |
| 6 | Suspicious IP | Immediate | Treat eve's session as compromised; rotate credentials; review actions taken post-login |
| 7 | Admin Overuse | Urgent | Audit the 09:00–09:09 admin session; review CreateAccessKey call; check for persistence |
| 5 | Brute Force | Urgent | Enable account lockout policy; enforce MFA on all IAM users |
| 3 | Over-Privileged Role | High | Scope IAM roles to minimum required permissions; remove admin from R106, R109, R110 |
| 4 | No Encryption | High | Enable EBS encryption on R106, R108, R109; enable SSE-S3 on R102, R104 |

---

## Methodology & Tooling

This audit was performed using a custom Python-based static analysis tool built on top of normalized CloudTrail and AWS Describe API data. The tool applies a deterministic rule engine with no external dependencies on cloud-native security services (GuardDuty, Security Hub, Config). All findings are reproducible by re-running the analysis against the same input files.

Detection rules, thresholds, and source code are available in the project repository. The parser, detection engine, and reporting layer are fully decoupled — the detection logic is input-format agnostic and can be pointed at any normalized dataset matching the expected schema.

---

*Simulated environment. All resource IDs, IP addresses, usernames, and account numbers are fictional and generated for demonstration purposes.*