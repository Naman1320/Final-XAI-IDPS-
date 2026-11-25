# infra/: AWS infrastructure for the IDPS (Terraform)

Everything for the cloud part of the project (docs/PLAN.md section 4b) as code, so one
`terraform destroy` removes it. **It has never been applied to real AWS** (the project has no AWS
account and must never be billed). Since 17 Nov 2026 it is validated and applied, unchanged, to an
open-source AWS emulator with `lab/cloud/tf.sh` (see `docs/cloud-architecture.md`): all 49 resources
are created and a second plan shows no changes. That run found and fixed one real bug
(`insensitive_value` is `insecure_value` on `aws_ssm_parameter`). Real AWS may still differ in small
ways (see "First run" below).

## You must do these yourself

Terraform cannot, and this repository must never, do them for you:

1. **Create the AWS account** (and turn on MFA for the root user). Check AWS Educate / student
   credits first.
2. **Create an IAM identity for Terraform** (an IAM Identity Center user, or an IAM user with
   access keys) with enough permissions to create the resources below, and configure it on your
   machine (`aws configure sso` or `aws configure`). Never commit keys; `.gitignore` already
   excludes `*.tfvars`, `*.tfstate`, `*.pem` and `*.key`.
3. **Choose the budget email** (`budget_email`, in the separate `budget/` stack below). AWS
   Budgets email alerts need no confirmation click; if nothing arrives, check your inbox and spam.
4. **Install Terraform** (1.6 or newer) and the AWS CLI v2, and the Session Manager plugin for the
   AWS CLI (needed for `aws ssm start-session`).
5. **Create the secrets in Parameter Store with the AWS CLI** after each deploy (below). Terraform
   does not manage them, so they are never in a `.tfvars` file or in Terraform state.
6. **Copy Caddy's root certificate** to the machine that runs the collector ("Trust the SOC
   certificate" below), so it can verify the SOC.

## What gets created

| Part | Resources |
|---|---|
| SOC host | VPC (10.50.0.0/16) with one public subnet and internet gateway; one EC2 instance (`t3.micro` by default) with an encrypted gp3 root volume, IMDSv2 required, an Elastic IP; user data installs Docker and starts PostgreSQL + the SOC API + Caddy (HTTPS) with Docker Compose |
| SOC access | Security group: TCP 443 and 80 only from `admin_cidrs` and `sensor_cidrs`. **No SSH port**; use SSM Session Manager (instance profile with `AmazonSSMManagedInstanceCore`) |
| Secrets | **Not in Terraform.** Three SSM SecureStrings you create once with the AWS CLI (`/idps-fyp/jwt-secret`, `/idps-fyp/anthropic-api-key`, `/idps-fyp/maxmind-key`), encrypted with a customer-managed KMS key (`aws_kms_key.ssm`, rotation on) whose key policy lets only the SOC instance role decrypt. The SOC role may read `/idps-fyp/*`; the victim role has an explicit Deny on it |
| Models | S3 bucket (all public access blocked, SSE-S3 encryption, versioning, TLS only) |
| Target VPC | VPC (10.60.0.0/16), one public subnet, one small victim instance (nginx, SSM only), a network ACL, VPC Flow Logs (all traffic, 60 s windows, default v2 format) to an S3 bucket (public access blocked, encryption, expiry after 7 days) |
| Collector | IAM role (created only when `collector_trusted_principal_arns` is set): list and read this account's flow-log prefix, create/replace/delete entries on that one network ACL, `ec2:DescribeNetworkAcls` |
| Cost control | `budget/` (a separate stack, see below): AWS Budgets monthly budget (default 10 USD), emails at 80% and 100% of actual spend and at 100% forecast |

Everything is tagged `Project=idps-fyp` (provider `default_tags`).

Files: `versions.tf` (providers, locals), `variables.tf`, `soc.tf`, `secrets.tf` (KMS key and
secret access rules), `target.tf`, `collector.tf`, `outputs.tf`, `modules/secure_bucket/` (the
hardened bucket, used twice: models and flow logs), `templates/` (instance boot scripts),
`terraform.tfvars.example`, and `budget/` (its own root module).

Both instances have `lifecycle { ignore_changes = [ami] }`, so a new Amazon Linux release does
not replace them (and does not wipe the SOC database); they use `cpu_credits = "standard"` so a
burstable instance is throttled instead of billed for surplus credits. Changing the user data
(for example `repo_ref`) still replaces an instance, because `user_data_replace_on_change` is on:
that also wipes the SOC database.

## Rough monthly cost

Prices change and differ by region; check the AWS Pricing Calculator. Rough eu-west-1 numbers
for everything running 24 hours a day, 30 days:

| Item | About |
|---|---|
| 2 x `t3.micro` | 2 x 8 USD |
| 2 x public IPv4 address (the SOC's Elastic IP, the victim's address) | 2 x 3.7 USD |
| EBS (20 GB + 8 GB gp3) | 2.5 USD |
| KMS key for the SOC secrets (`aws_kms_key.ssm`) | about 1 USD (prorated per hour; not charged while pending deletion) |
| Flow logs, S3, SSM parameters, Budgets | under 1 USD for lab traffic |
| **Total if left on all month** | **about 28 USD** |

So the 10 USD default budget is a deliberate alarm: **the design assumes you run a stack for a few
hours per test session and destroy it**. A 4-hour session costs roughly 0.15 USD. New accounts may
have free-tier credits that cover most of it. AWS Budgets alerts are delayed by hours and do not
stop spending. Destroy the stack when you are done.

## Budget (separate stack, create once)

The budget is its own root module in `infra/budget/`, so destroying the lab stack does not remove
it. Create it once, then leave it:

```bash
cd infra/budget
cp terraform.tfvars.example terraform.tfvars     # set budget_email (and monthly_budget_usd)
terraform init
terraform apply
```

It sends email at 80% and 100% of actual spend and when the forecast for the month passes 100%.
AWS Budgets email alerts do not need a subscription confirmation: if nothing arrives, check your
inbox and spam folder. Budgets alert hours late and never stop spending. Its state is
`infra/budget/terraform.tfstate` (git-ignored). Remove it only when you are done with the project:
`terraform destroy` inside `infra/budget/`.

## Deploy

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars     # then edit: admin_cidrs at least
terraform init
terraform validate
terraform plan -out tfplan                       # read it: this is what will be created
terraform apply tfplan
```

`terraform apply` can fail once with `MalformedPolicyDocumentException ... Invalid principal` on
the KMS key: the new SOC role is not visible to KMS yet. Run `terraform apply` again.

Then create the real secrets, **once per deploy**. Terraform does not manage the parameters (a
Terraform-managed parameter would put the decrypted value in `terraform.tfstate`), so the CLI is
the only place they are written. Use the customer-managed key, never the default `alias/aws/ssm`
key: the default key can be used by every principal in the account.

```bash
P=/idps-fyp   # your ssm_prefix
KEY=$(terraform output -raw ssm_kms_key_id)
aws ssm put-parameter --region eu-west-1 --type SecureString --key-id "$KEY" --name $P/jwt-secret \
  --value "$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
aws ssm put-parameter --region eu-west-1 --type SecureString --key-id "$KEY" --name $P/anthropic-api-key --value '...'
aws ssm put-parameter --region eu-west-1 --type SecureString --key-id "$KEY" --name $P/maxmind-key --value '...'
```

The Anthropic and MaxMind parameters are optional (leave them out to switch the assistant and the
geo-IP download off). Values must not contain spaces, quotes or `$`. Typing a secret on the command
line leaves it in your shell history; `--value file://secret.txt` avoids that. To change one later,
add `--overwrite`. Then start the stack on the host:

```bash
aws ssm start-session --target "$(terraform output -raw soc_instance_id)"
# inside the session:
sudo tail -n 30 /var/log/idps-bootstrap.log      # first-boot log
sudo /opt/idps/start.sh                          # reads the parameters, runs docker compose up -d
sudo docker compose -f /opt/idps/docker-compose.yml logs -f api
```

Create the first SOC user and a sensor token inside the API container (see docs/soc.md):

```bash
cd /opt/idps && sudo docker compose exec api python -m soc.api create-user alice --role admin
sudo docker compose exec api python -m soc.api create-sensor cloud-collector
```

Open `https://<soc_public_ip>/health` from an address in `admin_cidrs`. The certificate is issued
for the Elastic IP by Caddy's own CA, so the browser warns once (or import the root certificate,
below). A public certificate (Let's Encrypt) cannot be issued while port 80 is limited to
`admin_cidrs`, because Let's Encrypt's validation servers are not in that list; use a DNS
challenge or temporarily widen port 80 if you want one.

### Trust the SOC certificate (for the collector)

The collector verifies the SOC's certificate and never turns verification off. Copy Caddy's local
root certificate (public, not a secret) from the SOC host to the collector machine:

```bash
aws ssm start-session --target "$(terraform output -raw soc_instance_id)"
# inside the session:
sudo docker compose -f /opt/idps/docker-compose.yml exec caddy cat /data/caddy/pki/authorities/local/root.crt
```

Save the printed `-----BEGIN CERTIFICATE-----` block as a file on the collector machine, e.g.
`~/soc-root.crt`, and set `IDPS_SOC_URL=https://<soc_public_ip>` and
`IDPS_SOC_CA_FILE=~/soc-root.crt` (use the full path). A new deploy gets a new Elastic IP and a new
Caddy CA, so repeat this after every deploy.

Useful outputs: `terraform output` (SOC instance id and public IP, flow-log bucket and prefix,
target NACL id, collector role ARN, KMS key id).

## Destroy (after every test session)

```bash
cd infra
terraform destroy
```

This removes everything in this stack, the flow-log bucket and, with the default
`force_destroy_buckets = true`, the models bucket with its contents. Keep your trained models
locally (`models/` is git-ignored but stays on disk); the bucket is only a copy. To keep the
bucket contents, set `force_destroy_buckets = false` (destroy will then stop at a non-empty bucket
and you empty it yourself). The budget in `budget/` is not touched.

- The **SSM parameters are not removed** (Terraform does not manage them). The KMS key is
  scheduled for deletion in 7 days, which makes them unreadable; delete them anyway and create
  them again after the next deploy (the next deploy has a new key):

  ```bash
  aws ssm delete-parameters --region eu-west-1 --names /idps-fyp/jwt-secret /idps-fyp/anthropic-api-key /idps-fyp/maxmind-key
  ```
- Flow-log delivery can write one more object after the bucket was emptied, so the bucket delete
  can fail with `BucketNotEmpty`. Run `terraform destroy` again.

Check afterwards in the console (EC2, VPC, S3, Elastic IPs, KMS) that nothing is left.

## Network ACL rule numbers: Terraform vs the collector

The target subnet's network ACL is shared by two writers:

| Rule numbers | Owner |
|---|---|
| **1 to 90** | the collector (`idps/cloud/nacl.py`): DENY entries for blocked attacker IPs, one ingress and one egress per address, removed when the TTL runs out |
| 91 to 99 | unused |
| **100 and up** | Terraform: the ALLOW rules (`aws_network_acl_rule`: 100 and 101 return traffic, 110+ web port if `victim_web_open`, 200+ attacker test hosts, egress 100 all) |

Terraform never creates a rule below 100, and `aws_network_acl.target` has **no inline `ingress`
or `egress` blocks**: with inline blocks Terraform would treat every other rule as drift and
delete the collector's denies on the next apply. Do not add inline rules, and do not add a
Terraform rule numbered 1 to 90. A deny at a lower number is evaluated before every allow.

Quota: network ACLs allow 20 rules per direction by default. Terraform uses at most
`2 + victim_web_cidrs + attacker_cidrs` ingress rules (at most 10 with the validations), so the
collector's cap of 10 active denies (`IDPS_CLOUD_MAX_DENIES`, at most 10) fits. At the cap the
collector refuses new blocks instead of evicting existing ones (see docs/cloud.md).

## Security notes

- `admin_cidrs` is required, has no default, and the validation rejects 0.0.0.0/0, anything
  shorter than /24 and CIDRs with host bits set. `sensor_cidrs` has the same checks. `repo_url`
  and `repo_ref` are validated strictly because they are written into a boot script.
- **SOC secrets.** Only the SOC instance role can decrypt them: the SSM parameters use a
  customer-managed KMS key whose key policy allows `kms:Decrypt` to that role alone (through SSM),
  and the victim role has an explicit Deny on `ssm:GetParameter*` for `/idps-fyp/*` and on
  decrypting the key (`AmazonSSMManagedInstanceCore` itself allows `ssm:GetParameter` on `*`, which
  is why the default `alias/aws/ssm` key would not be enough). This does not stop an account
  administrator, who can edit the key policy. The account root keeps key administration and
  Encrypt (so `put-parameter` works), not Decrypt.
- The collector role can create/replace/delete entries on one network ACL, scoped by ARN, and
  list/read only this account's flow-log prefix. `ec2:DescribeNetworkAcls` cannot be scoped to a
  resource, so it is granted on `*` (read-only metadata). IAM also cannot restrict by rule number;
  the collector code only touches 1 to 90 and its tests enforce that.
- The collector role exists only if you list principals in `collector_trusted_principal_arns`;
  there is no default trust.
- The victim is in a public subnet with a public address because SSM needs a route to AWS and a
  NAT gateway costs about 33 USD a month. Its security group has no inbound rules unless you
  enable `victim_web_open` or list `attacker_cidrs`.
- DoS and flood tests are **not** allowed in AWS without approval; run those in the local lab only
  (docs/PLAN.md section 4b).
- Put the addresses you administer from (your admin IP, sensors, the SOC host, the target VPC) on
  the collector's `IDPS_ALLOWLIST`: an allowlisted address is never blocked, so it cannot be
  used to fill the deny cap or lock you out.

## First run: what to check

Terraform and the AWS provider were not available when these files were written, so nothing was
validated beyond HCL syntax (and a shell syntax check of the boot scripts). On first use:

- `terraform init` creates `.terraform.lock.hcl`; commit it. The provider is pinned `~> 6.0`.
- `terraform validate` first, then read `terraform plan` carefully.
- `compose_version` (default `v2.40.3`) must be a real Docker Compose release; the host
  download and checksum check fails loudly in `/var/log/idps-bootstrap.log` if it is not.
- The Caddy configuration (an internal-CA certificate for the bare Elastic IP) is untested; if
  HTTPS does not answer, check `docker compose logs caddy`.
- The KMS key policy and the victim Deny are untested: after deploy, check from a Session Manager
  shell on the victim that `aws ssm get-parameter --name /idps-fyp/jwt-secret --with-decryption`
  is denied.
- The API container installs its packages from PyPI at start (slow on a `t3.micro`); a prebuilt
  image is the obvious next step.
