# Step 0: cdk-nag 3.x — Static Security Analysis Before Anything Is Deployed

> Part 1 of the *AWS CDK Nag — Step-by-Step Security Tutorial* series.

This part explains what cdk-nag is, how the 3.x API differs from the 2.x one most blog posts still show, how it is wired into this repo, and how to read the findings it reports. Later parts remediate those findings one service at a time.

## The Problem / What We're Adding

A CDK app can synthesize a perfectly valid CloudFormation template for a bucket that is public, a role with `s3:*` on `*`, or a database with no encryption. CloudFormation will deploy all of it. Code review catches some of it, if the reviewer knows every service's security knobs.

[cdk-nag](https://github.com/cdklabs/cdk-nag) moves that check to **synthesis time**. It walks the construct tree and validates every resource against a rule pack, so `cdk synth` fails before anything reaches an AWS account:

- **AwsSolutionsChecks**: general best practices from the AWS Solutions Library. This series uses it.
- **HIPAASecurityChecks**, **NIST80053R5Checks**, **PCIDSS321Checks**: compliance-oriented packs.

## The Design

### Two stacks, same construct IDs

The repo contains the same resources twice:

- [`InsecureStack`](../lib/insecure-stack.ts): the "before", with the most common flaws written **on purpose**. It is never deployed.
- [`SecureStack`](../lib/secure-stack.ts): the "after", remediated. It uses **the same construct IDs**, so each finding in the first maps to a fix in the second.

Each later part of the series covers one group of resources across both stacks.

### Registering cdk-nag (3.x API)

cdk-nag 3.x is a **native CDK validation plugin**. It is registered once, at the `App` level, so every stack added later is covered with no extra wiring. In this repo that lives in [`buildApp()`](../lib/app.ts):

```typescript
export function buildApp(app: App): App {
  new SecureStack(app, 'SecureStack');

  if (String(app.node.tryGetContext('includeInsecure')) === 'true') {
    new InsecureStack(app, 'InsecureStack');
  }

  Validations.of(app).addPlugins(new AwsSolutionsChecks(app, { verbose: true }));
  return app;
}
```

[`bin/app.ts`](../bin/app.ts) only calls `buildApp(new App())`. Keeping the wiring in `lib/` means it is unit-tested like everything else ([`test/app.test.ts`](../test/app.test.ts)). `verbose: true` adds each rule's full explanation to the report.

> **Coming from cdk-nag 2.x?** `Aspects.of(app).add(new AwsSolutionsChecks())` becomes `Validations.of(app).addPlugins(new AwsSolutionsChecks(app))`, and `NagSuppressions.addResourceSuppressions(...)` becomes `Validations.of(construct).acknowledge(...)`. The whole series uses the 3.x API.

## The Trade-off

Why keep a deliberately insecure stack in the repo at all? Because a tutorial's claims about a tool should be **tested against the tool**. [`test/insecure-stack.test.ts`](../test/insecure-stack.test.ts) asserts that cdk-nag reports each of the 13 findings this series covers. If a future cdk-nag release stopped detecting one of them, the build would fail instead of the tutorial silently teaching something false.

The cost is one context flag: `InsecureStack` is only added when you pass `-c includeInsecure=true`, so a default `cdk synth`, and the pipeline, stay green.

## Verifying It

```bash
npx cdk synth                                          # SecureStack: passes
npx cdk synth InsecureStack -c includeInsecure=true    # fails with 13 errors
```

Excerpt of the real output:

```
ERROR The S3 Bucket has server access logs disabled. The bucket should have server access logging enabled to provide detailed records for the requests that are made to the bucket. (AwsSolutions)
   InsecureStack/DataBucket/Resource aws-cdk-lib.aws_s3.CfnBucket
   Acknowledge with 'AwsSolutions::AwsSolutions-S1'

ERROR The IAM entity contains wildcard permissions and does not have a cdk-nag rule suppression with evidence for those permission. [...]
   InsecureStack/AppRole/DefaultPolicy/Resource aws-cdk-lib.aws_iam.CfnPolicy
   Acknowledge with 'AwsSolutions-IAM5[Action::s3:*]'

WARNING Runtime: Runtime 'nodejs20.x' was deprecated on '2026-04-30'. [...] (CloudFormation Validate)
   InsecureStack/ReaderFunction/Resource (ReaderFunctionD0BD5D14) aws-cdk-lib.aws_lambda.CfnFunction
   Acknowledge with 'CloudFormation-Validate::W2531'
Synthesis finished with errors
```

### How to read a finding

```
<LEVEL> <Rule description> (<Rule pack>)
   <Construct path> <L1 type>
   Acknowledge with '<Finding ID>'
```

- **Level**: `ERROR` makes `cdk synth` (and therefore `cdk deploy`) exit non-zero; `WARNING` is informational.
- **Construct path**: where the resource is in the construct tree (`InsecureStack/DataBucket/Resource`). It matches the IDs in your code.
- **Finding ID**: the rule (`AwsSolutions-S1`) or, for *granular* rules such as IAM4/IAM5, the rule plus the exact finding (`AwsSolutions-IAM5[Action::s3:*]`). Look it up in [RULES.md](https://github.com/cdklabs/cdk-nag/blob/main/RULES.md).
- **Rule pack**: besides `AwsSolutions`, CDK runs its own `CloudFormation Validate` checks, which add useful warnings such as deprecated runtimes.

The full report is also written to `cdk.out/validation-report.json`.

Fix the highest-impact findings first (public access, encryption, permissive IAM), then the hardening ones (logging, runtime versions, ports).

## Cost & Cleanup

Nothing in this part touches AWS: synthesis and the tests need no credentials.

## What's Next

[Step 1](01-s3-buckets.md) fixes the three S3 findings (S1, S2, S10), and shows why the access-logs bucket needs no logging of its own.
