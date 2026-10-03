# Step 5: Suppressions, Tests, and CI — Making the Checks Hard to Game

> Part 6 of the *AWS CDK Nag — Step-by-Step Security Tutorial* series.

[Step 4](04-rds-secret-rotation.md) finished the remediations. This part covers what keeps them in place: how acknowledgments work in cdk-nag 3.x, which tests prove each fix, and the pipeline that enforces it.

## The Problem / What We're Adding

A security check is only as strong as the easiest way around it. With cdk-nag that way around is a suppression: a vague reason, a whole stack suppressed, or a suppression that quietly covers more than intended. And a green cdk-nag run says nothing about whether the stack actually **works** (see Step 4).

## The Design

### Acknowledging a finding (cdk-nag 3.x)

`SecureStack` has exactly **two** acknowledgments, both on `AppRole`, each scoped to one finding:

```typescript
// lib/secure-stack.ts
Validations.of(appRole).acknowledge({
  id: 'AwsSolutions-IAM5[Resource::<DataBucketE3889A50.Arn>/uploads/*]',
  reason:
    'The "*" is the deliberate prefix scope: the function can only call s3:GetObject ' +
    'on objects under uploads/ in this bucket. S3 object keys are created at runtime and cannot be ' +
    'enumerated in advance, so a prefix is the narrowest possible scope for object reads.',
});

// lib/constructs/reader-function.ts
Validations.of(props.role).acknowledge({
  id: 'AwsSolutions-IAM5[Resource::*]',
  reason:
    'X-Ray tracing (xray:PutTraceSegments / xray:PutTelemetryRecords) does not support ' +
    'resource-level permissions; Resource "*" is what AWS requires for these two actions.',
});
```

In the code, the bucket's logical ID is computed with `this.getLogicalId(...)` rather than hard-coded, so the ID does not go stale if the hash changes.

### What `acknowledge()` actually does

Each behavior below is pinned by [`test/acknowledge.test.ts`](../test/acknowledge.test.ts), so a cdk-nag upgrade that changes it fails the build:

- **Use the plain ID** (`AwsSolutions-S1`). The CLI suggests `AwsSolutions::AwsSolutions-S1`. `cdk synth` accepts both, but `validateScope()`, which the tests use, accepts **only** the plain one.
- **Granular rules are acknowledged finding by finding.** Acknowledging `AwsSolutions-IAM5[Action::s3:*]` does not hide `AwsSolutions-IAM5[Resource::*]`, and acknowledging the base ID `AwsSolutions-IAM5` hides neither.

## The Trade-off

### An acknowledgment covers more than it looks

A `Resource::` acknowledgment hides **every** action on that resource, including ones added later. Adding `s3:DeleteObject` on `uploads/*`, or `s3:ListAllMyBuckets` on `*`, passes cdk-nag silently.

Writing a more careful reason does not fix that; a test of what the suppression is meant to allow does. [`test/secure-stack.test.ts`](../test/secure-stack.test.ts) pins `AppRole`'s exact statement list:

```typescript
test('AppRole has exactly three statements: the S3 read, its log group, and X-Ray', () => {
  expect(appRoleStatements()).toEqual([
    expect.objectContaining({ Sid: 'ReadUploadsPrefixOnly', Action: 's3:GetObject' }),
    expect.objectContaining({
      Action: ['logs:CreateLogStream', 'logs:PutLogEvents'],
      Resource: { 'Fn::GetAtt': [expect.stringMatching(/^ReaderFunctionLogGroup/), 'Arn'] },
    }),
    expect.objectContaining({
      Action: ['xray:PutTelemetryRecords', 'xray:PutTraceSegments'],
      Resource: '*',
    }),
  ]);
});
```

A separate test asserts the stack has exactly these two acknowledgments, and that each reason names what it justifies. A new suppression fails the build until someone reviews it there.

### Write the reason for a skeptical reviewer

"It's required" or "not applicable" are not reasons. A reason explains why the risk the rule guards against does not apply to that resource. It lives in the code and in the construct metadata (`aws:cdk:acknowledged-rules`), where it serves as audit evidence.

## Verifying It

### Test layers

| File | What it proves |
|------|----------------|
| [`test/app.test.ts`](../test/app.test.ts) | The App wiring: only `SecureStack` by default; `includeInsecure` adds `InsecureStack`; a real `app.synth()` with cdk-nag passes or throws accordingly. |
| [`test/insecure-stack.test.ts`](../test/insecure-stack.test.ts) | cdk-nag **does** report each of the 13 findings the series covers. |
| [`test/secure-stack.test.ts`](../test/secure-stack.test.ts) | cdk-nag passes; exactly two acknowledgments; each remediation in the template, including what cdk-nag cannot see (endpoint ingress, rotation egress, the log-write grant, the exact role statements). |
| [`test/constructs/reader-function.test.ts`](../test/constructs/reader-function.test.ts) | `ReaderFunction` in isolation: arm64 image, tracing, log group, grants. |
| [`test/acknowledge.test.ts`](../test/acknowledge.test.ts) | The `acknowledge()` semantics described above. |
| [`lambda/reader/test`](../lambda/reader/test) | The handler: logic with fakes, the S3 gateway, config, and wiring. |

The cdk-nag check runs in a unit test through `validateScope()`, cdk-nag 3.x's test entry point. It prints the violations when it fails:

```typescript
test('passes the AWS Solutions (cdk-nag) rule pack with no violations', () => {
  const report = new AwsSolutionsChecks().validateScope(stack);
  if (!report.success) {
    // Fail with the actual violations printed, not just "false !== true".
    throw new Error(`AwsSolutions violations:\n${JSON.stringify(report.violations, null, 2)}`);
  }
  expect(report.success).toBe(true);
});
```

Tests load `cdk.json`'s `context` explicitly (`new App({ context: cdkJson.context })`), because feature flags are only applied by the `cdk` CLI, not by a bare `new App()`.

**Coverage is 100%** (statements, branches, functions and lines), enforced by `coverageThreshold` in both [`jest.config.js`](../jest.config.js) and [`lambda/reader/jest.config.js`](../lambda/reader/jest.config.js). Coverage alone proves little, so every test that guards a remediation was also checked by **deleting that remediation** and confirming the suite fails.

### The pipeline

[`.github/workflows/cdk-nag-check.yml`](../.github/workflows/cdk-nag-check.yml) runs on every push and pull request to `main`:

1. `npm ci` for the app and for `lambda/reader`; typecheck both.
2. Root tests, including cdk-nag, with the 100% threshold; then the Lambda's own tests with its own threshold.
3. `cdk synth` of `SecureStack`. A cdk-nag `ERROR` fails the job and blocks the PR.
4. `cdk synth` of `InsecureStack`, which must fail **because of cdk-nag findings**: the step checks the output for `AwsSolutions-`, so a compile error does not count.
5. A separate job on a native `ubuntu-24.04-arm` runner builds the arm64 image and checks the handler loads inside it.

Hardening: a read-only `GITHUB_TOKEN`, actions pinned by commit SHA, `persist-credentials: false`, `concurrency` and timeouts, and no AWS credentials anywhere. [Dependabot](../.github/dependabot.yml) updates npm (both projects, with a 7-day cooldown), the Docker base images and the actions.

### Other rule packs

Running `NIST80053R5Checks` or `HIPAASecurityChecks` against `SecureStack` adds findings such as customer-managed KMS keys, S3 replication, `IAMNoInlinePolicy` and Lambda DLQ/VPC/concurrency. Some are false positives: `EC2RestrictedCommonPorts` flags the database ingress rule because its port is a CloudFormation token. Choose the pack that matches your compliance target, not the strictest one available.

## Cost & Cleanup

Nothing here touches AWS: the tests and the pipeline are fully static.

## Lessons Learned

1. **Passing cdk-nag does not mean it works.** It checks for what is excessive, not for what is missing; the rotation path in Step 4 proved it.
2. **Fixing one rule can surface another.** The endpoint's default ingress made EC23 throw during evaluation; the secure fix also removed the error.
3. **The textbook IAM5 fix still triggers IAM5.** A prefix ARN ends in `*`. Acknowledge that exact finding with a reason; don't pretend it is gone.
4. **Lambda's default role is a hidden IAM4.** A dedicated role removes it, and then you have to grant logging yourself; a test pins that grant.
5. **The obvious fix can add findings.** `cloudwatchLogsRetention` brings a custom-resource Lambda with its own IAM4/IAM5.
6. **Suppressions need a test of what they allow.** cdk-nag cannot tell you what a `Resource::` acknowledgment is hiding; a unit test can.
7. **Test the "before" too.** Asserting the insecure stack still fails guards the tutorial against silent changes in cdk-nag.

## What's Next

This completes the series' first arc. Possible next steps: a customer-managed KMS key across S3, Secrets Manager and CloudWatch Logs, which most of the NIST/HIPAA findings ask for, and deploying from CI with GitHub OIDC.
