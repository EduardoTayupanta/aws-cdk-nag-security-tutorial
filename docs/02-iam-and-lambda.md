# Step 2: IAM and Lambda — Managed Policies, Wildcards, and Runtimes (IAM4 / IAM5 / L1)

> Part 3 of the *AWS CDK Nag — Step-by-Step Security Tutorial* series.

[Step 1](01-s3-buckets.md) locked down the buckets. This part gives the function that reads them least-privilege IAM, shows two findings that survive the obvious fixes, and packages the handler as a tested TypeScript, arm64 container image.

## The Problem / What We're Adding

`InsecureStack` produces four findings here:

```typescript
// lib/insecure-stack.ts
appRole.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName('AmazonS3FullAccess')); // IAM4
appRole.addToPolicy(new PolicyStatement({ actions: ['s3:*'], resources: ['*'] }));      // IAM5 ×2

new Function(this, 'ReaderFunction', {
  runtime: Runtime.NODEJS_20_X,                                                         // L1
  handler: 'index.handler',
  code: Code.fromInline('exports.handler = async () => ({ statusCode: 200 });'),
  role: appRole,
});
```

- `AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/AmazonS3FullAccess]`
- `AwsSolutions-IAM5[Action::s3:*]` and `AwsSolutions-IAM5[Resource::*]`
- `AwsSolutions-L1`: the zip function is not on the latest runtime of its family.

The function's job is small: given `{ "name": "report.csv" }`, return the size of `uploads/report.csv` in `DataBucket`.

## The Design

### IAM4: a dedicated role, not Lambda's default one

The less obvious IAM4 case: **every function using the default role** gets the `AWSLambdaBasicExecutionRole` managed policy. You could suppress it, since it only grants CloudWatch Logs, but a dedicated role removes it and scopes logging to one log group:

```typescript
const appRole = new Role(this, 'AppRole', {
  assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
});
```

[`ReaderFunction`](../lib/constructs/reader-function.ts) then grants that role only what the function needs: `logGroup.grantWrite(role)` on its own log group, plus X-Ray.

### IAM5: one action, one prefix

```typescript
appRole.addToPolicy(new PolicyStatement({
  sid: 'ReadUploadsPrefixOnly',
  actions: ['s3:GetObject'],
  resources: [dataBucket.arnForObjects('uploads/*')],
}));
```

> ⚠️ This **still triggers IAM5**: `IAM5[Resource::<DataBucketE3889A50.Arn>/uploads/*]`, because the ARN ends in `*`. That is expected: object keys are created at runtime, so a prefix is the narrowest possible scope. The right move is to acknowledge **that exact finding** with a reason (see [Step 5](05-suppressions-testing-ci.md)), not to widen the permission.

Why not `bucket.grantRead(role, 'uploads/*')`? It also grants `s3:GetObject*`, `s3:GetBucket*` and `s3:List*`: three more IAM5 findings to justify for a function that only reads objects.

Without `s3:ListBucket`, `HeadObject` on a missing key returns a **403** instead of a 404 `NotFound`. That is intentional: callers cannot probe which keys exist.

### L1: an arm64 container image

`SecureStack` packages the handler as a container image ([`lambda/reader/Dockerfile`](../lambda/reader/Dockerfile)): an esbuild bundle stage, then AWS's `public.ecr.aws/lambda/nodejs:22` base image.

```typescript
this.fn = new DockerImageFunction(this, 'Resource', {
  code: DockerImageCode.fromImageAsset(
    path.join(__dirname, '..', '..', 'lambda', 'reader'),
    { platform: Platform.LINUX_ARM64 },
  ),
  architecture: Architecture.ARM_64,
  memorySize: 256,
  timeout: Duration.seconds(10),
  tracing: Tracing.ACTIVE,
  role: props.role,
  logGroup: this.logGroup,
  environment: props.environment,
});
```

`Architecture.ARM_64` and `Platform.LINUX_ARM64` must both be set. Without the platform, Docker builds for the *host* architecture, and an amd64 image fails on an arm64 function with `exec format error`.

### The handler: logic behind a gateway

[`lambda/reader`](../lambda/reader) is a self-contained TypeScript sub-project with its own `package.json`, lockfile, `tsconfig.json` and Jest config:

| File | Role |
|------|------|
| [`src/index.ts`](../lambda/reader/src/index.ts) | Wiring only: config, S3 client, gateway |
| [`src/config.ts`](../lambda/reader/src/config.ts) | Reads and validates `BUCKET_NAME` and `READ_PREFIX` |
| [`src/describe-upload.ts`](../lambda/reader/src/describe-upload.ts) | Business logic, depends only on the `ObjectStorage` interface |
| [`src/gateways/s3-gateway.ts`](../lambda/reader/src/gateways/s3-gateway.ts) | `ObjectStorage` implemented with S3 `HeadObject` |

Only the gateway and the wiring import `@aws-sdk/*`. The logic always builds the key under `READ_PREFIX`, so it only ever asks for objects its IAM policy allows.

## The Trade-off

**L1 does not apply to container images.** That is not a loophole: the runtime version moves into the base image tag (`nodejs:22`), which Dependabot's `docker` ecosystem keeps current. The rule's goal, not running an end-of-life runtime, is still met, by a different mechanism. `InsecureStack` keeps a zip function precisely so L1 can be shown.

**X-Ray needs `Resource: "*"`.** `Tracing.ACTIVE` adds `xray:PutTraceSegments` and `xray:PutTelemetryRecords`, which do not support resource-level permissions. That is a second acknowledged finding, `AwsSolutions-IAM5[Resource::*]`, in the construct:

```typescript
Validations.of(props.role).acknowledge({
  id: 'AwsSolutions-IAM5[Resource::*]',
  reason:
    'X-Ray tracing (xray:PutTraceSegments / xray:PutTelemetryRecords) does not support ' +
    'resource-level permissions; Resource "*" is what AWS requires for these two actions.',
});
```

An acknowledgment keyed to `Resource::*` would also hide **any other** action someone later adds on `*`. A unit test pins the role's exact statement list, so that change fails the build (see [Step 5](05-suppressions-testing-ci.md)).

## Verifying It

- [`test/constructs/reader-function.test.ts`](../test/constructs/reader-function.test.ts): `PackageType: Image`, `Architectures: ['arm64']`, active tracing, the log group and its retention, the exact role statements, and the single X-Ray acknowledgment.
- [`test/secure-stack.test.ts`](../test/secure-stack.test.ts): `AppRole` has **exactly** three statements (the S3 read, its log group, X-Ray) and no managed policies.
- [`lambda/reader/test`](../lambda/reader/test): the logic against an in-memory fake, the gateway with `S3Client.send` spied, config, and a wiring smoke test. 100% coverage, enforced by the sub-project's own threshold.
- CI builds the image on a native `ubuntu-24.04-arm` runner and checks the bundled handler loads inside the real base image.

```bash
npm run test:lambda   # 14 tests, 100% statements/branches/functions/lines
```

## Cost & Cleanup

Lambda and X-Ray bill per request; nothing is billed while idle. The image lives in the CDK bootstrap ECR repository; `npx cdk gc --unstable=gc` reclaims unused assets after a teardown.

## What's Next

[Step 3](03-vpc-flow-logs.md) builds the network the database will live in: Flow Logs, isolated subnets, and a VPC endpoint opened to exactly one security group.
