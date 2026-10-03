# Step 1: S3 — Access Logs, Public Access, and TLS (S1 / S2 / S10)

> Part 2 of the *AWS CDK Nag — Step-by-Step Security Tutorial* series.

[Step 0](00-cdk-nag-concepts.md) wired cdk-nag into the app. This part remediates the three S3 findings, and explains why the bucket that receives the access logs is compliant without logging of its own.

## The Problem / What We're Adding

`InsecureStack`'s `DataBucket` triggers three AwsSolutions errors:

| Rule | Problem |
|------|---------|
| AwsSolutions-S1  | Server access logging is disabled |
| AwsSolutions-S2  | Public access is not blocked |
| AwsSolutions-S10 | Requests without TLS are not denied |

```typescript
// lib/insecure-stack.ts
new Bucket(this, 'DataBucket', {
  blockPublicAccess: new BlockPublicAccess({
    blockPublicAcls: false, blockPublicPolicy: false,
    ignorePublicAcls: false, restrictPublicBuckets: false,
  }),
  removalPolicy: RemovalPolicy.DESTROY,
});
```

## The Design

[`SecureStack`](../lib/secure-stack.ts) adds a dedicated access-logs bucket and fixes all three rules on the data bucket:

```typescript
const accessLogsBucket = new Bucket(this, 'AccessLogsBucket', {
  encryption: BucketEncryption.S3_MANAGED,
  versioned: true,
  blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
  enforceSSL: true,
  objectOwnership: ObjectOwnership.BUCKET_OWNER_ENFORCED,
  lifecycleRules: [{ id: 'expire-access-logs', expiration: Duration.days(365) }],
  removalPolicy,
  autoDeleteObjects: true,
});

const dataBucket = new Bucket(this, 'DataBucket', {
  encryption: BucketEncryption.S3_MANAGED,
  blockPublicAccess: BlockPublicAccess.BLOCK_ALL, // S2
  enforceSSL: true,                               // S10
  versioned: true,
  objectOwnership: ObjectOwnership.BUCKET_OWNER_ENFORCED,
  serverAccessLogsBucket: accessLogsBucket,       // S1
  serverAccessLogsPrefix: 'data-bucket/',
  removalPolicy,
  autoDeleteObjects: true,
});
```

- `enforceSSL: true` adds a bucket policy that **denies** any request where `aws:SecureTransport` is `false`.
- `BUCKET_OWNER_ENFORCED` disables ACLs entirely; access is governed by policies only.
- The `cdk.json` feature flag `@aws-cdk/aws-s3:serverAccessLogsUseBucketPolicy` makes CDK grant log delivery through a bucket policy instead of an ACL, which is what the disabled ACLs require.

## The Trade-off

**Doesn't the logs bucket need logging of its own?** No. S1 treats a bucket that is already the access-log **destination** of another bucket as compliant, so no suppression is needed. Pointing the logs bucket at itself or at a third bucket would only add cost.

**Why SSE-S3 and not SSE-KMS?** For the data bucket, KMS would be a reasonable upgrade (the NIST and HIPAA packs ask for it). The access-logs bucket **must** stay on SSE-S3: S3 server access logging cannot deliver to a destination bucket that uses SSE-KMS default encryption.

**Why `DESTROY` + `autoDeleteObjects`?** This is a **demo-only** choice, so a sandbox deploy can be removed with `cdk destroy`. Production buckets holding real data should use `RemovalPolicy.RETAIN`. `autoDeleteObjects` adds a CDK-managed custom-resource Lambda; cdk-nag reports no findings for it.

## Verifying It

[`test/secure-stack.test.ts`](../test/secure-stack.test.ts) asserts each remediation on the synthesized template, not only that cdk-nag passes:

```typescript
test('both buckets reject requests without TLS', () => {
  template.resourcePropertiesCountIs('AWS::S3::BucketPolicy', Match.objectLike({
    PolicyDocument: Match.objectLike({
      Statement: Match.arrayWith([
        Match.objectLike({
          Effect: 'Deny',
          Action: 's3:*',
          Condition: { Bool: { 'aws:SecureTransport': 'false' } },
        }),
      ]),
    }),
  }), 2);
});
```

Other tests in the same file check the public-access block, encryption, versioning and the logging target of `DataBucket`, and the SSE-S3 encryption, versioning and 365-day expiry of `AccessLogsBucket`. Every one of them was checked by deleting the remediation and confirming the suite goes red.

## Cost & Cleanup

Two S3 buckets: storage and requests only, nothing billed while idle beyond the bytes stored. `cdk destroy` empties and deletes both.

## What's Next

[Step 2](02-iam-and-lambda.md) moves to IAM and Lambda: the hidden IAM4 in Lambda's default role, why the textbook IAM5 fix still triggers IAM5, and packaging the handler as an arm64 container image.
