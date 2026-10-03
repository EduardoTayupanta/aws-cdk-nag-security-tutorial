# Step 4: RDS — Encryption, Rotation, and the Bug cdk-nag Can't See (RDS2 / RDS3 / RDS10 / RDS11 / SMG4)

> Part 5 of the *AWS CDK Nag — Step-by-Step Security Tutorial* series.

[Step 3](03-vpc-flow-logs.md) built an isolated VPC with a closed Secrets Manager endpoint. This part adds a PostgreSQL instance, fixes five findings, and shows a stack that passed every rule but would not have worked.

## The Problem / What We're Adding

A single RDS instance with default settings triggers **five** rules:

| Rule | Problem | Remediation |
|------|---------|-------------|
| RDS2  | Storage not encrypted | `storageEncrypted: true` |
| RDS3  | No Multi-AZ | `multiAz: true` |
| RDS10 | No deletion protection | `deletionProtection: true` |
| RDS11 | Default port (5432) | `port: 5433` |
| SMG4  | The password secret is never rotated | `addRotationSingleUser()` |

## The Design

```typescript
const database = new DatabaseInstance(this, 'AppDatabase', {
  instanceIdentifier: DB_INSTANCE_IDENTIFIER, // 'secure-stack-app-db'
  engine: DatabaseInstanceEngine.postgres({ version: PostgresEngineVersion.VER_17 }),
  instanceType: InstanceType.of(InstanceClass.T4G, InstanceSize.MICRO),
  allocatedStorage: 20,
  storageType: StorageType.GP3,
  vpc,
  vpcSubnets: { subnetType: SubnetType.PRIVATE_ISOLATED },
  storageEncrypted: true,   // RDS2
  deletionProtection: true, // RDS10
  multiAz: true,            // RDS3
  port: 5433,               // RDS11
  iamAuthentication: true,
  backupRetention: Duration.days(7),
  cloudwatchLogsExports: ['postgresql', 'upgrade'],
  removalPolicy,
});
```

### Rotation inside an isolated VPC

The rotation function runs **inside** the VPC, which has no internet path, so it reaches Secrets Manager through the endpoint from Step 3:

```typescript
const rotationSecurityGroup = new SecurityGroup(this, 'RotationSecurityGroup', {
  vpc,
  description: 'Rotation Lambda for the AppDatabase secret',
  allowAllOutbound: false,
});
secretsManagerEndpoint.connections.allowDefaultPortFrom(rotationSecurityGroup); // 443
database.addRotationSingleUser({
  endpoint: secretsManagerEndpoint,
  securityGroup: rotationSecurityGroup,
});
```

`allowAllOutbound: false` means CDK writes exactly two egress rules for the rotation function: to the endpoint on 443 and to the database port. Nothing else.

### Log exports with retention, without a custom resource

RDS creates its export log groups with **"Never expire"** retention. The obvious fix, `cloudwatchLogsRetention`, adds a `Custom::LogRetention` Lambda that brings **new** IAM4 and IAM5 findings. Instead, the stack fixes the instance identifier and creates the log groups itself, before the database:

```typescript
const dbLogGroups = new Construct(this, 'AppDatabaseLogGroups');
for (const logType of DB_LOG_EXPORTS) {
  database.node.addDependency(new LogGroup(dbLogGroups, logType, {
    logGroupName: `/aws/rds/instance/${DB_INSTANCE_IDENTIFIER}/${logType}`,
    retention: RetentionDays.ONE_MONTH,
    removalPolicy,
  }));
}
```

## The Trade-off

### The bug cdk-nag cannot see

The first version of this stack passed every AwsSolutions rule and synthesized cleanly, but **rotation would have failed**. The endpoint had `open: false` and no ingress rule at all: the rotation function could not reach Secrets Manager.

The `endpoint` option of `addRotationSingleUser` looks like it should handle this. It **only changes the URL** the function calls (`https://<vpce-id>.secretsmanager.<region>.amazonaws.com`); it does not touch the endpoint's security group. The `allowDefaultPortFrom` line above is what actually opens the path.

cdk-nag flags permissions that are too **open**. A path that is missing looks, to a static checker, exactly like a secure one. It was a `Template` assertion that caught it:

```typescript
template.hasResourceProperties('AWS::EC2::SecurityGroupIngress', Match.objectLike({
  GroupId: { 'Fn::GetAtt': [endpointSgId, 'GroupId'] },
  IpProtocol: 'tcp',
  FromPort: 443,
  ToPort: 443,
  SourceSecurityGroupId: { 'Fn::GetAtt': [Match.stringLikeRegexp('^RotationSecurityGroup'), 'GroupId'] },
}));
```

### Other choices

- **Port obfuscation (RDS11)** is defense in depth against untargeted scans, not a security boundary. It costs nothing here.
- **A fixed `instanceIdentifier`** makes the log group names predictable. The price is that the stack can be deployed only once per account and Region.
- **Deletion protection with `RemovalPolicy.DESTROY`.** `DESTROY` is a demo-only choice so teardown leaves nothing behind. Deletion protection stays on, because it is the RDS10 lesson. Teardown therefore needs one extra command, documented in the README's [Tear It Down](../README.md#tear-it-down) section.

## Verifying It

[`test/secure-stack.test.ts`](../test/secure-stack.test.ts) asserts:

- encryption, Multi-AZ, deletion protection, port 5433, IAM authentication, 7-day backups, 20 GB gp3, and both log exports;
- each export log group exists with 30-day retention and the database `DependsOn` it;
- the rotation schedule (`rate(30 days)`) and that the rotation application uses `RotationSecurityGroup`;
- the endpoint's single ingress rule (above), and that the rotation security group has no `0.0.0.0/0` egress, only the two explicit rules.

## Cost & Cleanup

This is the expensive part of the stack: **RDS Multi-AZ** (`db.t4g.micro` × 2 plus 20 GB gp3 per AZ) is billed hourly, even when idle. The rotation function bills per invocation. Tear it down as soon as you are done.

## What's Next

[Step 5](05-suppressions-testing-ci.md) looks at the two acknowledged findings in detail: how `acknowledge()` scopes work, how the tests prove each remediation, and the CI pipeline that keeps it all green.
