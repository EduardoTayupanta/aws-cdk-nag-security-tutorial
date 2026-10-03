# Step 3: VPC — Flow Logs, Isolated Subnets, and a Closed Endpoint (VPC7 / EC23)

> Part 4 of the *AWS CDK Nag — Step-by-Step Security Tutorial* series.

[Step 2](02-iam-and-lambda.md) scoped the function's IAM. This part builds the network for the database in [Step 4](04-rds-secret-rotation.md): Flow Logs, no internet path at all, and a VPC endpoint that only one security group can reach.

## The Problem / What We're Adding

```typescript
// lib/insecure-stack.ts — AwsSolutions-VPC7: no Flow Logs
const vpc = new Vpc(this, 'AppVpc', {
  maxAzs: 2,
  natGateways: 0,
  subnetConfiguration: [{ name: 'isolated', subnetType: SubnetType.PRIVATE_ISOLATED }],
});
```

Without Flow Logs there is no record of which traffic reached, or was rejected by, anything in the VPC.

## The Design

```typescript
const vpc = new Vpc(this, 'AppVpc', {
  maxAzs: 2,
  natGateways: 0,
  subnetConfiguration: [{ name: 'isolated', subnetType: SubnetType.PRIVATE_ISOLATED }],
  flowLogs: {
    FlowLog: {
      destination: FlowLogDestination.toCloudWatchLogs(new LogGroup(this, 'VpcFlowLogGroup', {
        retention: RetentionDays.ONE_YEAR,
        removalPolicy,
      })),
    },
  },
});

const secretsManagerEndpoint = vpc.addInterfaceEndpoint('SecretsManagerEndpoint', {
  service: InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
  subnets: { subnetType: SubnetType.PRIVATE_ISOLATED },
  open: false,
});
```

- **Isolated subnets, no NAT Gateway, no Internet Gateway.** The database never needs the internet, so there is no route to it. That is cheaper and leaves a smaller attack surface than a NAT-based private subnet.
- **One interface endpoint.** The only AWS API anything in this VPC calls is Secrets Manager, from the rotation Lambda in Step 4.
- **Flow Logs** capture `ALL` traffic to an explicit log group with one-year retention.

## The Trade-off

**`open: false` on the endpoint.** By default CDK opens an interface endpoint's security group on 443 to the **whole VPC CIDR**. That has two problems:

1. It is broader than needed: only the rotation function talks to Secrets Manager.
2. The rule's source is the VPC CIDR, a CloudFormation intrinsic (`Fn::GetAtt`). `AwsSolutions-EC23` cannot evaluate it and reports *"Rule threw an error during validation"*.

With `open: false`, the endpoint starts with **no** ingress, and Step 4 opens it to exactly one security group. The fix for the evaluation error is also the more secure design.

**The catch:** a closed endpoint passes cdk-nag even if nothing is ever allowed in, and then rotation fails at runtime. cdk-nag checks for what is **excessive**, not for what is **missing**. Step 4 covers the test that catches it.

## Verifying It

From [`test/secure-stack.test.ts`](../test/secure-stack.test.ts):

```typescript
test('the VPC sends Flow Logs for all traffic to CloudWatch Logs', () => {
  template.hasResourceProperties('AWS::EC2::FlowLog', Match.objectLike({
    ResourceId: { Ref: Match.stringLikeRegexp('^AppVpc') },
    ResourceType: 'VPC',
    TrafficType: 'ALL',
    LogDestinationType: 'cloud-watch-logs',
  }));
});

test('the VPC has no NAT Gateway or Internet Gateway', () => {
  template.resourceCountIs('AWS::EC2::NatGateway', 0);
  template.resourceCountIs('AWS::EC2::InternetGateway', 0);
});
```

A third test asserts that the endpoint's security group has no inline ingress rules, so neither the VPC CIDR nor `0.0.0.0/0`, and exactly one ingress rule, from the rotation security group on 443.

## Cost & Cleanup

The **interface endpoint is billed hourly in each AZ** (two here), plus data processed, even when idle. Flow Logs bill for ingestion and storage in CloudWatch Logs. There is no NAT Gateway to pay for.

## What's Next

[Step 4](04-rds-secret-rotation.md) puts a PostgreSQL instance in these subnets: five RDS/Secrets Manager rules, a rotation function that must reach the endpoint, and a log-retention fix that avoids a custom resource.
