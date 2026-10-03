import { Construct } from 'constructs';
import { CfnOutput, Duration, RemovalPolicy, Stack, StackProps, Validations } from 'aws-cdk-lib/core';
import { BlockPublicAccess, Bucket, BucketEncryption, CfnBucket, ObjectOwnership } from 'aws-cdk-lib/aws-s3';
import { PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import {
  FlowLogDestination,
  InstanceClass,
  InstanceSize,
  InstanceType,
  InterfaceVpcEndpointAwsService,
  SecurityGroup,
  SubnetType,
  Vpc,
} from 'aws-cdk-lib/aws-ec2';
import { DatabaseInstance, DatabaseInstanceEngine, PostgresEngineVersion, StorageType } from 'aws-cdk-lib/aws-rds';
import { ReaderFunction } from './constructs/reader-function';

/** Bucket prefix the Lambda can read; nothing outside it. */
export const READABLE_PREFIX = 'uploads/';

/**
 * Fixed DB identifier, so the CloudWatch log groups RDS exports to have
 * predictable names and can be created (with retention) by this stack.
 */
export const DB_INSTANCE_IDENTIFIER = 'secure-stack-app-db';

/** PostgreSQL log types exported to CloudWatch Logs. */
const DB_LOG_EXPORTS = ['postgresql', 'upgrade'];

/**
 * The tutorial's "AFTER": the same resources as `InsecureStack`, with the same
 * construct IDs, remediated to pass cdk-nag's AwsSolutions rule pack.
 *
 * Two acknowledged exceptions remain (`Validations.of(...).acknowledge`), each
 * scoped to one exact finding with its justification next to the resource:
 * the `uploads/` prefix (below) and X-Ray's `Resource: "*"` (in
 * `ReaderFunction`). Everything else is fixed instead of suppressed.
 *
 * Demo-only choice: everything uses `RemovalPolicy.DESTROY` (and buckets
 * auto-delete their objects) so a sandbox deploy can be torn down cleanly.
 * Production data stores would use `RETAIN` / `SNAPSHOT`. Deletion
 * protection stays on for the database, because that IS the RDS10 lesson;
 * see the README's "Tear It Down" section.
 */
export class SecureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const removalPolicy = RemovalPolicy.DESTROY;

    // ── S3: AwsSolutions-S1 / S2 / S10 ────────────────────────────────────
    // The logs bucket does not need logging itself: rule S1 treats a bucket
    // that is already an access-log destination as compliant. It must use
    // SSE-S3: S3 server access logging cannot deliver to an SSE-KMS bucket.
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
      enforceSSL: true, // S10
      versioned: true,
      objectOwnership: ObjectOwnership.BUCKET_OWNER_ENFORCED,
      serverAccessLogsBucket: accessLogsBucket, // S1
      serverAccessLogsPrefix: 'data-bucket/',
      removalPolicy,
      autoDeleteObjects: true,
    });

    // ── IAM: AwsSolutions-IAM4 / IAM5 ─────────────────────────────────────
    // A dedicated role instead of Lambda's default one: this avoids attaching
    // the AWSLambdaBasicExecutionRole managed policy (IAM4). ReaderFunction
    // scopes its log permissions to ONE specific log group.
    const appRole = new Role(this, 'AppRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'ReaderFunction role: read uploads/, write its own log group, send X-Ray traces.',
    });

    // A single action on a single prefix. `bucket.grantRead()` would also add
    // s3:GetObject*, s3:GetBucket* and s3:List* (more IAM5 findings to
    // justify); this function only needs to read objects.
    appRole.addToPolicy(new PolicyStatement({
      sid: 'ReadUploadsPrefixOnly',
      actions: ['s3:GetObject'],
      resources: [dataBucket.arnForObjects(`${READABLE_PREFIX}*`)],
    }));

    // One of the stack's two exceptions (the other, X-Ray's Resource "*", is in
    // ReaderFunction). In cdk-nag 3.x each finding is acknowledged separately
    // by its full `Rule[Finding]` ID, so a wildcard on any OTHER resource or
    // action is reported again. But it also silently covers a NEW action on
    // this same resource (e.g. s3:DeleteObject on uploads/*), which is why
    // test/secure-stack.test.ts pins AppRole's exact statement list.
    Validations.of(appRole).acknowledge({
      id: `AwsSolutions-IAM5[Resource::<${this.getLogicalId(dataBucket.node.defaultChild as CfnBucket)}.Arn>/${READABLE_PREFIX}*]`,
      reason:
        'The "*" is the deliberate prefix scope: the function can only call s3:GetObject ' +
        `on objects under ${READABLE_PREFIX} in this bucket. S3 object keys are created at runtime ` +
        'and cannot be enumerated in advance, so a prefix is the narrowest possible scope for ' +
        'object reads.',
    });

    // ── Lambda: AwsSolutions-L1 ───────────────────────────────────────────
    // A container image (arm64, Node.js 22 base image): L1 only applies to
    // zip-packaged functions, and the runtime version is now the base image
    // tag in lambda/reader/Dockerfile, kept current by Dependabot.
    const reader = new ReaderFunction(this, 'ReaderFunction', {
      role: appRole,
      environment: { BUCKET_NAME: dataBucket.bucketName, READ_PREFIX: READABLE_PREFIX },
      removalPolicy,
    });

    // ── VPC: AwsSolutions-VPC7 ────────────────────────────────────────────
    // Isolated subnets only and no NAT Gateway: the database does not need
    // internet egress. The only thing it must reach is Secrets Manager (for
    // credential rotation), through a VPC endpoint.
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
    // `open: false` skips the default ingress rule (the whole VPC CIDR); it is
    // opened below to the rotation Lambda only (AwsSolutions-EC23).
    const secretsManagerEndpoint = vpc.addInterfaceEndpoint('SecretsManagerEndpoint', {
      service: InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
      subnets: { subnetType: SubnetType.PRIVATE_ISOLATED },
      open: false,
    });

    // ── RDS: AwsSolutions-RDS2 / RDS10 (+ RDS3, RDS11, SMG4) ──────────────
    const database = new DatabaseInstance(this, 'AppDatabase', {
      instanceIdentifier: DB_INSTANCE_IDENTIFIER,
      engine: DatabaseInstanceEngine.postgres({ version: PostgresEngineVersion.VER_17 }),
      instanceType: InstanceType.of(InstanceClass.T4G, InstanceSize.MICRO),
      allocatedStorage: 20,
      storageType: StorageType.GP3,
      vpc,
      vpcSubnets: { subnetType: SubnetType.PRIVATE_ISOLATED },
      storageEncrypted: true, // RDS2
      deletionProtection: true, // RDS10
      multiAz: true, // RDS3
      port: 5433, // RDS11: non-default port (default is 5432)
      iamAuthentication: true,
      backupRetention: Duration.days(7),
      cloudwatchLogsExports: DB_LOG_EXPORTS,
      removalPolicy,
    });

    // RDS creates its export log groups with "Never expire" retention. Creating
    // them here first sets a retention period without `cloudwatchLogsRetention`,
    // whose Custom::LogRetention Lambda would add new IAM4/IAM5 findings.
    const dbLogGroups = new Construct(this, 'AppDatabaseLogGroups');
    for (const logType of DB_LOG_EXPORTS) {
      database.node.addDependency(new LogGroup(dbLogGroups, logType, {
        logGroupName: `/aws/rds/instance/${DB_INSTANCE_IDENTIFIER}/${logType}`,
        retention: RetentionDays.ONE_MONTH,
        removalPolicy,
      }));
    }
    // SMG4: automatic rotation of the master password.
    // The rotation Lambda runs in the VPC with its own security group, and the
    // Secrets Manager endpoint is opened (443) ONLY to that security group.
    // `allowAllOutbound: false`: CDK then adds exactly two egress rules, to the
    // endpoint (443) and to the database port; nothing else.
    // Note: the `endpoint` option only changes the URL the Lambda uses; it does
    // not open the endpoint's security group, which is why the rule is added here.
    const rotationSecurityGroup = new SecurityGroup(this, 'RotationSecurityGroup', {
      vpc,
      description: 'Rotation Lambda for the AppDatabase secret',
      allowAllOutbound: false,
    });
    secretsManagerEndpoint.connections.allowDefaultPortFrom(rotationSecurityGroup);
    database.addRotationSingleUser({
      endpoint: secretsManagerEndpoint,
      securityGroup: rotationSecurityGroup,
    });

    // ── Outputs for the end-to-end walkthrough (README, "Try It End to End") ──
    new CfnOutput(this, 'DataBucketName', { value: dataBucket.bucketName });
    new CfnOutput(this, 'ReaderFunctionName', { value: reader.fn.functionName });
    new CfnOutput(this, 'DatabaseInstanceIdentifier', { value: DB_INSTANCE_IDENTIFIER });
    new CfnOutput(this, 'DatabaseSecretArn', { value: database.secret!.secretArn });
  }
}
