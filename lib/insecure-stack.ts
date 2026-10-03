import { Construct } from 'constructs';
import { RemovalPolicy, Stack, StackProps } from 'aws-cdk-lib/core';
import { BlockPublicAccess, Bucket } from 'aws-cdk-lib/aws-s3';
import { ManagedPolicy, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Code, Function, Runtime } from 'aws-cdk-lib/aws-lambda';
import { InstanceClass, InstanceSize, InstanceType, SubnetType, Vpc } from 'aws-cdk-lib/aws-ec2';
import { DatabaseInstance, DatabaseInstanceEngine, PostgresEngineVersion } from 'aws-cdk-lib/aws-rds';

/**
 * The tutorial's "BEFORE": a stack with the most common security flaws written
 * ON PURPOSE, to show how cdk-nag reports them.
 *
 * ⚠️ Not meant to be deployed. `bin/app.ts` only adds it to the App when
 * `-c includeInsecure=true` is passed, so the default `cdk synth` (and the CI
 * pipeline) stays green.
 *
 * Each block is tagged with the rules it triggers; `test/insecure-stack.test.ts`
 * verifies that cdk-nag actually reports them, and `lib/secure-stack.ts` shows
 * the remediation for each one under the same construct ID.
 */
export class InsecureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // AwsSolutions-S1  → no server access logging
    // AwsSolutions-S2  → public access not blocked
    // AwsSolutions-S10 → TLS not enforced (aws:SecureTransport)
    const dataBucket = new Bucket(this, 'DataBucket', {
      blockPublicAccess: new BlockPublicAccess({
        blockPublicAcls: false,
        blockPublicPolicy: false,
        ignorePublicAcls: false,
        restrictPublicBuckets: false,
      }),
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // AwsSolutions-IAM4 → overly broad AWS managed policy
    // AwsSolutions-IAM5 → wildcards in Action (s3:*) and Resource (*)
    const appRole = new Role(this, 'AppRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
    });
    appRole.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName('AmazonS3FullAccess'));
    appRole.addToPolicy(new PolicyStatement({ actions: ['s3:*'], resources: ['*'] }));

    // AwsSolutions-L1 → runtime is not the latest in its family
    new Function(this, 'ReaderFunction', {
      runtime: Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: Code.fromInline('exports.handler = async () => ({ statusCode: 200 });'),
      role: appRole,
      environment: { BUCKET_NAME: dataBucket.bucketName },
    });

    // AwsSolutions-VPC7 → VPC without Flow Logs
    const vpc = new Vpc(this, 'AppVpc', {
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [{ name: 'isolated', subnetType: SubnetType.PRIVATE_ISOLATED }],
    });

    // AwsSolutions-RDS2  → unencrypted storage
    // AwsSolutions-RDS10 → no deletion protection
    // (also triggers RDS3, RDS11, RDS13, SMG4… see the README)
    new DatabaseInstance(this, 'AppDatabase', {
      engine: DatabaseInstanceEngine.postgres({ version: PostgresEngineVersion.VER_17 }),
      instanceType: InstanceType.of(InstanceClass.T4G, InstanceSize.MICRO),
      vpc,
      vpcSubnets: { subnetType: SubnetType.PRIVATE_ISOLATED },
      storageEncrypted: false,
      deletionProtection: false,
      removalPolicy: RemovalPolicy.DESTROY,
    });
  }
}
