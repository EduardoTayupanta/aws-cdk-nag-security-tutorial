import { Match, Template } from 'aws-cdk-lib/assertions';
import { READABLE_PREFIX, SecureStack } from '../lib/secure-stack';
import { nagAcknowledgmentsIn, newTestApp, runAwsSolutions } from './helpers';

describe('SecureStack', () => {
  const stack = new SecureStack(newTestApp(), 'SecureStack');
  const template = Template.fromStack(stack);

  // ── cdk-nag ──────────────────────────────────────────────────────────────

  test('passes the AWS Solutions (cdk-nag) rule pack with no violations', () => {
    const report = runAwsSolutions(stack);
    if (!report.success) {
      // Fail with the actual violations, not just "false !== true".
      throw new Error(`AwsSolutions violations:\n${JSON.stringify(report.violations, null, 2)}`);
    }
    expect(report.success).toBe(true);
  });

  test('has exactly ONE suppression, scoped to the IAM5 finding for the uploads/ prefix', () => {
    // If someone adds another suppression, this test forces it to be reviewed here.
    const acks = nagAcknowledgmentsIn(stack);
    expect(acks).toEqual([
      {
        path: 'SecureStack/AppRole',
        id: expect.stringMatching(/^AwsSolutions-IAM5\[Resource::<DataBucket[0-9A-F]{8}\.Arn>\/uploads\/\*\]$/),
        reason: expect.any(String),
      },
    ]);
    expect(acks[0].reason.length).toBeGreaterThan(80);
  });

  // ── S3: S1 / S2 / S10 ───────────────────────────────────────────────────

  test('the data bucket blocks public access, is encrypted, and sends access logs to the logs bucket', () => {
    template.hasResourceProperties('AWS::S3::Bucket', Match.objectLike({
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true,
      },
      BucketEncryption: Match.objectLike({
        ServerSideEncryptionConfiguration: [
          Match.objectLike({ ServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } }),
        ],
      }),
      LoggingConfiguration: {
        DestinationBucketName: { Ref: Match.stringLikeRegexp('^AccessLogsBucket') },
        LogFilePrefix: 'data-bucket/',
      },
    }));
  });

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

  // ── IAM: IAM4 / IAM5 ────────────────────────────────────────────────────

  test('the app role has no AWS managed policies', () => {
    template.hasResourceProperties('AWS::IAM::Role', Match.objectLike({
      AssumeRolePolicyDocument: Match.objectLike({
        Statement: [Match.objectLike({ Principal: { Service: 'lambda.amazonaws.com' } })],
      }),
      ManagedPolicyArns: Match.absent(),
    }));
  });

  test(`the role can only call s3:GetObject under ${READABLE_PREFIX}`, () => {
    template.hasResourceProperties('AWS::IAM::Policy', Match.objectLike({
      Roles: [{ Ref: Match.stringLikeRegexp('^AppRole') }],
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          {
            Sid: 'ReadUploadsPrefixOnly',
            Effect: 'Allow',
            Action: 's3:GetObject',
            Resource: {
              'Fn::Join': ['', [
                { 'Fn::GetAtt': [Match.stringLikeRegexp('^DataBucket'), 'Arn'] },
                `/${READABLE_PREFIX}*`,
              ]],
            },
          },
        ]),
      }),
    }));
  });

  test('no policy in the stack grants service-wide wildcard actions (e.g. s3:*)', () => {
    const policies = template.findResources('AWS::IAM::Policy');
    const actions = Object.values(policies).flatMap((p) =>
      p.Properties.PolicyDocument.Statement.flatMap((s: { Action: string | string[] }) => [s.Action].flat()),
    );
    expect(actions.filter((a) => a.endsWith(':*') || a === '*')).toEqual([]);
  });

  // ── Lambda: L1 ──────────────────────────────────────────────────────────

  test('ReaderFunction uses the latest Node.js runtime and its own log group', () => {
    template.hasResourceProperties('AWS::Lambda::Function', Match.objectLike({
      Runtime: 'nodejs24.x',
      Role: { 'Fn::GetAtt': [Match.stringLikeRegexp('^AppRole'), 'Arn'] },
      LoggingConfig: { LogGroup: { Ref: Match.stringLikeRegexp('^ReaderLogGroup') } },
    }));
  });

  // ── VPC: VPC7 ───────────────────────────────────────────────────────────

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

  test('the Secrets Manager endpoint only accepts traffic from the rotation Lambda (EC23)', () => {
    // No CIDR-based ingress rules: neither the whole VPC nor 0.0.0.0/0.
    const endpointSgs = template.findResources('AWS::EC2::SecurityGroup', {
      Properties: { GroupDescription: Match.stringLikeRegexp('SecretsManagerEndpoint') },
    });
    const [endpointSgId] = Object.keys(endpointSgs);
    expect(endpointSgs[endpointSgId].Properties.SecurityGroupIngress).toBeUndefined();

    // Regression: without this rule rotation fails at runtime (it cannot reach
    // Secrets Manager), and neither cdk-nag nor synth catches it.
    template.resourcePropertiesCountIs('AWS::EC2::SecurityGroupIngress', Match.objectLike({
      GroupId: { 'Fn::GetAtt': [endpointSgId, 'GroupId'] },
    }), 1);
    template.hasResourceProperties('AWS::EC2::SecurityGroupIngress', Match.objectLike({
      GroupId: { 'Fn::GetAtt': [endpointSgId, 'GroupId'] },
      IpProtocol: 'tcp',
      FromPort: 443,
      ToPort: 443,
      SourceSecurityGroupId: { 'Fn::GetAtt': [Match.stringLikeRegexp('^RotationSecurityGroup'), 'GroupId'] },
    }));
    template.hasResourceProperties('AWS::Serverless::Application', Match.objectLike({
      Parameters: Match.objectLike({
        vpcSecurityGroupIds: { 'Fn::GetAtt': [Match.stringLikeRegexp('^RotationSecurityGroup'), 'GroupId'] },
      }),
    }));
  });

  // ── RDS: RDS2 / RDS3 / RDS10 / RDS11 / SMG4 ─────────────────────────────

  test('the database is encrypted, deletion-protected, Multi-AZ, and on a non-standard port', () => {
    template.hasResourceProperties('AWS::RDS::DBInstance', Match.objectLike({
      StorageEncrypted: true,
      DeletionProtection: true,
      MultiAZ: true,
      Port: '5433',
      EnableIAMDatabaseAuthentication: true,
      BackupRetentionPeriod: 7,
      EnableCloudwatchLogsExports: ['postgresql'],
      PubliclyAccessible: false,
    }));
  });

  test('the database master password rotates automatically', () => {
    template.hasResourceProperties('AWS::SecretsManager::RotationSchedule', Match.objectLike({
      SecretId: { Ref: Match.stringLikeRegexp('^AppDatabaseSecret') },
      RotationRules: Match.objectLike({ ScheduleExpression: 'rate(30 days)' }),
    }));
  });
});
