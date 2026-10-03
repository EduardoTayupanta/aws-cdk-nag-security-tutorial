import { Match, Template } from 'aws-cdk-lib/assertions';
import { DB_INSTANCE_IDENTIFIER, READABLE_PREFIX, SecureStack } from '../lib/secure-stack';
import { nagAcknowledgmentsIn, newTestApp, runAwsSolutions } from './helpers';

describe('SecureStack', () => {
  const stack = new SecureStack(newTestApp(), 'SecureStack');
  const template = Template.fromStack(stack);

  /** Every statement in the policies attached to AppRole. */
  const appRoleStatements = () => Object.values(template.findResources('AWS::IAM::Policy', {
    Properties: { Roles: [{ Ref: Match.stringLikeRegexp('^AppRole') }] },
  })).flatMap((p) => p.Properties.PolicyDocument.Statement);

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
    // The reason must name what it justifies, not just exist.
    expect(acks[0].reason).toMatch(/s3:GetObject/);
    expect(acks[0].reason).toContain(READABLE_PREFIX);
  });

  // ── S3: S1 / S2 / S10 ───────────────────────────────────────────────────

  test('the data bucket blocks public access, is encrypted, versioned, and sends access logs to the logs bucket', () => {
    template.hasResourceProperties('AWS::S3::Bucket', Match.objectLike({
      VersioningConfiguration: { Status: 'Enabled' },
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

  test('the access-logs bucket uses SSE-S3 (required for log delivery), is versioned, and expires logs', () => {
    template.hasResourceProperties('AWS::S3::Bucket', Match.objectLike({
      LoggingConfiguration: Match.absent(),
      VersioningConfiguration: { Status: 'Enabled' },
      BucketEncryption: Match.objectLike({
        ServerSideEncryptionConfiguration: [
          Match.objectLike({ ServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } }),
        ],
      }),
      LifecycleConfiguration: {
        Rules: [Match.objectLike({ Id: 'expire-access-logs', ExpirationInDays: 365, Status: 'Enabled' })],
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

  test('s3:GetObject on that prefix is the ONLY S3 permission AppRole has', () => {
    // The IAM5 acknowledgment is keyed to the resource, so it would also hide
    // a new action on uploads/* (e.g. s3:DeleteObject). This test does not.
    const s3Statements = appRoleStatements().filter((st) =>
      [st.Action].flat().some((a: string) => a.startsWith('s3:')));
    expect(s3Statements).toEqual([
      expect.objectContaining({ Sid: 'ReadUploadsPrefixOnly', Action: 's3:GetObject' }),
    ]);
  });

  test('AppRole can write to ReaderLogGroup, and only to it', () => {
    // Regression: without grantWrite the function cannot log at runtime, and
    // neither cdk-nag nor synth notices.
    const logStatements = appRoleStatements().filter((st) =>
      [st.Action].flat().some((a: string) => a.startsWith('logs:')));
    expect(logStatements).toEqual([
      expect.objectContaining({
        Effect: 'Allow',
        Action: expect.arrayContaining(['logs:CreateLogStream', 'logs:PutLogEvents']),
        Resource: { 'Fn::GetAtt': [expect.stringMatching(/^ReaderLogGroup/), 'Arn'] },
      }),
    ]);
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
      Environment: {
        Variables: {
          BUCKET_NAME: { Ref: Match.stringLikeRegexp('^DataBucket') },
          READ_PREFIX: READABLE_PREFIX,
        },
      },
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
    expect(Object.keys(endpointSgs)).toHaveLength(1);
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

  test('the rotation security group only allows egress to the endpoint and the database', () => {
    const rotationSgs = template.findResources('AWS::EC2::SecurityGroup', {
      Properties: { GroupDescription: 'Rotation Lambda for the AppDatabase secret' },
    });
    expect(Object.keys(rotationSgs)).toHaveLength(1);
    const [rotationSgId] = Object.keys(rotationSgs);

    // allowAllOutbound: false → no inline 0.0.0.0/0 egress rule, only one
    // explicit egress rule per allowed target.
    expect(rotationSgs[rotationSgId].Properties.SecurityGroupEgress).toBeUndefined();
    const egress = Object.values(template.findResources('AWS::EC2::SecurityGroupEgress', {
      Properties: { GroupId: { 'Fn::GetAtt': [rotationSgId, 'GroupId'] } },
    })).map((r) => r.Properties.DestinationSecurityGroupId['Fn::GetAtt'][0]);
    expect(egress.sort()).toEqual([
      expect.stringMatching(/^AppDatabaseSecurityGroup/),
      expect.stringMatching(/^AppVpcSecretsManagerEndpointSecurityGroup/),
    ]);
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
      EnableCloudwatchLogsExports: ['postgresql', 'upgrade'],
      PubliclyAccessible: false,
      AllocatedStorage: '20',
      StorageType: 'gp3',
    }));
  });

  test.each(['postgresql', 'upgrade'])('the exported %s log group exists before the database, with retention', (logType) => {
    const logGroups = template.findResources('AWS::Logs::LogGroup', {
      Properties: { LogGroupName: `/aws/rds/instance/${DB_INSTANCE_IDENTIFIER}/${logType}` },
    });
    expect(Object.keys(logGroups)).toHaveLength(1);
    const [logGroupId] = Object.keys(logGroups);
    expect(logGroups[logGroupId].Properties.RetentionInDays).toBe(30);

    // RDS would otherwise create it first, with "Never expire" retention.
    template.hasResource('AWS::RDS::DBInstance', {
      Properties: Match.objectLike({ DBInstanceIdentifier: DB_INSTANCE_IDENTIFIER }),
      DependsOn: Match.arrayWith([logGroupId]),
    });
  });

  test('the database master password rotates automatically', () => {
    template.hasResourceProperties('AWS::SecretsManager::RotationSchedule', Match.objectLike({
      SecretId: { Ref: Match.stringLikeRegexp('^AppDatabaseSecret') },
      RotationRules: Match.objectLike({ ScheduleExpression: 'rate(30 days)' }),
    }));
  });
});
