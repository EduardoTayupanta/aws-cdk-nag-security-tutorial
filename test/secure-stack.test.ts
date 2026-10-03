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

  test('has exactly TWO suppressions, each scoped to one IAM5 finding on AppRole', () => {
    // If someone adds another suppression, this test forces it to be reviewed here.
    const acks = nagAcknowledgmentsIn(stack);
    expect(acks).toEqual([
      {
        path: 'SecureStack/AppRole',
        id: expect.stringMatching(/^AwsSolutions-IAM5\[Resource::<DataBucket[0-9A-F]{8}\.Arn>\/uploads\/\*\]$/),
        reason: expect.any(String),
      },
      {
        path: 'SecureStack/AppRole',
        id: 'AwsSolutions-IAM5[Resource::*]',
        reason: expect.any(String),
      },
    ]);
    // Each reason must name what it justifies, not just exist.
    expect(acks[0].reason).toMatch(/s3:GetObject/);
    expect(acks[0].reason).toContain(READABLE_PREFIX);
    expect(acks[1].reason).toMatch(/xray:PutTraceSegments/);
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

  test('AppRole has exactly three statements: the S3 read, its log group, and X-Ray', () => {
    // The two acknowledgments are keyed to resources (uploads/* and "*"), so
    // they would also hide any NEW action on those resources. Pinning the full
    // statement list makes such a change fail here instead.
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

  test('no policy in the stack grants service-wide wildcard actions (e.g. s3:*)', () => {
    const policies = template.findResources('AWS::IAM::Policy');
    const actions = Object.values(policies).flatMap((p) =>
      p.Properties.PolicyDocument.Statement.flatMap((s: { Action: string | string[] }) => [s.Action].flat()),
    );
    expect(actions.filter((a) => a.endsWith(':*') || a === '*')).toEqual([]);
  });

  // ── Lambda: L1 (container image) ────────────────────────────────────────
  // The function's own properties are covered in test/constructs/reader-function.test.ts;
  // here: that the stack wires it to AppRole and the right bucket/prefix.

  test('ReaderFunction runs as AppRole and reads DataBucket under the readable prefix', () => {
    template.hasResourceProperties('AWS::Lambda::Function', Match.objectLike({
      PackageType: 'Image',
      Role: { 'Fn::GetAtt': [Match.stringLikeRegexp('^AppRole'), 'Arn'] },
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

  // ── Demo-only teardown + walkthrough outputs ────────────────────────────

  test('demo stack: buckets auto-delete, every bucket/log group/DB is DESTROY', () => {
    template.resourceCountIs('Custom::S3AutoDeleteObjects', 2);
    for (const type of ['AWS::S3::Bucket', 'AWS::Logs::LogGroup', 'AWS::RDS::DBInstance']) {
      const policies = Object.values(template.findResources(type)).map((r) => r.DeletionPolicy);
      expect(policies.length).toBeGreaterThan(0);
      expect(policies).toEqual(policies.map(() => 'Delete'));
    }
  });

  test('exposes the outputs the README walkthrough uses', () => {
    template.hasOutput('DataBucketName', { Value: { Ref: Match.stringLikeRegexp('^DataBucket') } });
    template.hasOutput('ReaderFunctionName', { Value: { Ref: Match.stringLikeRegexp('^ReaderFunction') } });
    template.hasOutput('DatabaseInstanceIdentifier', { Value: DB_INSTANCE_IDENTIFIER });
    template.hasOutput('DatabaseSecretArn', { Value: { Ref: Match.stringLikeRegexp('^AppDatabaseSecret') } });
  });
});
