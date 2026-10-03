import { Match, Template } from 'aws-cdk-lib/assertions';
import { READABLE_PREFIX, SecureStack } from '../lib/secure-stack';
import { nagAcknowledgmentsIn, newTestApp, runAwsSolutions } from './helpers';

describe('SecureStack', () => {
  const stack = new SecureStack(newTestApp(), 'SecureStack');
  const template = Template.fromStack(stack);

  // ── cdk-nag ──────────────────────────────────────────────────────────────

  test('pasa el paquete AwsSolutions (cdk-nag) sin violaciones', () => {
    const report = runAwsSolutions(stack);
    if (!report.success) {
      // Fallar mostrando las violaciones reales, no solo "false !== true".
      throw new Error(`Violaciones AwsSolutions:\n${JSON.stringify(report.violations, null, 2)}`);
    }
    expect(report.success).toBe(true);
  });

  test('tiene UNA sola supresión, acotada al hallazgo IAM5 del prefijo uploads/', () => {
    // Si alguien agrega otra supresión, este test obliga a revisarla aquí.
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

  test('el bucket de datos bloquea acceso público, cifra y envía access logs al bucket de logs', () => {
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

  test('ambos buckets rechazan peticiones sin TLS', () => {
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

  test('el rol de la app no tiene políticas administradas de AWS', () => {
    template.hasResourceProperties('AWS::IAM::Role', Match.objectLike({
      AssumeRolePolicyDocument: Match.objectLike({
        Statement: [Match.objectLike({ Principal: { Service: 'lambda.amazonaws.com' } })],
      }),
      ManagedPolicyArns: Match.absent(),
    }));
  });

  test(`el rol solo puede hacer s3:GetObject bajo ${READABLE_PREFIX}`, () => {
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

  test('ninguna política del stack concede acciones con wildcard de servicio (p. ej. s3:*)', () => {
    const policies = template.findResources('AWS::IAM::Policy');
    const actions = Object.values(policies).flatMap((p) =>
      p.Properties.PolicyDocument.Statement.flatMap((s: { Action: string | string[] }) => [s.Action].flat()),
    );
    expect(actions.filter((a) => a.endsWith(':*') || a === '*')).toEqual([]);
  });

  // ── Lambda: L1 ──────────────────────────────────────────────────────────

  test('ReaderFunction usa el runtime Node.js más reciente y su propio log group', () => {
    template.hasResourceProperties('AWS::Lambda::Function', Match.objectLike({
      Runtime: 'nodejs24.x',
      Role: { 'Fn::GetAtt': [Match.stringLikeRegexp('^AppRole'), 'Arn'] },
      LoggingConfig: { LogGroup: { Ref: Match.stringLikeRegexp('^ReaderLogGroup') } },
    }));
  });

  // ── VPC: VPC7 ───────────────────────────────────────────────────────────

  test('la VPC envía Flow Logs de todo el tráfico a CloudWatch Logs', () => {
    template.hasResourceProperties('AWS::EC2::FlowLog', Match.objectLike({
      ResourceId: { Ref: Match.stringLikeRegexp('^AppVpc') },
      ResourceType: 'VPC',
      TrafficType: 'ALL',
      LogDestinationType: 'cloud-watch-logs',
    }));
  });

  test('la VPC no tiene NAT Gateway ni Internet Gateway', () => {
    template.resourceCountIs('AWS::EC2::NatGateway', 0);
    template.resourceCountIs('AWS::EC2::InternetGateway', 0);
  });

  test('el endpoint de Secrets Manager solo acepta tráfico desde la Lambda de rotación (EC23)', () => {
    // Sin reglas de entrada por CIDR: ni la VPC entera ni 0.0.0.0/0.
    const endpointSgs = template.findResources('AWS::EC2::SecurityGroup', {
      Properties: { GroupDescription: Match.stringLikeRegexp('SecretsManagerEndpoint') },
    });
    const [endpointSgId] = Object.keys(endpointSgs);
    expect(endpointSgs[endpointSgId].Properties.SecurityGroupIngress).toBeUndefined();

    // Regresión: sin esta regla la rotación falla en runtime (no puede llamar
    // a Secrets Manager) y ni cdk-nag ni el synth lo detectan.
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

  test('la base de datos está cifrada, protegida contra borrado, en Multi-AZ y en un puerto no estándar', () => {
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

  test('la contraseña maestra de la base de datos rota automáticamente', () => {
    template.hasResourceProperties('AWS::SecretsManager::RotationSchedule', Match.objectLike({
      SecretId: { Ref: Match.stringLikeRegexp('^AppDatabaseSecret') },
      RotationRules: Match.objectLike({ ScheduleExpression: 'rate(30 days)' }),
    }));
  });
});
