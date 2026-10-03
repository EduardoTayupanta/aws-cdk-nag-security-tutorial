import { RemovalPolicy, Stack } from 'aws-cdk-lib/core';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { ReaderFunction } from '../../lib/constructs/reader-function';
import { nagAcknowledgmentsIn, newTestApp, runAwsSolutions } from '../helpers';

function build(removalPolicy?: RemovalPolicy) {
  const stack = new Stack(newTestApp(), 'TestStack');
  const role = new Role(stack, 'Role', { assumedBy: new ServicePrincipal('lambda.amazonaws.com') });
  new ReaderFunction(stack, 'ReaderFunction', {
    role,
    environment: { BUCKET_NAME: 'my-bucket', READ_PREFIX: 'uploads/' },
    removalPolicy,
  });
  return { stack, template: Template.fromStack(stack) };
}

describe('ReaderFunction', () => {
  describe('with default props', () => {
    const { stack, template } = build();

    test('is an arm64 container-image function with active X-Ray tracing', () => {
      template.hasResourceProperties('AWS::Lambda::Function', Match.objectLike({
        PackageType: 'Image',
        Architectures: ['arm64'],
        TracingConfig: { Mode: 'Active' },
        MemorySize: 256,
        Timeout: 10,
        Role: { 'Fn::GetAtt': [Match.stringLikeRegexp('^Role'), 'Arn'] },
        LoggingConfig: { LogGroup: { Ref: Match.stringLikeRegexp('^ReaderFunctionLogGroup') } },
        Environment: { Variables: { BUCKET_NAME: 'my-bucket', READ_PREFIX: 'uploads/' } },
      }));
    });

    test('has its own log group, retained by default, with one-month retention', () => {
      template.hasResource('AWS::Logs::LogGroup', {
        Properties: { RetentionInDays: 30 },
        DeletionPolicy: 'Retain',
      });
    });

    test('grants the role exactly: write to its own log group, and X-Ray', () => {
      template.hasResourceProperties('AWS::IAM::Policy', {
        Roles: [{ Ref: Match.stringLikeRegexp('^Role') }],
        PolicyDocument: Match.objectLike({
          Statement: [
            {
              Effect: 'Allow',
              Action: ['logs:CreateLogStream', 'logs:PutLogEvents'],
              Resource: { 'Fn::GetAtt': [Match.stringLikeRegexp('^ReaderFunctionLogGroup'), 'Arn'] },
            },
            {
              Effect: 'Allow',
              Action: ['xray:PutTelemetryRecords', 'xray:PutTraceSegments'],
              Resource: '*',
            },
          ],
        }),
      });
    });

    test('passes cdk-nag, with only the X-Ray Resource "*" acknowledged', () => {
      const report = runAwsSolutions(stack);
      if (!report.success) {
        throw new Error(`AwsSolutions violations:\n${JSON.stringify(report.violations, null, 2)}`);
      }
      expect(nagAcknowledgmentsIn(stack)).toEqual([
        expect.objectContaining({ path: 'TestStack/Role', id: 'AwsSolutions-IAM5[Resource::*]' }),
      ]);
    });
  });

  test('applies an explicit removal policy to its log group', () => {
    const { template } = build(RemovalPolicy.DESTROY);
    template.hasResource('AWS::Logs::LogGroup', { DeletionPolicy: 'Delete' });
  });
});
