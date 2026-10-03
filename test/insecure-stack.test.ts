import { InsecureStack } from '../lib/insecure-stack';
import { newTestApp, reportedRuleIds, runAwsSolutions } from './helpers';

// The "before": these tests prove that cdk-nag DOES detect every flaw the
// tutorial documents. If a future cdk-nag release stops reporting one of
// them, the tutorial would be teaching something false — and this test flags it.
describe('InsecureStack', () => {
  const stack = new InsecureStack(newTestApp(), 'InsecureStack');
  const reported = reportedRuleIds(stack);

  test('fails the AwsSolutions rule pack', () => {
    expect(runAwsSolutions(stack).success).toBe(false);
  });

  test.each([
    ['AwsSolutions-S1', 'bucket without server access logs'],
    ['AwsSolutions-S2', 'bucket without public access block'],
    ['AwsSolutions-S10', 'bucket that does not enforce TLS'],
    ['AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/AmazonS3FullAccess]', 'AmazonS3FullAccess managed policy'],
    ['AwsSolutions-IAM5[Action::s3:*]', 'wildcard in Action'],
    ['AwsSolutions-IAM5[Resource::*]', 'wildcard in Resource'],
    ['AwsSolutions-L1', 'Lambda not on the latest runtime'],
    ['AwsSolutions-VPC7', 'VPC without Flow Logs'],
    ['AwsSolutions-RDS2', 'RDS without encryption at rest'],
    ['AwsSolutions-RDS3', 'RDS without Multi-AZ'],
    ['AwsSolutions-RDS10', 'RDS without deletion protection'],
    ['AwsSolutions-RDS11', 'RDS on the default port'],
    ['AwsSolutions-SMG4', 'RDS secret without rotation'],
  ])('reports %s (%s)', (ruleId) => {
    expect(reported).toContain(ruleId);
  });
});
