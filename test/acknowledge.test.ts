import { Stack, Validations } from 'aws-cdk-lib/core';
import { PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { newTestApp, reportedRuleIds } from './helpers';

// How `Validations.of(x).acknowledge()` behaves (cdk-nag 3.x). These tests
// back up what the README claims about suppressions; if a new cdk-nag
// release changes the behavior, they fail and flag it.
describe('Validations.acknowledge with cdk-nag', () => {
  test('a simple rule is acknowledged by its plain ID (AwsSolutions-S1)', () => {
    const stack = new Stack(newTestApp(), 'Plain');
    const bucket = new Bucket(stack, 'Bucket', { enforceSSL: true });
    expect(reportedRuleIds(stack)).toContain('AwsSolutions-S1');

    Validations.of(bucket).acknowledge({ id: 'AwsSolutions-S1', reason: 'Demonstration in a test.' });
    expect(reportedRuleIds(stack)).not.toContain('AwsSolutions-S1');
  });

  test('the format suggested by the CLI (AwsSolutions::AwsSolutions-S1) is NOT honored by validateScope()', () => {
    // `cdk synth` accepts both formats, but validateScope() — what the tests
    // use — only accepts the plain ID. That is why the tutorial recommends it.
    const stack = new Stack(newTestApp(), 'Prefixed');
    const bucket = new Bucket(stack, 'Bucket', { enforceSSL: true });

    Validations.of(bucket).acknowledge({ id: 'AwsSolutions::AwsSolutions-S1', reason: 'Demonstration in a test.' });
    expect(reportedRuleIds(stack)).toContain('AwsSolutions-S1');
  });

  test('a granular finding suppresses ONLY that finding, not the whole rule', () => {
    const stack = new Stack(newTestApp(), 'Granular');
    const role = new Role(stack, 'Role', { assumedBy: new ServicePrincipal('lambda.amazonaws.com') });
    role.addToPolicy(new PolicyStatement({ actions: ['s3:*'], resources: ['*'] }));

    Validations.of(role).acknowledge({ id: 'AwsSolutions-IAM5[Action::s3:*]', reason: 'Demonstration in a test.' });

    const reported = reportedRuleIds(stack);
    expect(reported).not.toContain('AwsSolutions-IAM5[Action::s3:*]');
    expect(reported).toContain('AwsSolutions-IAM5[Resource::*]');
  });

  test('acknowledging the base ID (AwsSolutions-IAM5) does not suppress the granular findings', () => {
    const stack = new Stack(newTestApp(), 'Base');
    const role = new Role(stack, 'Role', { assumedBy: new ServicePrincipal('lambda.amazonaws.com') });
    role.addToPolicy(new PolicyStatement({ actions: ['s3:*'], resources: ['*'] }));

    Validations.of(role).acknowledge({ id: 'AwsSolutions-IAM5', reason: 'Demonstration in a test.' });

    expect(reportedRuleIds(stack)).toEqual(expect.arrayContaining([
      'AwsSolutions-IAM5[Action::s3:*]',
      'AwsSolutions-IAM5[Resource::*]',
    ]));
  });
});
