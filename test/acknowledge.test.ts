import { Stack, Validations } from 'aws-cdk-lib/core';
import { PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { newTestApp, reportedRuleIds } from './helpers';

// Cómo se comporta `Validations.of(x).acknowledge()` (cdk-nag 3.x). Estos
// tests respaldan lo que el README afirma sobre las supresiones; si una
// versión nueva de cdk-nag cambia el comportamiento, fallan y avisan.
describe('Validations.acknowledge con cdk-nag', () => {
  test('una regla simple se reconoce con su ID tal cual (AwsSolutions-S1)', () => {
    const stack = new Stack(newTestApp(), 'Plain');
    const bucket = new Bucket(stack, 'Bucket', { enforceSSL: true });
    expect(reportedRuleIds(stack)).toContain('AwsSolutions-S1');

    Validations.of(bucket).acknowledge({ id: 'AwsSolutions-S1', reason: 'Demostración en un test.' });
    expect(reportedRuleIds(stack)).not.toContain('AwsSolutions-S1');
  });

  test('el formato que sugiere el CLI (AwsSolutions::AwsSolutions-S1) NO lo respeta validateScope()', () => {
    // `cdk synth` acepta ambos formatos, pero validateScope() — lo que usan
    // los tests — solo el ID simple. Por eso el tutorial recomienda el simple.
    const stack = new Stack(newTestApp(), 'Prefixed');
    const bucket = new Bucket(stack, 'Bucket', { enforceSSL: true });

    Validations.of(bucket).acknowledge({ id: 'AwsSolutions::AwsSolutions-S1', reason: 'Demostración en un test.' });
    expect(reportedRuleIds(stack)).toContain('AwsSolutions-S1');
  });

  test('un hallazgo granular solo suprime ESE hallazgo, no la regla completa', () => {
    const stack = new Stack(newTestApp(), 'Granular');
    const role = new Role(stack, 'Role', { assumedBy: new ServicePrincipal('lambda.amazonaws.com') });
    role.addToPolicy(new PolicyStatement({ actions: ['s3:*'], resources: ['*'] }));

    Validations.of(role).acknowledge({ id: 'AwsSolutions-IAM5[Action::s3:*]', reason: 'Demostración en un test.' });

    const reported = reportedRuleIds(stack);
    expect(reported).not.toContain('AwsSolutions-IAM5[Action::s3:*]');
    expect(reported).toContain('AwsSolutions-IAM5[Resource::*]');
  });

  test('reconocer el ID base (AwsSolutions-IAM5) no suprime los hallazgos granulares', () => {
    const stack = new Stack(newTestApp(), 'Base');
    const role = new Role(stack, 'Role', { assumedBy: new ServicePrincipal('lambda.amazonaws.com') });
    role.addToPolicy(new PolicyStatement({ actions: ['s3:*'], resources: ['*'] }));

    Validations.of(role).acknowledge({ id: 'AwsSolutions-IAM5', reason: 'Demostración en un test.' });

    expect(reportedRuleIds(stack)).toEqual(expect.arrayContaining([
      'AwsSolutions-IAM5[Action::s3:*]',
      'AwsSolutions-IAM5[Resource::*]',
    ]));
  });
});
