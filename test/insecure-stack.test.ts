import { InsecureStack } from '../lib/insecure-stack';
import { newTestApp, reportedRuleIds, runAwsSolutions } from './helpers';

// El "antes": estos tests prueban que cdk-nag SÍ detecta cada falla que el
// tutorial documenta. Si una versión futura de cdk-nag deja de reportar una
// de ellas, el tutorial estaría enseñando algo falso — y este test lo avisa.
describe('InsecureStack', () => {
  const stack = new InsecureStack(newTestApp(), 'InsecureStack');
  const reported = reportedRuleIds(stack);

  test('no pasa el paquete AwsSolutions', () => {
    expect(runAwsSolutions(stack).success).toBe(false);
  });

  test.each([
    ['AwsSolutions-S1', 'bucket sin server access logs'],
    ['AwsSolutions-S2', 'bucket sin bloqueo de acceso público'],
    ['AwsSolutions-S10', 'bucket que no exige TLS'],
    ['AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/AmazonS3FullAccess]', 'política administrada AmazonS3FullAccess'],
    ['AwsSolutions-IAM5[Action::s3:*]', 'wildcard en Action'],
    ['AwsSolutions-IAM5[Resource::*]', 'wildcard en Resource'],
    ['AwsSolutions-L1', 'Lambda sin el runtime más reciente'],
    ['AwsSolutions-VPC7', 'VPC sin Flow Logs'],
    ['AwsSolutions-RDS2', 'RDS sin cifrado en reposo'],
    ['AwsSolutions-RDS3', 'RDS sin Multi-AZ'],
    ['AwsSolutions-RDS10', 'RDS sin deletion protection'],
    ['AwsSolutions-RDS11', 'RDS en el puerto por defecto'],
    ['AwsSolutions-SMG4', 'secreto de RDS sin rotación'],
  ])('reporta %s (%s)', (ruleId) => {
    expect(reported).toContain(ruleId);
  });
});
