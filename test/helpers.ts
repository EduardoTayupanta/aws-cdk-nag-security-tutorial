import { App, Stack, Validations } from 'aws-cdk-lib/core';
import { AwsSolutionsChecks } from 'cdk-nag';
import * as cdkJson from '../cdk.json';

/**
 * Los feature flags de cdk.json solo los aplica el CLI de `cdk`, nunca un
 * `new App()` a secas. Se cargan explícitamente para que los tests se
 * comporten igual que `cdk synth` (p. ej. el flag de S3 que hace que los
 * access logs usen bucket policy en lugar de ACLs).
 */
export function newTestApp(): App {
  return new App({ context: cdkJson.context });
}

/**
 * Ejecuta el paquete AwsSolutions sobre el stack con `validateScope()`, el
 * punto de entrada de cdk-nag 3.x para tests (no necesita un `cdk synth`).
 */
export function runAwsSolutions(stack: Stack) {
  return new AwsSolutionsChecks().validateScope(stack);
}

/** IDs de regla (p. ej. `AwsSolutions-IAM5[Action::s3:*]`) reportados para el stack. */
export function reportedRuleIds(stack: Stack): string[] {
  return runAwsSolutions(stack).violations.map((v) => v.ruleName);
}

export interface RecordedAcknowledgment {
  readonly path: string;
  readonly id: string;
  readonly reason: string;
}

/**
 * Todas las supresiones de cdk-nag (`Validations.of(x).acknowledge(...)`)
 * registradas en el árbol del stack. CDK las guarda como metadata del
 * construct (`{ "Annotation::<id>": "<reason>" }`) justamente para poder
 * construir un rastro de auditoría. Se filtran las que CDK agrega por su
 * cuenta (p. ej. `CloudFormation-Validate::W3010`).
 */
export function nagAcknowledgmentsIn(stack: Stack): RecordedAcknowledgment[] {
  return stack.node.findAll().flatMap((c) =>
    c.node.metadata
      .filter((m) => m.type === Validations.ACKNOWLEDGED_RULES_METADATA_KEY)
      .flatMap((m) => Object.entries(m.data as Record<string, string>))
      .map(([id, reason]) => ({ path: c.node.path, id: id.replace(/^Annotation::/, ''), reason }))
      .filter(({ id }) => id.startsWith('AwsSolutions-')),
  );
}
