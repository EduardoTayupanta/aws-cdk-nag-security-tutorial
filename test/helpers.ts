import { App, Stack, Validations } from 'aws-cdk-lib/core';
import { AwsSolutionsChecks } from 'cdk-nag';
import * as cdkJson from '../cdk.json';

/**
 * The feature flags in cdk.json are only applied by the `cdk` CLI, never by a
 * bare `new App()`. They are loaded explicitly so the tests behave the same as
 * `cdk synth` (e.g. the S3 flag that makes access logs use a bucket policy
 * instead of ACLs).
 */
export function newTestApp(): App {
  return new App({ context: cdkJson.context });
}

/**
 * Runs the AwsSolutions pack against the stack with `validateScope()`, the
 * cdk-nag 3.x entry point for tests (no `cdk synth` needed).
 */
export function runAwsSolutions(stack: Stack) {
  return new AwsSolutionsChecks().validateScope(stack);
}

/** Rule IDs (e.g. `AwsSolutions-IAM5[Action::s3:*]`) reported for the stack. */
export function reportedRuleIds(stack: Stack): string[] {
  return runAwsSolutions(stack).violations.map((v) => v.ruleName);
}

export interface RecordedAcknowledgment {
  readonly path: string;
  readonly id: string;
  readonly reason: string;
}

/**
 * Every cdk-nag suppression (`Validations.of(x).acknowledge(...)`) recorded in
 * the stack's tree. CDK stores them as construct metadata
 * (`{ "Annotation::<id>": "<reason>" }`) precisely so an audit trail can be
 * built. Entries that CDK adds on its own (e.g. `CloudFormation-Validate::W3010`)
 * are filtered out.
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
