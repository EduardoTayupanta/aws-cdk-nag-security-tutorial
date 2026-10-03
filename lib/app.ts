import { App, Validations } from 'aws-cdk-lib/core';
import { AwsSolutionsChecks } from 'cdk-nag';
import { InsecureStack } from './insecure-stack';
import { SecureStack } from './secure-stack';

/**
 * Wires the tutorial's stacks and cdk-nag into an App. Kept out of
 * `bin/app.ts` so the wiring itself is unit-tested (see test/app.test.ts).
 */
export function buildApp(app: App): App {
  // The "after": always synthesized, and what the CI pipeline validates.
  new SecureStack(app, 'SecureStack');

  // The "before": on demand only, to see the cdk-nag findings:
  //   npx cdk synth InsecureStack -c includeInsecure=true
  // String() also accepts a boolean `true` set in cdk.json context.
  if (String(app.node.tryGetContext('includeInsecure')) === 'true') {
    new InsecureStack(app, 'InsecureStack');
  }

  // Registered once at the App level (cdk-nag 3.x API on top of CDK's native
  // Validations mechanism): any stack added later is covered automatically.
  // `verbose` adds each rule's full explanation to the report.
  Validations.of(app).addPlugins(new AwsSolutionsChecks(app, { verbose: true }));

  return app;
}
