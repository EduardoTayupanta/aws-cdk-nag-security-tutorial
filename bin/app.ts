#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib/core';
import { Validations } from 'aws-cdk-lib/core';
import { AwsSolutionsChecks } from 'cdk-nag';
import { InsecureStack } from '../lib/insecure-stack';
import { SecureStack } from '../lib/secure-stack';

const app = new cdk.App();

// The "after": always synthesized, and what the CI pipeline validates.
new SecureStack(app, 'SecureStack');

// The "before": on demand only, to see the cdk-nag findings:
//   npx cdk synth InsecureStack -c includeInsecure=true
if (app.node.tryGetContext('includeInsecure') === 'true') {
  new InsecureStack(app, 'InsecureStack');
}

// Registered once at the App level (cdk-nag 3.x API on top of CDK's native
// Validations mechanism): any stack added later is covered automatically.
// `verbose` adds each rule's full explanation to the report.
Validations.of(app).addPlugins(new AwsSolutionsChecks(app, { verbose: true }));
