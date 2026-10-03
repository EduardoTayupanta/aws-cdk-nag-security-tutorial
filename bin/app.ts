#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib/core';
import { Validations } from 'aws-cdk-lib/core';
import { AwsSolutionsChecks } from 'cdk-nag';
import { InsecureStack } from '../lib/insecure-stack';
import { SecureStack } from '../lib/secure-stack';

const app = new cdk.App();

// El "después": siempre se sintetiza, y es lo que valida el pipeline de CI.
new SecureStack(app, 'SecureStack');

// El "antes": solo bajo demanda, para ver los hallazgos de cdk-nag:
//   npx cdk synth InsecureStack -c includeInsecure=true
if (app.node.tryGetContext('includeInsecure') === 'true') {
  new InsecureStack(app, 'InsecureStack');
}

// Registrado una sola vez a nivel de App (API de cdk-nag 3.x sobre el
// mecanismo nativo de Validations de CDK): cualquier stack que se agregue
// después queda cubierto automáticamente. `verbose` añade la explicación
// completa de cada regla al reporte.
Validations.of(app).addPlugins(new AwsSolutionsChecks(app, { verbose: true }));
