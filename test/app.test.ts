import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { App } from 'aws-cdk-lib/core';
import { buildApp } from '../lib/app';
import * as cdkJson from '../cdk.json';

// aws-cdk-lib exposes no public API to list registered validation plugins, so
// these tests check behavior instead: `app.synth()` runs the plugins, and a
// cdk-nag ERROR makes it throw.
function newApp(extraContext: Record<string, unknown> = {}): App {
  return new App({
    context: { ...cdkJson.context, ...extraContext },
    outdir: mkdtempSync(join(tmpdir(), 'cdk-nag-tutorial-')),
  });
}

describe('buildApp', () => {
  test('by default adds only SecureStack, and synth passes cdk-nag', () => {
    const app = buildApp(newApp());
    expect(app.node.children.map((c) => c.node.id)).toEqual(['SecureStack']);
    expect(() => app.synth()).not.toThrow();
  });

  test.each([
    ['the CLI string "true"', 'true'],
    ['a boolean true from cdk.json', true],
  ])('includeInsecure as %s adds InsecureStack, and cdk-nag stops the synth', (_label, value) => {
    const app = buildApp(newApp({ includeInsecure: value }));
    expect(app.node.children.map((c) => c.node.id)).toEqual(['SecureStack', 'InsecureStack']);
    expect(() => app.synth()).toThrow(/AwsSolutions-S1/);
  });

  test('any other includeInsecure value leaves InsecureStack out', () => {
    const app = buildApp(newApp({ includeInsecure: 'yes' }));
    expect(app.node.children.map((c) => c.node.id)).toEqual(['SecureStack']);
  });
});
