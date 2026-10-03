import * as path from 'node:path';
import { Construct } from 'constructs';
import { Duration, RemovalPolicy, Validations } from 'aws-cdk-lib/core';
import { Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { Role } from 'aws-cdk-lib/aws-iam';
import { Architecture, DockerImageCode, DockerImageFunction, Tracing } from 'aws-cdk-lib/aws-lambda';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';

export interface ReaderFunctionProps {
  /**
   * Execution role, owned by the caller. A dedicated role (instead of
   * Lambda's default one) keeps the AWSLambdaBasicExecutionRole managed
   * policy out of the stack (AwsSolutions-IAM4); this construct only grants
   * it what the function itself needs: its own log group and X-Ray.
   */
  readonly role: Role;

  /** Environment variables: the resource names `lambda/reader/src/config.ts` reads. */
  readonly environment: Record<string, string>;

  /** @default RemovalPolicy.RETAIN */
  readonly removalPolicy?: RemovalPolicy;
}

/**
 * ReaderFunction: the TypeScript handler in `lambda/reader`, packaged as an
 * arm64 container image, with its own log group and active X-Ray tracing.
 */
export class ReaderFunction extends Construct {
  /** The underlying Lambda function, for wiring and grants. */
  public readonly fn: DockerImageFunction;

  /** The function's log group (explicit, instead of the deprecated `logRetention`). */
  public readonly logGroup: LogGroup;

  constructor(scope: Construct, id: string, props: ReaderFunctionProps) {
    super(scope, id);

    this.logGroup = new LogGroup(this, 'LogGroup', {
      retention: RetentionDays.ONE_MONTH,
      removalPolicy: props.removalPolicy ?? RemovalPolicy.RETAIN,
    });
    this.logGroup.grantWrite(props.role);

    this.fn = new DockerImageFunction(this, 'Resource', {
      code: DockerImageCode.fromImageAsset(
        path.join(__dirname, '..', '..', 'lambda', 'reader'),
        // Without an explicit platform Docker builds for the *host*
        // architecture; on x86 hosts/CI that yields an amd64 image that
        // fails with "exec format error" on an ARM_64 function.
        { platform: Platform.LINUX_ARM64 },
      ),
      architecture: Architecture.ARM_64,
      memorySize: 256,
      timeout: Duration.seconds(10),
      tracing: Tracing.ACTIVE,
      role: props.role,
      logGroup: this.logGroup,
      environment: props.environment,
    });

    // Tracing.ACTIVE adds xray:PutTraceSegments / PutTelemetryRecords to the
    // role. test/constructs/reader-function.test.ts pins that the X-Ray
    // actions are the ONLY ones on Resource "*", since this acknowledgment
    // would otherwise also hide any other action added there.
    Validations.of(props.role).acknowledge({
      id: 'AwsSolutions-IAM5[Resource::*]',
      reason:
        'X-Ray tracing (xray:PutTraceSegments / xray:PutTelemetryRecords) does not support ' +
        'resource-level permissions; Resource "*" is what AWS requires for these two actions.',
    });
  }
}
