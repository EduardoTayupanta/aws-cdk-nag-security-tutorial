import { Construct } from 'constructs';
import { RemovalPolicy, Stack, StackProps } from 'aws-cdk-lib/core';
import { BlockPublicAccess, Bucket } from 'aws-cdk-lib/aws-s3';
import { ManagedPolicy, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Code, Function, Runtime } from 'aws-cdk-lib/aws-lambda';
import { InstanceClass, InstanceSize, InstanceType, SubnetType, Vpc } from 'aws-cdk-lib/aws-ec2';
import { DatabaseInstance, DatabaseInstanceEngine, PostgresEngineVersion } from 'aws-cdk-lib/aws-rds';

/**
 * El "ANTES" del tutorial: un stack con las fallas de seguridad más comunes
 * escritas A PROPÓSITO, para ver cómo las reporta cdk-nag.
 *
 * ⚠️ No está pensado para desplegarse. `bin/app.ts` solo lo agrega al App
 * cuando se pasa `-c includeInsecure=true`, así `cdk synth` por defecto (y el
 * pipeline de CI) se mantiene en verde.
 *
 * Cada bloque está marcado con las reglas que dispara; `test/insecure-stack.test.ts`
 * verifica que cdk-nag realmente las reporte, y `lib/secure-stack.ts` muestra
 * la remediación de cada una con el mismo ID de construct.
 */
export class InsecureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // AwsSolutions-S1  → sin server access logging
    // AwsSolutions-S2  → acceso público no bloqueado
    // AwsSolutions-S10 → no exige TLS (aws:SecureTransport)
    const dataBucket = new Bucket(this, 'DataBucket', {
      blockPublicAccess: new BlockPublicAccess({
        blockPublicAcls: false,
        blockPublicPolicy: false,
        ignorePublicAcls: false,
        restrictPublicBuckets: false,
      }),
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // AwsSolutions-IAM4 → política administrada de AWS demasiado amplia
    // AwsSolutions-IAM5 → wildcards en Action (s3:*) y Resource (*)
    const appRole = new Role(this, 'AppRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
    });
    appRole.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName('AmazonS3FullAccess'));
    appRole.addToPolicy(new PolicyStatement({ actions: ['s3:*'], resources: ['*'] }));

    // AwsSolutions-L1 → runtime que no es el más reciente de su familia
    new Function(this, 'ReaderFunction', {
      runtime: Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: Code.fromInline('exports.handler = async () => ({ statusCode: 200 });'),
      role: appRole,
      environment: { BUCKET_NAME: dataBucket.bucketName },
    });

    // AwsSolutions-VPC7 → VPC sin Flow Logs
    const vpc = new Vpc(this, 'AppVpc', {
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [{ name: 'isolated', subnetType: SubnetType.PRIVATE_ISOLATED }],
    });

    // AwsSolutions-RDS2  → almacenamiento sin cifrar
    // AwsSolutions-RDS10 → sin deletion protection
    // (además dispara RDS3, RDS11, RDS13, SMG4… ver el README)
    new DatabaseInstance(this, 'AppDatabase', {
      engine: DatabaseInstanceEngine.postgres({ version: PostgresEngineVersion.VER_17 }),
      instanceType: InstanceType.of(InstanceClass.T4G, InstanceSize.MICRO),
      vpc,
      vpcSubnets: { subnetType: SubnetType.PRIVATE_ISOLATED },
      storageEncrypted: false,
      deletionProtection: false,
      removalPolicy: RemovalPolicy.DESTROY,
    });
  }
}
