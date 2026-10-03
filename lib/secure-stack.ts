import { Construct } from 'constructs';
import { Duration, Stack, StackProps, Validations } from 'aws-cdk-lib/core';
import { BlockPublicAccess, Bucket, BucketEncryption, CfnBucket, ObjectOwnership } from 'aws-cdk-lib/aws-s3';
import { PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Code, Function, Runtime } from 'aws-cdk-lib/aws-lambda';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import {
  FlowLogDestination,
  InstanceClass,
  InstanceSize,
  InstanceType,
  InterfaceVpcEndpointAwsService,
  SecurityGroup,
  SubnetType,
  Vpc,
} from 'aws-cdk-lib/aws-ec2';
import { DatabaseInstance, DatabaseInstanceEngine, PostgresEngineVersion } from 'aws-cdk-lib/aws-rds';

/** Prefijo del bucket que la Lambda puede leer; nada fuera de él. */
export const READABLE_PREFIX = 'uploads/';

/**
 * El "DESPUÉS" del tutorial: los mismos recursos que `InsecureStack`, con los
 * mismos IDs de construct, remediados para pasar el paquete de reglas
 * AwsSolutions de cdk-nag.
 *
 * Solo queda UNA excepción reconocida (`Validations.of(...).acknowledge`), con
 * su justificación escrita junto al recurso. Todo lo demás se corrige en vez
 * de suprimirse.
 */
export class SecureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // ── S3: AwsSolutions-S1 / S2 / S10 ────────────────────────────────────
    // El bucket de logs no necesita a su vez logging: la regla S1 reconoce a
    // un bucket que ya es destino de access logs como compliant.
    const accessLogsBucket = new Bucket(this, 'AccessLogsBucket', {
      encryption: BucketEncryption.S3_MANAGED,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      objectOwnership: ObjectOwnership.BUCKET_OWNER_ENFORCED,
      lifecycleRules: [{ id: 'expire-access-logs', expiration: Duration.days(365) }],
    });

    const dataBucket = new Bucket(this, 'DataBucket', {
      encryption: BucketEncryption.S3_MANAGED,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL, // S2
      enforceSSL: true, // S10
      versioned: true,
      objectOwnership: ObjectOwnership.BUCKET_OWNER_ENFORCED,
      serverAccessLogsBucket: accessLogsBucket, // S1
      serverAccessLogsPrefix: 'data-bucket/',
    });

    // ── IAM: AwsSolutions-IAM4 / IAM5 ─────────────────────────────────────
    // Rol propio en lugar del rol por defecto de Lambda: así no se adjunta la
    // política administrada AWSLambdaBasicExecutionRole (IAM4) y los permisos
    // de logs quedan acotados a UN log group concreto.
    const appRole = new Role(this, 'AppRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Rol de ReaderFunction: lectura de uploads/ y escritura en su propio log group.',
    });

    const readerLogGroup = new LogGroup(this, 'ReaderLogGroup', {
      retention: RetentionDays.ONE_MONTH,
    });
    readerLogGroup.grantWrite(appRole);

    // Una sola acción, sobre un solo prefijo. `bucket.grantRead()` agregaría
    // además s3:GetObject*, s3:GetBucket* y s3:List* (más hallazgos IAM5 que
    // justificar); esta función solo necesita leer objetos.
    appRole.addToPolicy(new PolicyStatement({
      sid: 'ReadUploadsPrefixOnly',
      actions: ['s3:GetObject'],
      resources: [dataBucket.arnForObjects(`${READABLE_PREFIX}*`)],
    }));

    // La única excepción del stack. En cdk-nag 3.x cada hallazgo se reconoce
    // por separado con su ID completo `Regla[Hallazgo]`: si mañana alguien
    // agrega otro wildcard a este rol, cdk-nag lo vuelve a reportar.
    Validations.of(appRole).acknowledge({
      id: `AwsSolutions-IAM5[Resource::<${this.getLogicalId(dataBucket.node.defaultChild as CfnBucket)}.Arn>/${READABLE_PREFIX}*]`,
      reason:
        `El "*" es el alcance por prefijo deliberado: la función solo puede ejecutar s3:GetObject ` +
        `sobre objetos bajo ${READABLE_PREFIX} de este bucket. S3 no permite enumerar las keys de ` +
        'antemano (se crean en tiempo de ejecución), por lo que un prefijo es el alcance más ' +
        'estrecho posible para lectura de objetos.',
    });

    // ── Lambda: AwsSolutions-L1 ───────────────────────────────────────────
    // Runtime fijado explícitamente (no NODEJS_LATEST, cuyo valor puede cambiar
    // entre versiones de aws-cdk-lib y alterar el template sin aviso).
    new Function(this, 'ReaderFunction', {
      runtime: Runtime.NODEJS_24_X,
      handler: 'index.handler',
      code: Code.fromInline([
        "const { S3Client, HeadObjectCommand } = require('@aws-sdk/client-s3');",
        'const s3 = new S3Client({});',
        'exports.handler = async (event) => {',
        `  const key = '${READABLE_PREFIX}' + event.name;`,
        '  const head = await s3.send(new HeadObjectCommand({ Bucket: process.env.BUCKET_NAME, Key: key }));',
        '  return { key, contentLength: head.ContentLength };',
        '};',
      ].join('\n')),
      role: appRole,
      logGroup: readerLogGroup,
      timeout: Duration.seconds(10),
      environment: { BUCKET_NAME: dataBucket.bucketName },
    });

    // ── VPC: AwsSolutions-VPC7 ────────────────────────────────────────────
    // Solo subnets aisladas y sin NAT Gateway: la base de datos no necesita
    // salir a internet. Lo único que debe alcanzar es Secrets Manager (para
    // la rotación de credenciales), vía VPC endpoint.
    const vpc = new Vpc(this, 'AppVpc', {
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [{ name: 'isolated', subnetType: SubnetType.PRIVATE_ISOLATED }],
      flowLogs: {
        FlowLog: {
          destination: FlowLogDestination.toCloudWatchLogs(new LogGroup(this, 'VpcFlowLogGroup', {
            retention: RetentionDays.ONE_YEAR,
          })),
        },
      },
    });
    // `open: false` evita la regla de entrada por defecto (todo el CIDR de la
    // VPC); más abajo se abre solo a la Lambda de rotación (AwsSolutions-EC23).
    const secretsManagerEndpoint = vpc.addInterfaceEndpoint('SecretsManagerEndpoint', {
      service: InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
      subnets: { subnetType: SubnetType.PRIVATE_ISOLATED },
      open: false,
    });

    // ── RDS: AwsSolutions-RDS2 / RDS10 (+ RDS3, RDS11, SMG4) ──────────────
    const database = new DatabaseInstance(this, 'AppDatabase', {
      engine: DatabaseInstanceEngine.postgres({ version: PostgresEngineVersion.VER_17 }),
      instanceType: InstanceType.of(InstanceClass.T4G, InstanceSize.MICRO),
      vpc,
      vpcSubnets: { subnetType: SubnetType.PRIVATE_ISOLATED },
      storageEncrypted: true, // RDS2
      deletionProtection: true, // RDS10
      multiAz: true, // RDS3
      port: 5433, // RDS11: puerto distinto al por defecto (5432)
      iamAuthentication: true,
      backupRetention: Duration.days(7),
      cloudwatchLogsExports: ['postgresql'],
    });
    // SMG4: rotación automática de la contraseña maestra.
    // La Lambda de rotación corre en la VPC con su propio security group, y el
    // endpoint de Secrets Manager se abre (443) SOLO a ese security group.
    // Ojo: la opción `endpoint` solo cambia la URL que usa la Lambda; no abre
    // el security group del endpoint, por eso la regla se agrega aquí.
    const rotationSecurityGroup = new SecurityGroup(this, 'RotationSecurityGroup', {
      vpc,
      description: 'Lambda de rotacion del secreto de AppDatabase',
    });
    secretsManagerEndpoint.connections.allowDefaultPortFrom(rotationSecurityGroup);
    database.addRotationSingleUser({
      endpoint: secretsManagerEndpoint,
      securityGroup: rotationSecurityGroup,
    });
  }
}
