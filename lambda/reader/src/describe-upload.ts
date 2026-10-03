import type { ReaderConfig } from './config';
import type { ObjectStorage } from './gateways/s3-gateway';

/** Invocation payload, e.g. `{ "name": "report.csv" }`. */
export interface DescribeUploadEvent {
  readonly name?: unknown;
}

export interface UploadDescription {
  readonly key: string;
  readonly sizeBytes: number;
}

export interface Deps {
  readonly storage: ObjectStorage;
  readonly config: ReaderConfig;
}

/**
 * Describes one uploaded object. The key is always built under the readable
 * prefix, so the function only ever asks for objects its IAM policy allows.
 */
export async function describeUpload(
  event: DescribeUploadEvent | undefined,
  { storage, config }: Deps,
): Promise<UploadDescription> {
  const name = event?.name;
  if (typeof name !== 'string' || name.length === 0) {
    throw new Error('event.name must be a non-empty string');
  }

  const key = `${config.readPrefix}${name}`;
  const sizeBytes = await storage.getObjectSize(config.bucketName, key);
  return { key, sizeBytes };
}
