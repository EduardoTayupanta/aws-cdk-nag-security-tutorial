export interface ReaderConfig {
  /** Bucket holding the readable objects. */
  readonly bucketName: string;
  /** Key prefix the function is allowed to read, e.g. `uploads/`. */
  readonly readPrefix: string;
}

export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable ${name}`);
  }
  return value;
}

export function loadConfig(): ReaderConfig {
  return {
    bucketName: requireEnv('BUCKET_NAME'),
    readPrefix: requireEnv('READ_PREFIX'),
  };
}
