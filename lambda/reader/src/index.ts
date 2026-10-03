import { S3Client } from '@aws-sdk/client-s3';
import { loadConfig } from './config';
import { describeUpload, type DescribeUploadEvent, type UploadDescription } from './describe-upload';
import { S3Gateway } from './gateways/s3-gateway';

// Wiring only. Created once per execution environment and reused across
// invocations; a missing env var fails the cold start, not a request.
const config = loadConfig();
const storage = new S3Gateway(new S3Client({}));

export async function handler(event: DescribeUploadEvent): Promise<UploadDescription> {
  return describeUpload(event, { storage, config });
}
