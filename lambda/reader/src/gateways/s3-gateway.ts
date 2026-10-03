import { HeadObjectCommand, S3Client } from '@aws-sdk/client-s3';

/** What the use case needs from object storage, named by intent. */
export interface ObjectStorage {
  /** Size in bytes of the object at `bucket/key`. */
  getObjectSize(bucket: string, key: string): Promise<number>;
}

/** `ObjectStorage` backed by Amazon S3. No business logic lives here. */
export class S3Gateway implements ObjectStorage {
  constructor(private readonly client: S3Client) {}

  async getObjectSize(bucket: string, key: string): Promise<number> {
    // HeadObject is authorized by s3:GetObject. Without s3:ListBucket, a
    // missing key is reported as a 403 instead of a 404 NotFound — which is
    // intentional: callers cannot probe which keys exist.
    const res = await this.client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
    if (res.ContentLength === undefined) {
      throw new Error(`No ContentLength returned for s3://${bucket}/${key}`);
    }
    return res.ContentLength;
  }
}
