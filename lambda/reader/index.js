// ReaderFunction handler: returns the size of one object under READ_PREFIX.
//
// Plain CommonJS on purpose, so it ships as-is with Code.fromAsset() and needs
// no bundling step. The AWS SDK v3 is provided by the Node.js Lambda runtime.
const { S3Client, HeadObjectCommand } = require('@aws-sdk/client-s3');

const s3 = new S3Client({});

/**
 * @param {{ name?: unknown }} event  e.g. `{ "name": "report.csv" }`
 * @returns {Promise<{ key: string, contentLength: number | undefined }>}
 */
exports.handler = async (event) => {
  const name = event?.name;
  if (typeof name !== 'string' || name.length === 0) {
    throw new Error('event.name must be a non-empty string');
  }

  const key = `${process.env.READ_PREFIX}${name}`;
  // The role only has s3:GetObject (no s3:ListBucket), so a missing key comes
  // back as 403 AccessDenied instead of 404. That is intentional: callers
  // cannot probe which keys exist.
  const head = await s3.send(new HeadObjectCommand({ Bucket: process.env.BUCKET_NAME, Key: key }));
  return { key, contentLength: head.ContentLength };
};
