import { HeadObjectCommand, S3Client } from '@aws-sdk/client-s3';

// Wiring smoke test: real config + real gateway, only S3Client.send mocked.
// Env vars must be set before the module loads (it reads them at init), so
// the handler is require()d in beforeAll instead of a hoisted import.
describe('handler', () => {
  let send: jest.SpyInstance;
  let handler: typeof import('../src/index').handler;

  beforeAll(() => {
    process.env.BUCKET_NAME = 'my-bucket';
    process.env.READ_PREFIX = 'uploads/';
    process.env.AWS_REGION = 'us-east-1';
    send = jest.spyOn(S3Client.prototype, 'send').mockResolvedValue({ ContentLength: 7 } as never);
    handler = require('../src/index').handler;
  });
  afterAll(() => send.mockRestore());

  test('describes the requested upload end to end', async () => {
    await expect(handler({ name: 'report.csv' })).resolves.toEqual({ key: 'uploads/report.csv', sizeBytes: 7 });

    const command = send.mock.calls[0][0];
    expect(command).toBeInstanceOf(HeadObjectCommand);
    expect(command.input).toEqual({ Bucket: 'my-bucket', Key: 'uploads/report.csv' });
  });
});
