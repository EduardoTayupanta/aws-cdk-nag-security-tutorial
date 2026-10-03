import { HeadObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { S3Gateway } from '../../src/gateways/s3-gateway';

describe('S3Gateway', () => {
  const client = new S3Client({ region: 'us-east-1' });
  let send: jest.SpyInstance;

  beforeEach(() => {
    send = jest.spyOn(client, 'send');
  });
  afterEach(() => send.mockRestore());

  test('getObjectSize issues a HeadObject for the exact bucket and key', async () => {
    send.mockResolvedValue({ ContentLength: 42 } as never);

    await expect(new S3Gateway(client).getObjectSize('my-bucket', 'uploads/a.csv')).resolves.toBe(42);

    expect(send).toHaveBeenCalledTimes(1);
    const command = send.mock.calls[0][0];
    expect(command).toBeInstanceOf(HeadObjectCommand);
    expect(command.input).toEqual({ Bucket: 'my-bucket', Key: 'uploads/a.csv' });
  });

  test('throws when S3 returns no ContentLength', async () => {
    send.mockResolvedValue({} as never);

    await expect(new S3Gateway(client).getObjectSize('my-bucket', 'uploads/a.csv'))
      .rejects.toThrow('No ContentLength returned for s3://my-bucket/uploads/a.csv');
  });

  test('propagates S3 errors unchanged (e.g. the 403 for a missing key)', async () => {
    const denied = Object.assign(new Error('UnknownError'), { name: '403', $metadata: { httpStatusCode: 403 } });
    send.mockRejectedValue(denied);

    await expect(new S3Gateway(client).getObjectSize('my-bucket', 'uploads/missing.csv')).rejects.toBe(denied);
  });
});
