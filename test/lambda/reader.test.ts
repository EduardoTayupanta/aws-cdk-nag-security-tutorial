import { HeadObjectCommand, S3Client } from '@aws-sdk/client-s3';

// Mock the client's single `send` entry point: every command the handler
// issues becomes inspectable, with no network call.
let sendSpy: jest.SpyInstance;
// The handler is plain CommonJS (lambda/reader/index.js), so it is typed here.
let handler: (event: unknown) => Promise<{ key: string; contentLength?: number }>;

// Env vars are set before the module loads, hence require() in beforeAll
// rather than a hoisted top-level import.
beforeAll(() => {
  process.env.BUCKET_NAME = 'my-bucket';
  process.env.READ_PREFIX = 'uploads/';
  handler = require('../../lambda/reader/index').handler;
});

beforeEach(() => {
  sendSpy = jest.spyOn(S3Client.prototype, 'send').mockResolvedValue({ ContentLength: 42 } as never);
});
afterEach(() => sendSpy.mockRestore());

describe('ReaderFunction handler', () => {
  test('reads the object under READ_PREFIX and returns its size', async () => {
    await expect(handler({ name: 'report.csv' })).resolves.toEqual({
      key: 'uploads/report.csv',
      contentLength: 42,
    });

    expect(sendSpy).toHaveBeenCalledTimes(1);
    const command = sendSpy.mock.calls[0][0];
    expect(command).toBeInstanceOf(HeadObjectCommand);
    expect(command.input).toEqual({ Bucket: 'my-bucket', Key: 'uploads/report.csv' });
  });

  test.each([
    ['a missing event', undefined],
    ['a missing name', {}],
    ['an empty name', { name: '' }],
    ['a non-string name', { name: 42 }],
  ])('rejects %s without calling S3', async (_label, event) => {
    await expect(handler(event)).rejects.toThrow('event.name must be a non-empty string');
    expect(sendSpy).not.toHaveBeenCalled();
  });

  test('propagates S3 errors (e.g. AccessDenied for a missing key)', async () => {
    sendSpy.mockRejectedValueOnce(Object.assign(new Error('Access Denied'), { name: 'AccessDenied' }));
    await expect(handler({ name: 'missing.csv' })).rejects.toThrow('Access Denied');
  });
});
