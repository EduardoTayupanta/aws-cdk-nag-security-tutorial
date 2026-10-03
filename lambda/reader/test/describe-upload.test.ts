import { describeUpload } from '../src/describe-upload';
import type { ObjectStorage } from '../src/gateways/s3-gateway';

// Business logic is tested against a plain fake of the gateway interface:
// no AWS SDK, no mocking framework tricks.
function fakeStorage(sizeBytes = 42): ObjectStorage & { getObjectSize: jest.Mock } {
  return { getObjectSize: jest.fn().mockResolvedValue(sizeBytes) };
}

const config = { bucketName: 'my-bucket', readPrefix: 'uploads/' };

describe('describeUpload', () => {
  test('reads the object under the readable prefix and returns its size', async () => {
    const storage = fakeStorage(1234);

    await expect(describeUpload({ name: 'report.csv' }, { storage, config }))
      .resolves.toEqual({ key: 'uploads/report.csv', sizeBytes: 1234 });
    expect(storage.getObjectSize).toHaveBeenCalledWith('my-bucket', 'uploads/report.csv');
  });

  test.each([
    ['a missing event', undefined],
    ['a missing name', {}],
    ['an empty name', { name: '' }],
    ['a non-string name', { name: 42 }],
  ])('rejects %s without touching storage', async (_label, event) => {
    const storage = fakeStorage();

    await expect(describeUpload(event, { storage, config })).rejects.toThrow('event.name must be a non-empty string');
    expect(storage.getObjectSize).not.toHaveBeenCalled();
  });

  test('propagates storage errors', async () => {
    const storage = fakeStorage();
    storage.getObjectSize.mockRejectedValue(new Error('Access Denied'));

    await expect(describeUpload({ name: 'missing.csv' }, { storage, config })).rejects.toThrow('Access Denied');
  });
});
