import { loadConfig, requireEnv } from '../src/config';

describe('config', () => {
  const saved = { ...process.env };
  afterEach(() => {
    process.env = { ...saved };
  });

  test('requireEnv returns a variable that is set', () => {
    process.env.SOME_VAR = 'value';
    expect(requireEnv('SOME_VAR')).toBe('value');
  });

  test.each([
    ['missing', undefined],
    ['empty', ''],
  ])('requireEnv throws when the variable is %s', (_label, value) => {
    if (value === undefined) {
      delete process.env.SOME_VAR;
    } else {
      process.env.SOME_VAR = value;
    }
    expect(() => requireEnv('SOME_VAR')).toThrow('Missing required environment variable SOME_VAR');
  });

  test('loadConfig maps BUCKET_NAME and READ_PREFIX', () => {
    process.env.BUCKET_NAME = 'my-bucket';
    process.env.READ_PREFIX = 'uploads/';
    expect(loadConfig()).toEqual({ bucketName: 'my-bucket', readPrefix: 'uploads/' });
  });
});
