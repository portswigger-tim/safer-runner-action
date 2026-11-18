import * as fs from 'fs';
import * as path from 'path';
import { SELFTEST_BOGUS_IP } from '../constants.js';
import { REPOINT_HOST, REPOINT_PATH } from './selftest.js';

const vectors = JSON.parse(
  fs.readFileSync(path.join(import.meta.dirname, '..', '..', 'proxy', 'test-vectors.json'), 'utf8')
);

describe('repoint self-test probe', () => {
  it('is the request the addon exempts from http-filter', () => {
    expect({ host: REPOINT_HOST, method: 'GET', path: REPOINT_PATH, dst_ip: SELFTEST_BOGUS_IP }).toEqual(
      vectors.selftest_probe
    );
  });
});
