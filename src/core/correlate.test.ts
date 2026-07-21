import { describe, it, expect } from 'vitest';
import { correlate } from './correlate.js';
import { ingress } from '../sanitizer/ingress.js';

describe('correlate', () => {
  it('flags a file read followed by a download from the same IP within the window', () => {
    const read = ingress({ CLIENT_IP: '9.9.9.9', QUERY: 'uiapi { query { ContentVersion { edges } } }',
      TIMESTAMP_DERIVED: '2024-02-20T00:00:00.000Z' }, 'GraphQlQueryExecution');
    const dl = ingress({ CLIENT_IP: '9.9.9.9', URI: '/sfc/servlet.shepherd',
      TIMESTAMP_DERIVED: '2024-02-20T00:01:00.000Z' }, 'ContentTransfer');
    const res = correlate([read, dl]);
    expect(res).toHaveLength(1);
    expect(res[0].kind).toBe('read-then-download');
  });

  it('does not flag when the download is outside the window', () => {
    const read = ingress({ CLIENT_IP: '9.9.9.9', QUERY: 'uiapi { query { ContentVersion { edges } } }',
      TIMESTAMP_DERIVED: '2024-02-20T00:00:00.000Z' }, 'GraphQlQueryExecution');
    const dl = ingress({ CLIENT_IP: '9.9.9.9', URI: '/sfc/servlet.shepherd',
      TIMESTAMP_DERIVED: '2024-02-20T01:00:00.000Z' }, 'ContentTransfer');
    expect(correlate([read, dl])).toHaveLength(0);
  });
});
