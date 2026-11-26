import { describe, expect, it } from 'vitest';
import { newDraft, type RuleDraft } from './ruleDraft';
import { detectService, presetDetail, serviceChange, type ServiceId } from './services';

const inbound = newDraft('inbound');

function applied(id: ServiceId, draft: RuleDraft = inbound): RuleDraft {
  return { ...draft, ...serviceChange(id, draft) };
}

describe('serviceChange', () => {
  it.each([
    ['http', 'tcp', '80'],
    ['https', 'tcp', '443'],
    ['ssh', 'tcp', '22'],
    ['rdp', 'tcp', '3389'],
    ['smb', 'tcp', '445'],
    ['dns', 'tcp+udp', '53'],
    ['all', 'tcp+udp', ''],
  ] as const)('sets %s to %s port %j', (id, protocol, port) => {
    expect(applied(id)).toMatchObject({ protocol, destinationPort: port, publicPort: '' });
  });

  it('opens every protocol for "All ports" where the model allows it', () => {
    expect(applied('all', newDraft('outbound')).protocol).toBe('any');
    expect(applied('all', { ...inbound, action: 'drop' }).protocol).toBe('any');
  });

  it('keeps protocol and port for "Custom"', () => {
    const draft = { ...inbound, protocol: 'udp' as const, destinationPort: '1194' };
    expect(serviceChange('custom', draft)).toEqual({});
  });
});

describe('detectService', () => {
  it('recognises presets and falls back to custom', () => {
    expect(detectService(applied('https'))).toBe('https');
    expect(detectService(applied('dns'))).toBe('dns');
    expect(detectService(applied('all'))).toBe('all');
    expect(detectService({ ...inbound, protocol: 'any' })).toBe('all');
    expect(detectService({ ...inbound, protocol: 'udp', destinationPort: '443' })).toBe('custom');
    expect(detectService({ ...inbound, protocol: 'esp' })).toBe('custom');
  });
});

describe('presetDetail', () => {
  it('shows port and protocol of named presets only', () => {
    expect(presetDetail('https')).toBe('443/tcp');
    expect(presetDetail('dns')).toBe('53/tcp+udp');
    expect(presetDetail('all')).toBeUndefined();
  });
});
