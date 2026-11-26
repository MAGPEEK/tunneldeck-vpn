import { describe, expect, it } from 'vitest';
import { editorSteps, intentDraft, intentOf } from './intents';
import { newDraft } from './ruleDraft';

const HOST = '192.168.1.10';

describe('intentDraft', () => {
  it('presets direction, action, service and destination per intent', () => {
    expect(intentDraft('forward', HOST)).toMatchObject({
      direction: 'inbound',
      action: 'accept',
      protocol: 'tcp',
      destinationPort: '443',
      destination: '',
    });
    expect(intentDraft('hostService', HOST)).toMatchObject({
      direction: 'inbound',
      action: 'accept',
      destination: HOST,
      destinationPort: '443',
    });
    expect(intentDraft('outbound', HOST)).toMatchObject({
      direction: 'outbound',
      action: 'accept',
      protocol: 'any',
      destination: '',
    });
    expect(intentDraft('block', HOST)).toMatchObject({
      direction: 'inbound',
      action: 'drop',
      protocol: 'any',
      destination: HOST,
    });
    expect(intentDraft('custom', HOST)).toMatchObject({
      direction: 'inbound',
      action: 'accept',
      destination: '',
    });
  });
});

describe('intentOf', () => {
  it('derives the intent of a stored rule', () => {
    const hosts = [HOST];
    expect(intentOf({ ...newDraft('outbound') }, hosts)).toBe('outbound');
    expect(intentOf({ ...newDraft('inbound'), action: 'reject', destination: HOST }, hosts)).toBe(
      'block',
    );
    expect(intentOf({ ...newDraft('inbound'), destination: HOST }, hosts)).toBe('hostService');
    expect(intentOf({ ...newDraft('inbound'), destination: '192.168.1.2' }, hosts)).toBe('forward');
  });
});

describe('editorSteps', () => {
  it('shows only the steps of each intent', () => {
    expect(editorSteps('forward', intentDraft('forward', HOST))).toEqual([
      'device',
      'service',
      'name',
    ]);
    expect(editorSteps('outbound', intentDraft('outbound', HOST))).toEqual([
      'device',
      'destination',
      'service',
      'name',
    ]);
    expect(editorSteps('block', intentDraft('block', HOST))).toEqual([
      'rule',
      'device',
      'service',
      'name',
    ]);
    expect(editorSteps('custom', newDraft('outbound'))).toEqual([
      'rule',
      'device',
      'destination',
      'service',
      'name',
    ]);
  });
});
