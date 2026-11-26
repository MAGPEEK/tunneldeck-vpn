import { newDraft, isToHost, type RuleDraft } from './ruleDraft';
import { serviceChange } from './services';

/** What the user wants to do; each "Add rule" card is one intent (SPEC §16.4). */
export type Intent = 'forward' | 'hostService' | 'outbound' | 'ipsec' | 'block' | 'custom';

/** The intents that open the step editor; "ipsec" opens the template form. */
export type EditorIntent = Exclude<Intent, 'ipsec'>;

export const INTENTS: Intent[] = ['forward', 'hostService', 'outbound', 'ipsec', 'block', 'custom'];

/** A numbered section of the step editor. */
export type EditorStep = 'rule' | 'device' | 'destination' | 'service' | 'name';

/** A new draft with the direction, action, service and destination the intent presets. */
export function intentDraft(intent: EditorIntent, hostAddress: string): RuleDraft {
  switch (intent) {
    case 'forward':
      return withService(newDraft('inbound'), 'https');
    case 'hostService':
      return { ...withService(newDraft('inbound'), 'https'), destination: hostAddress };
    case 'outbound':
      return newDraft('outbound');
    case 'block': {
      const draft: RuleDraft = { ...newDraft('inbound'), action: 'drop', destination: hostAddress };
      return withService(draft, 'all');
    }
    case 'custom':
      return newDraft('inbound');
  }
}

function withService(draft: RuleDraft, service: 'https' | 'all'): RuleDraft {
  return { ...draft, ...serviceChange(service, draft) };
}

/** The intent an existing rule is edited with. */
export function intentOf(draft: RuleDraft, hostAddresses: readonly string[]): EditorIntent {
  if (draft.direction === 'outbound') {
    return 'outbound';
  }
  if (draft.action !== 'accept') {
    return 'block';
  }
  return isToHost(draft, hostAddresses) ? 'hostService' : 'forward';
}

/** The steps the editor shows for an intent, in order. */
export function editorSteps(intent: EditorIntent, draft: RuleDraft): EditorStep[] {
  const destination: EditorStep[] = draft.direction === 'outbound' ? ['destination'] : [];
  const rule: EditorStep[] = intent === 'block' || intent === 'custom' ? ['rule'] : [];
  return [...rule, 'device', ...destination, 'service', 'name'];
}
