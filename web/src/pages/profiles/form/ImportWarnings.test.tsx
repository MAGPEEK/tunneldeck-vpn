import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { ImportWarning } from '../../../api/profiles';
import { ImportWarnings } from './ImportWarnings';

function warning(fields: Partial<ImportWarning>): ImportWarning {
  return { code: 'unknown', severity: 'info', message: 'server text', ...fields };
}

describe('ImportWarnings', () => {
  it.each([
    [
      'a further [Interface] section',
      warning({ code: 'additional_interface', directive: '[Interface]', line: 7 }),
      'is a further [Interface] section; its keys are merged into the first one.',
    ],
    [
      'the number of notes left out',
      warning({ code: 'warnings_limited', count: 12 }),
      '12 more notes are not listed.',
    ],
    ['an unknown code with the server text', warning({ code: 'brand_new' }), 'server text'],
  ])('describes %s', (_name, entry, text) => {
    render(<ImportWarnings warnings={[entry]} />);
    expect(screen.getByRole('listitem')).toHaveTextContent(text);
  });
});
