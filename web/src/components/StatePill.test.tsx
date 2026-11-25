import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { StatePill } from './StatePill';

describe('StatePill', () => {
  it('defaults to the neutral tone without a dot', () => {
    const { container } = render(<StatePill>Disconnected</StatePill>);
    const pill = screen.getByText('Disconnected');
    expect(pill).toHaveAttribute('data-tone', 'neutral');
    expect(container.querySelector('[aria-hidden="true"]')).toBeNull();
  });

  it('renders the tone and a decorative dot', () => {
    const { container } = render(
      <StatePill tone="success" dot>
        Connected
      </StatePill>,
    );
    expect(screen.getByText('Connected')).toHaveAttribute('data-tone', 'success');
    expect(container.querySelector('[aria-hidden="true"]')).not.toBeNull();
  });
});
