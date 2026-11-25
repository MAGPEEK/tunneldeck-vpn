import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { Card } from './Card';

describe('Card', () => {
  it('renders the title as a heading that names the region, with actions', () => {
    render(
      <Card title="Connection" actions={<button type="button">Reconnect</button>}>
        Connected
      </Card>,
    );
    expect(screen.getByRole('heading', { name: 'Connection' })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Connection' })).toHaveTextContent('Connected');
    expect(screen.getByRole('button', { name: 'Reconnect' })).toBeInTheDocument();
  });

  it('renders only the body without title or actions', () => {
    render(<Card>Plain content</Card>);
    expect(screen.queryByRole('heading')).not.toBeInTheDocument();
    expect(screen.getByText('Plain content')).toBeInTheDocument();
  });
});
