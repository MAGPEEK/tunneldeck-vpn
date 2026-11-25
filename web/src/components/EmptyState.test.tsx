import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { EmptyState } from './EmptyState';

describe('EmptyState', () => {
  it('renders title, body and action', () => {
    render(
      <EmptyState
        title="Add your first VPN profile"
        body="Profiles hold the server and credentials."
        action={<button type="button">Create profile</button>}
      />,
    );
    expect(screen.getByRole('heading', { name: 'Add your first VPN profile' })).toBeInTheDocument();
    expect(screen.getByText('Profiles hold the server and credentials.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create profile' })).toBeInTheDocument();
  });

  it('renders without an action', () => {
    render(<EmptyState title="Nothing here" body="No entries yet." />);
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
});
