import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { Button } from './Button';

describe('Button', () => {
  it('defaults to a secondary non-submit button', () => {
    render(<Button>Save changes</Button>);
    const button = screen.getByRole('button', { name: 'Save changes' });
    expect(button).toHaveAttribute('type', 'button');
    expect(button.className).toMatch(/secondary/);
  });

  it('applies the requested variant', () => {
    render(<Button variant="danger">Delete profile</Button>);
    expect(screen.getByRole('button', { name: 'Delete profile' }).className).toMatch(/danger/);
  });

  it('applies the small size only when requested', () => {
    render(
      <>
        <Button size="small">Edit</Button>
        <Button>Save</Button>
      </>,
    );
    expect(screen.getByRole('button', { name: 'Edit' }).className).toMatch(/small/);
    expect(screen.getByRole('button', { name: 'Save' }).className).not.toMatch(/small/);
  });

  it('calls onClick when pressed', () => {
    const onClick = vi.fn();
    render(<Button onClick={onClick}>Connect</Button>);
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
    expect(onClick).toHaveBeenCalledOnce();
  });

  it('keeps its label and blocks clicks while loading', () => {
    const onClick = vi.fn();
    render(
      <Button loading onClick={onClick}>
        Connect
      </Button>,
    );
    const button = screen.getByRole('button', { name: 'Connect' });
    expect(button).toHaveAttribute('aria-busy', 'true');
    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(onClick).not.toHaveBeenCalled();
  });
});
