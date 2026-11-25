import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { Field } from './Field';

describe('Field', () => {
  it('binds the label to the input and describes it with the hint', () => {
    render(<Field label="Username" hint="3 to 32 characters" name="username" />);
    const input = screen.getByLabelText('Username');
    expect(input).toHaveAttribute('name', 'username');
    expect(input).toHaveAccessibleDescription('3 to 32 characters');
    expect(input).not.toHaveAttribute('aria-invalid');
  });

  it('marks the input invalid and announces the error', () => {
    render(<Field label="Password" hint="At least 12 characters" error="Too short." />);
    const input = screen.getByLabelText('Password');
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveAccessibleDescription('At least 12 characters Too short.');
  });

  it('binds a custom control passed as children', () => {
    render(
      <Field label="Protocol" error="Choose a protocol.">
        {(control) => (
          <select {...control}>
            <option>OpenVPN</option>
          </select>
        )}
      </Field>,
    );
    const select = screen.getByRole('combobox', { name: 'Protocol' });
    expect(select).toHaveAttribute('aria-invalid', 'true');
    expect(select).toHaveAccessibleDescription('Choose a protocol.');
  });
});
