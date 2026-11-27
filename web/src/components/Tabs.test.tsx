import { fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { describe, expect, it } from 'vitest';
import { Tabs } from './Tabs';

const TABS = [
  { id: 'one', label: 'One' },
  { id: 'two', label: 'Two' },
  { id: 'three', label: 'Three' },
];

function Harness() {
  const [active, setActive] = useState('one');
  return (
    <Tabs label="Views" tabs={TABS} active={active} onChange={setActive}>
      <p>Panel {active}</p>
    </Tabs>
  );
}

describe('Tabs', () => {
  it('exposes the ARIA tab roles and links the panel to the selected tab', () => {
    render(<Harness />);
    expect(screen.getByRole('tablist', { name: 'Views' })).toBeInTheDocument();
    const selected = screen.getByRole('tab', { name: 'One', selected: true });
    const panel = screen.getByRole('tabpanel');
    expect(panel).toHaveTextContent('Panel one');
    expect(panel).toHaveAttribute('aria-labelledby', selected.id);
    expect(selected).toHaveAttribute('aria-controls', panel.id);
  });

  it('keeps only the selected tab in the tab sequence', () => {
    render(<Harness />);
    expect(screen.getByRole('tab', { name: 'One' })).toHaveAttribute('tabindex', '0');
    expect(screen.getByRole('tab', { name: 'Two' })).toHaveAttribute('tabindex', '-1');
  });

  it('selects a tab on click', () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole('tab', { name: 'Two' }));
    expect(screen.getByRole('tab', { name: 'Two', selected: true })).toBeInTheDocument();
    expect(screen.getByRole('tabpanel')).toHaveTextContent('Panel two');
  });

  it('moves the selection with the arrow keys and wraps around', () => {
    render(<Harness />);
    const tablist = screen.getByRole('tablist');
    fireEvent.keyDown(tablist, { key: 'ArrowRight' });
    expect(screen.getByRole('tab', { name: 'Two', selected: true })).toBeInTheDocument();
    fireEvent.keyDown(tablist, { key: 'ArrowLeft' });
    expect(screen.getByRole('tab', { name: 'One', selected: true })).toBeInTheDocument();
    fireEvent.keyDown(tablist, { key: 'ArrowLeft' });
    expect(screen.getByRole('tab', { name: 'Three', selected: true })).toBeInTheDocument();
    fireEvent.keyDown(tablist, { key: 'Home' });
    expect(screen.getByRole('tab', { name: 'One', selected: true })).toBeInTheDocument();
    fireEvent.keyDown(tablist, { key: 'End' });
    expect(screen.getByRole('tab', { name: 'Three', selected: true })).toBeInTheDocument();
  });
});
