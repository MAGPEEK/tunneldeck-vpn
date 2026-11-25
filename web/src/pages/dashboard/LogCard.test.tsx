import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { LogLine } from '../../api/connection';
import { LogCard } from './LogCard';

const firstLine: LogLine = {
  time: '2026-11-25T10:00:00Z',
  level: 'info',
  text: 'TCP/UDP: Preserving recently used remote address',
};

const lines: LogLine[] = [
  firstLine,
  { time: '2026-11-25T10:00:01Z', level: 'warn', text: 'WARNING: No encryption' },
  { time: '2026-11-25T10:00:02Z', level: 'error', text: 'AUTH_FAILED' },
];

function shownTexts(): string[] {
  return Array.from(screen.getByRole('log').querySelectorAll('[data-level]')).map(
    (element) => element.textContent ?? '',
  );
}

/** jsdom has no layout; give the log body a scroll geometry. */
function setGeometry(body: HTMLElement, scrollTop: number) {
  Object.defineProperty(body, 'scrollHeight', { configurable: true, value: 1000 });
  Object.defineProperty(body, 'clientHeight', { configurable: true, value: 360 });
  body.scrollTop = scrollTop;
}

describe('LogCard', () => {
  it('renders lines with level colours and filters by level', () => {
    render(<LogCard lines={lines} />);
    expect(shownTexts()).toHaveLength(3);
    expect(screen.getByText('AUTH_FAILED').closest('[data-level]')).toHaveAttribute(
      'data-level',
      'error',
    );

    fireEvent.change(screen.getByRole('combobox', { name: 'Level' }), {
      target: { value: 'warnings' },
    });
    expect(shownTexts()).toHaveLength(2);

    fireEvent.change(screen.getByRole('combobox', { name: 'Level' }), {
      target: { value: 'errors' },
    });
    expect(shownTexts()).toEqual([expect.stringContaining('AUTH_FAILED')]);
  });

  it('filters by text', () => {
    render(<LogCard lines={lines} />);
    fireEvent.change(screen.getByRole('searchbox', { name: 'Filter log text' }), {
      target: { value: 'encryption' },
    });
    expect(shownTexts()).toEqual([expect.stringContaining('WARNING: No encryption')]);
  });

  it('copies the filtered lines', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
    render(<LogCard lines={lines} />);
    fireEvent.change(screen.getByRole('combobox', { name: 'Level' }), {
      target: { value: 'errors' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Copy' }));

    expect(await screen.findByRole('button', { name: 'Copied' })).toBeInTheDocument();
    expect(writeText).toHaveBeenCalledWith(expect.stringMatching(/^\d\d:\d\d:\d\d AUTH_FAILED$/));
  });

  it('follows new lines until the user scrolls up, then offers Jump to latest', () => {
    const { rerender } = render(<LogCard lines={lines} />);
    const body = screen.getByRole('log');
    setGeometry(body, 640);
    rerender(<LogCard lines={[...lines, { ...firstLine, text: 'newer' }]} />);
    expect(body.scrollTop).toBe(1000);
    expect(screen.queryByRole('button', { name: 'Jump to latest' })).not.toBeInTheDocument();

    body.scrollTop = 100;
    fireEvent.scroll(body);
    rerender(<LogCard lines={[...lines, { ...firstLine, text: 'newest' }]} />);
    expect(body.scrollTop).toBe(100);

    fireEvent.click(screen.getByRole('button', { name: 'Jump to latest' }));
    expect(body.scrollTop).toBe(1000);
    expect(screen.queryByRole('button', { name: 'Jump to latest' })).not.toBeInTheDocument();
  });

  it('says when there are no lines', () => {
    render(<LogCard lines={[]} />);
    expect(screen.getByText('No log lines')).toBeInTheDocument();
  });
});
