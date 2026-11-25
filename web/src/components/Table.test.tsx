import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { Table, type Column } from './Table';

interface Rule {
  id: string;
  protocol: string;
  port: number;
}

const columns: Column<Rule>[] = [
  { key: 'protocol', header: 'Protocol', render: (rule) => rule.protocol },
  { key: 'port', header: 'Port', render: (rule) => rule.port, align: 'end' },
];

describe('Table', () => {
  it('renders column headers and one row per item', () => {
    render(
      <Table
        caption="Host-access rules"
        columns={columns}
        rows={[
          { id: 'a', protocol: 'tcp', port: 443 },
          { id: 'b', protocol: 'udp', port: 1194 },
        ]}
        rowKey={(rule) => rule.id}
        emptyMessage="No rules yet."
      />,
    );
    const table = screen.getByRole('table', { name: 'Host-access rules' });
    expect(
      within(table)
        .getAllByRole('columnheader')
        .map((th) => th.textContent),
    ).toEqual(['Protocol', 'Port']);
    const rows = within(table).getAllByRole('row');
    expect(rows).toHaveLength(3);
    expect(rows[2]).toHaveTextContent('udp1194');
  });

  it('shows the empty message across all columns', () => {
    render(
      <Table columns={columns} rows={[]} rowKey={(rule) => rule.id} emptyMessage="No rules yet." />,
    );
    const cell = screen.getByRole('cell', { name: 'No rules yet.' });
    expect(cell).toHaveAttribute('colspan', '2');
  });
});
