import { Fragment, type ReactNode } from 'react';
import styles from './Table.module.css';

export interface Column<Row> {
  key: string;
  header: ReactNode;
  render: (row: Row) => ReactNode;
  align?: 'start' | 'end';
}

export interface TableProps<Row> {
  columns: Column<Row>[];
  rows: Row[];
  rowKey: (row: Row) => string;
  emptyMessage: ReactNode;
  caption?: ReactNode;
  /** Content of an extra full-width row under a row, such as an inline confirmation. */
  rowDetail?: (row: Row) => ReactNode;
  /** Marks a row, such as `highlighted` for an unsaved insert (styled in Table.module.css). */
  rowState?: (row: Row) => 'highlighted' | undefined;
}

export function Table<Row>({
  columns,
  rows,
  rowKey,
  emptyMessage,
  caption,
  rowDetail,
  rowState,
}: TableProps<Row>) {
  const alignClass = (column: Column<Row>) => (column.align === 'end' ? styles.end : undefined);
  return (
    <div className={styles.wrapper}>
      <table className={styles.table}>
        {caption !== undefined && <caption className="visually-hidden">{caption}</caption>}
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key} scope="col" className={alignClass(column)}>
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className={styles.empty}>
                {emptyMessage}
              </td>
            </tr>
          ) : (
            rows.map((row) => {
              const detail = rowDetail?.(row);
              return (
                <Fragment key={rowKey(row)}>
                  <tr data-state={rowState?.(row)}>
                    {columns.map((column) => (
                      <td key={column.key} className={alignClass(column)}>
                        {column.render(row)}
                      </td>
                    ))}
                  </tr>
                  {detail !== undefined && detail !== null && (
                    <tr className={styles.detail}>
                      <td colSpan={columns.length}>{detail}</td>
                    </tr>
                  )}
                </Fragment>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
