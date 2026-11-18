import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DataTable, type Column } from '../ui/DataTable';
import { joinPath } from '../lib/format';

afterEach(cleanup);

interface Row {
  id: string;
  name: string;
  n: number;
}
const rows: Row[] = Array.from({ length: 60 }, (_, i) => ({ id: `r${i}`, name: `item-${String(i).padStart(2, '0')}`, n: (i * 7) % 60 }));
const columns: Column<Row>[] = [
  { id: 'name', header: 'Name', sortValue: (r) => r.name, cell: (r) => r.name },
  { id: 'n', header: 'Count', align: 'num', sortValue: (r) => r.n, defaultDir: 'desc', cell: (r) => r.n },
  { id: 'plain', header: 'Plain', cell: () => 'x' },
];

const bodyRows = () => within(screen.getByRole('table')).getAllByRole('row').slice(1);
const firstCell = (i = 0) => within(bodyRows()[i]).getAllByRole('cell')[0].textContent;

describe('DataTable', () => {
  it('sorts by a column with keyboard-accessible headers and aria-sort', async () => {
    const user = userEvent.setup();
    render(<DataTable label="Things" rows={rows} columns={columns} rowKey={(r) => r.id} />);
    const [nameTh, countTh, plainTh] = screen.getAllByRole('columnheader');
    expect(nameTh).toHaveAttribute('aria-sort', 'none');
    expect(plainTh).not.toHaveAttribute('aria-sort');
    expect(within(plainTh).queryByRole('button')).toBeNull();

    // keyboard: focus the header button and press Enter (asc), then Space (desc)
    const nameBtn = within(nameTh).getByRole('button', { name: 'Name' });
    nameBtn.focus();
    await user.keyboard('{Enter}');
    expect(nameTh).toHaveAttribute('aria-sort', 'ascending');
    expect(firstCell()).toBe('item-00');
    await user.keyboard(' ');
    expect(nameTh).toHaveAttribute('aria-sort', 'descending');
    expect(firstCell()).toBe('item-59');

    // numeric column starts with its default direction (desc)
    await user.click(within(countTh).getByRole('button', { name: 'Count' }));
    expect(countTh).toHaveAttribute('aria-sort', 'descending');
    expect(nameTh).toHaveAttribute('aria-sort', 'none');
    expect(within(bodyRows()[0]).getAllByRole('cell')[1]).toHaveTextContent('59');
  });

  it('paginates 25 per page, shows the range and changes the page size', async () => {
    const user = userEvent.setup();
    render(<DataTable label="Things" rows={rows} columns={columns} rowKey={(r) => r.id} initialSort={{ id: 'name', dir: 'asc' }} />);
    expect(bodyRows()).toHaveLength(25);
    expect(screen.getByText('1–25 of 60')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Next page' }));
    expect(screen.getByText('26–50 of 60')).toBeInTheDocument();
    expect(firstCell()).toBe('item-25');
    await user.click(screen.getByRole('button', { name: 'Next page' }));
    expect(screen.getByText('51–60 of 60')).toBeInTheDocument();
    expect(bodyRows()).toHaveLength(10);
    expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();

    // page size via the custom Select; goes back to the first page
    await user.click(screen.getByRole('combobox', { name: 'Rows per page' }));
    await user.click(screen.getByRole('option', { name: '50' }));
    expect(screen.getByText('1–50 of 60')).toBeInTheDocument();
    expect(bodyRows()).toHaveLength(50);
    expect(screen.getByText('Page 1 of 2')).toBeInTheDocument();
  });

  it('filters with the text hook-in and shows the no-match state', async () => {
    const { rerender } = render(<DataTable label="Things" rows={rows} columns={columns} rowKey={(r) => r.id} filterText="item-1" />);
    expect(bodyRows()).toHaveLength(10);
    expect(screen.getByText(/filtered from 60/)).toBeInTheDocument();
    rerender(<DataTable label="Things" rows={rows} columns={columns} rowKey={(r) => r.id} filterText="nothing-like-this" />);
    expect(screen.getByText('Nothing matches')).toBeInTheDocument();
  });

  it('renders loading, error and empty states', () => {
    const { rerender } = render(<DataTable label="Things" what="things" rows={undefined} loading columns={columns} rowKey={(r) => r.id} />);
    expect(screen.getByText('Loading things…')).toBeInTheDocument();
    rerender(<DataTable label="Things" what="things" rows={undefined} error={new Error('boom')} columns={columns} rowKey={(r) => r.id} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Could not load things');
    rerender(<DataTable label="Things" what="things" rows={[]} columns={columns} rowKey={(r) => r.id} empty={<p>Nothing yet, add one</p>} />);
    expect(screen.getByText('Nothing yet, add one')).toBeInTheDocument();
  });

  it('activates rows by click, Enter and Space, but not from inner buttons', async () => {
    const user = userEvent.setup();
    const onRow = vi.fn();
    const onBtn = vi.fn();
    const cols: Column<Row>[] = [...columns, { id: 'act', header: 'Actions', srOnlyHeader: true, cell: (r) => <button type="button" onClick={() => onBtn(r.id)}>Act {r.id}</button> }];
    render(<DataTable label="Things" rows={rows.slice(0, 3)} columns={cols} rowKey={(r) => r.id} onRowClick={(r) => onRow(r.id)} rowLabel={(r) => `Open ${r.name}`} />);
    const row = screen.getByRole('row', { name: 'Open item-01' });
    await user.click(within(row).getAllByRole('cell')[0]);
    expect(onRow).toHaveBeenLastCalledWith('r1');
    row.focus();
    await user.keyboard('{Enter}');
    await user.keyboard(' ');
    expect(onRow).toHaveBeenCalledTimes(3);
    await user.click(screen.getByRole('button', { name: 'Act r2' }));
    expect(onBtn).toHaveBeenCalledWith('r2');
    expect(onRow).toHaveBeenCalledTimes(3);
  });
});

describe('joinPath', () => {
  it('joins storage segments with exactly one slash', () => {
    expect(joinPath('olympos', 'olympos-lab', 'lab', 'orders-pg', 'postgresql')).toBe('olympos/olympos-lab/lab/orders-pg/postgresql');
    expect(joinPath('olympos/', '/olympos-lab/', 'lab')).toBe('olympos/olympos-lab/lab');
    expect(joinPath('', 'a', '', 'b')).toBe('a/b');
    expect(joinPath(' olympos// ', 'a//b')).toBe('olympos/a/b');
    expect(joinPath('/mnt/nfs/', 'x')).toBe('/mnt/nfs/x');
    expect(joinPath(undefined, '/')).toBe('');
  });
});
