import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Field, Modal } from '../ui/kit';
import { Select, type SelectOption } from '../ui/Select';

afterEach(cleanup);

const FRUIT: SelectOption[] = [
  { value: 'apple', label: 'Apple' },
  { value: 'banana', label: 'Banana' },
  { value: 'blueberry', label: 'Blueberry', disabled: true },
  { value: 'cherry', label: 'Cherry' },
  { value: 'date', label: 'Date' },
];

function Harness({ onChange = () => {}, initial = 'banana', options = FRUIT, searchable = false }: { onChange?: (v: string) => void; initial?: string; options?: SelectOption[]; searchable?: boolean }) {
  const [v, setV] = useState(initial);
  return (
    <Field label="Fruit" htmlFor="fruit">
      <Select
        id="fruit"
        value={v}
        searchable={searchable}
        onChange={(x) => {
          setV(x);
          onChange(x);
        }}
        options={options}
      />
    </Field>
  );
}

const activeOption = () => {
  const id = screen.getByRole('combobox').getAttribute('aria-activedescendant');
  return id ? document.getElementById(id) : null;
};

describe('Select', () => {
  it('is a labelled combobox that opens a listbox with the selected option active', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const cb = screen.getByRole('combobox', { name: 'Fruit' });
    expect(cb).toHaveAttribute('aria-haspopup', 'listbox');
    expect(cb).toHaveAttribute('aria-expanded', 'false');
    expect(cb).toHaveTextContent('Banana');
    expect(screen.queryByRole('listbox')).toBeNull();

    cb.focus();
    await user.keyboard('{ArrowDown}');
    expect(cb).toHaveAttribute('aria-expanded', 'true');
    const lb = screen.getByRole('listbox', { name: 'Fruit' });
    expect(cb).toHaveAttribute('aria-controls', lb.id);
    expect(screen.getAllByRole('option')).toHaveLength(5);
    expect(screen.getByRole('option', { name: 'Banana' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('option', { name: 'Blueberry' })).toHaveAttribute('aria-disabled', 'true');
    expect(activeOption()).toHaveTextContent('Banana');
    expect(cb).toHaveFocus(); // focus stays on the trigger (aria-activedescendant)
  });

  it('moves with arrows / Home / End, skips disabled options and chooses with Enter', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<Harness onChange={onChange} />);
    const cb = screen.getByRole('combobox');
    cb.focus();
    await user.keyboard('{Enter}');
    await user.keyboard('{ArrowDown}'); // Blueberry is disabled → Cherry
    expect(activeOption()).toHaveTextContent('Cherry');
    await user.keyboard('{End}');
    expect(activeOption()).toHaveTextContent('Date');
    await user.keyboard('{ArrowDown}'); // stays at the end
    expect(activeOption()).toHaveTextContent('Date');
    await user.keyboard('{Home}');
    expect(activeOption()).toHaveTextContent('Apple');
    await user.keyboard('{ArrowUp}');
    expect(activeOption()).toHaveTextContent('Apple');
    await user.keyboard('{ArrowDown}{ArrowDown}{ArrowUp}'); // Banana → Cherry → Banana
    expect(activeOption()).toHaveTextContent('Banana');
    await user.keyboard('{End}{Enter}');
    expect(onChange).toHaveBeenCalledWith('date');
    expect(cb).toHaveAttribute('aria-expanded', 'false');
    expect(cb).toHaveTextContent('Date');
    expect(cb).toHaveFocus();
  });

  it('jumps by typeahead and cycles on a repeated letter', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<Harness onChange={onChange} initial="apple" />);
    const cb = screen.getByRole('combobox');
    cb.focus();
    await user.keyboard('c'); // closed: opens on the match
    expect(cb).toHaveAttribute('aria-expanded', 'true');
    expect(activeOption()).toHaveTextContent('Cherry');
    await user.keyboard('h'); // "ch" is still Cherry (prefix match)
    expect(activeOption()).toHaveTextContent('Cherry');
    await new Promise((r) => setTimeout(r, 750)); // typeahead buffer resets
    await user.keyboard('d');
    expect(activeOption()).toHaveTextContent('Date');
    await user.keyboard('{Escape}');
    await new Promise((r) => setTimeout(r, 750)); // typeahead buffer resets
    await user.keyboard('{ArrowDown}b');
    expect(activeOption()).toHaveTextContent('Banana'); // disabled Blueberry never matches
    await user.keyboard(' ');
    expect(onChange).toHaveBeenLastCalledWith('banana');
  });

  it('Esc closes without changing the value and does not close an enclosing dialog', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    const onClose = vi.fn();
    render(
      <Modal open onClose={onClose} title="Pick">
        <Harness onChange={onChange} />
      </Modal>,
    );
    const cb = screen.getByRole('combobox', { name: 'Fruit' });
    await user.click(cb);
    expect(screen.getByRole('listbox')).toBeInTheDocument();
    await user.keyboard('{ArrowDown}{Escape}');
    expect(screen.queryByRole('listbox')).toBeNull();
    expect(onChange).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(cb).toHaveFocus();
    await user.keyboard('{Escape}'); // now the dialog closes
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('chooses with the mouse and ignores disabled options; outside click closes', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <>
        <Harness onChange={onChange} />
        <button type="button">elsewhere</button>
      </>,
    );
    await user.click(screen.getByRole('combobox'));
    await user.click(screen.getByRole('option', { name: 'Blueberry' }));
    expect(onChange).not.toHaveBeenCalled();
    expect(screen.getByRole('listbox')).toBeInTheDocument();
    await user.click(screen.getByRole('option', { name: 'Cherry' }));
    expect(onChange).toHaveBeenCalledWith('cherry');
    expect(screen.queryByRole('listbox')).toBeNull();
    await user.click(screen.getByRole('combobox'));
    await user.click(screen.getByRole('button', { name: 'elsewhere' }));
    expect(screen.queryByRole('listbox')).toBeNull();
  });

  it('filters long lists when searchable', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    const zones = ['Europe/Berlin', 'Europe/Istanbul', 'Asia/Tokyo', 'America/New_York', 'UTC'].map((z) => ({ value: z, label: z }));
    render(<Harness options={zones} initial="UTC" searchable onChange={onChange} />);
    await user.click(screen.getByRole('combobox'));
    const search = screen.getByRole('searchbox', { name: 'Filter options' });
    expect(search).toHaveFocus();
    await user.type(search, 'tok');
    expect(screen.getAllByRole('option').map((o) => o.textContent)).toEqual(['Asia/Tokyo']);
    expect(document.getElementById(search.getAttribute('aria-activedescendant')!)).toHaveTextContent('Asia/Tokyo');
    await user.keyboard('{Enter}');
    expect(onChange).toHaveBeenCalledWith('Asia/Tokyo');
    expect(screen.getByRole('combobox')).toHaveFocus();
    await user.click(screen.getByRole('combobox'));
    await user.type(screen.getByRole('searchbox'), 'zzz');
    expect(screen.queryAllByRole('option')).toHaveLength(0);
    expect(screen.getByText(/Nothing matches/)).toBeInTheDocument();
  });

  it('shows the error state and can be disabled', () => {
    render(
      <>
        <Select aria-label="Broken" value="" onChange={() => {}} options={FRUIT} invalid placeholder="Pick one" />
        <Select aria-label="Off" value="apple" onChange={() => {}} options={FRUIT} disabled />
      </>,
    );
    const broken = screen.getByRole('combobox', { name: 'Broken' });
    expect(broken).toHaveAttribute('aria-invalid', 'true');
    expect(broken).toHaveTextContent('Pick one');
    expect(screen.getByRole('combobox', { name: 'Off' })).toBeDisabled();
  });
});
