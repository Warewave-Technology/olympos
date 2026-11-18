import { useState } from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Field } from '../ui/kit';
import { TagInput, validateDatabaseName } from '../ui/TagInput';

afterEach(cleanup);

function Harness({ initial = [] as string[] }) {
  const [v, setV] = useState(initial);
  const [draft, setDraft] = useState<string | null>(null);
  return (
    <>
      <Field label="Databases" htmlFor="dbs">
        <TagInput id="dbs" mode="values" value={v} onChange={setV} validate={validateDatabaseName} listLabel="Databases to back up" onDraftError={setDraft} />
      </Field>
      <output data-testid="value">{JSON.stringify(v)}</output>
      <output data-testid="draft">{draft ?? ''}</output>
    </>
  );
}
const value = () => JSON.parse(screen.getByTestId('value').textContent!);

describe('TagInput mode="values"', () => {
  it('turns plain names into chips on Enter, comma, space and Tab (no key=value needed)', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const input = screen.getByLabelText('Databases');
    await user.type(input, 'orders{Enter}');
    expect(value()).toEqual(['orders']);
    await user.type(input, 'billing,');
    await user.type(input, 'audit_log ');
    await user.type(input, 'reports');
    await user.tab();
    expect(value()).toEqual(['orders', 'billing', 'audit_log', 'reports']);
    expect(screen.getByRole('list', { name: 'Databases to back up' }).querySelectorAll('li')).toHaveLength(4);
  });

  it('splits a pasted list, ignores duplicates and removes chips', async () => {
    const user = userEvent.setup();
    render(<Harness initial={['orders']} />);
    const input = screen.getByLabelText('Databases');
    fireEvent.paste(input, { clipboardData: { getData: () => 'orders, postgres\nanalytics' } });
    expect(value()).toEqual(['orders', 'postgres', 'analytics']);
    await user.click(screen.getByRole('button', { name: 'Remove postgres' }));
    expect(value()).toEqual(['orders', 'analytics']);
    await user.click(input);
    await user.keyboard('{Backspace}');
    expect(value()).toEqual(['orders']);
  });

  it('keeps invalid names in the field with a message and reports the draft error', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const input = screen.getByLabelText('Databases');
    await user.type(input, 'bad"name{Enter}');
    expect(value()).toEqual([]);
    expect(input).toHaveValue('bad"name');
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByRole('alert')).toHaveTextContent(/quote or backslash/);
    expect(screen.getByTestId('draft')).toHaveTextContent(/quote/);
    expect(validateDatabaseName('x'.repeat(64))).toMatch(/63/);
    expect(validateDatabaseName('orders')).toBeNull();
  });
});
