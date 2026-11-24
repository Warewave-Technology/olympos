import { useState } from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { equalityTerms, matchesSelector, parseLabelTerm, parseSelector, validateLabelKey, validateLabelValue } from '../lib/labels';
import { Field } from '../ui/kit';
import { ScopeInput, TagInput } from '../ui/TagInput';

afterEach(cleanup);

describe('label syntax', () => {
  it('validates Kubernetes label keys and values', () => {
    expect(validateLabelKey('env')).toBeNull();
    expect(validateLabelKey('app.kubernetes.io/name')).toBeNull();
    expect(validateLabelKey('Team_A.x')).toBeNull();
    expect(validateLabelKey('-env')).toMatch(/start and end/);
    expect(validateLabelKey('a/b/c')).toMatch(/only one/);
    expect(validateLabelKey('Upper.Case/name')).toMatch(/DNS subdomain/);
    expect(validateLabelKey('x'.repeat(64))).toMatch(/63/);
    expect(validateLabelValue('')).toBeNull();
    expect(validateLabelValue('prod-1')).toBeNull();
    expect(validateLabelValue('has space')).toMatch(/letters, digits/);
    expect(parseLabelTerm('env=prod')).toEqual({ ok: true, key: 'env', value: 'prod' });
    expect(parseLabelTerm('env')).toMatchObject({ ok: false });
    expect(parseLabelTerm('env==prod')).toMatchObject({ ok: false });
  });

  it('parses and matches set-based selectors', () => {
    const labels = { env: 'prod', team: 'data' };
    expect(matchesSelector('env in (prod,staging), team=data', labels)).toBe(true);
    expect(matchesSelector('env notin (prod)', labels)).toBe(false);
    expect(matchesSelector('!legacy,team', labels)).toBe(true);
    expect(matchesSelector('env!=prod', labels)).toBe(false);
    expect(parseSelector('env in (a,b').error).toMatch(/parentheses/);
    expect(equalityTerms('env=prod,team=data')).toEqual(labels);
    expect(equalityTerms('env in (a,b)')).toBeNull();
    expect(equalityTerms('')).toEqual({});
  });
});

function Harness({ initial = {} as Record<string, string>, lockedPrefix, max }: { initial?: Record<string, string>; lockedPrefix?: string; max?: number }) {
  const [v, setV] = useState(initial);
  return (
    <>
      <Field label="Labels" htmlFor="lbl">
        <TagInput id="lbl" value={v} onChange={setV} lockedPrefix={lockedPrefix} max={max} />
      </Field>
      <output data-testid="value">{JSON.stringify(v)}</output>
    </>
  );
}
const value = () => JSON.parse(screen.getByTestId('value').textContent!);

describe('TagInput', () => {
  it('turns key=value into a chip on Enter, comma and Tab', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const input = screen.getByLabelText('Labels');
    await user.type(input, 'env=prod{Enter}');
    expect(value()).toEqual({ env: 'prod' });
    expect(input).toHaveValue('');
    await user.type(input, 'team = data,');
    expect(value()).toEqual({ env: 'prod', team: 'data' });
    await user.type(input, 'site=factory');
    await user.tab();
    expect(value()).toEqual({ env: 'prod', team: 'data', site: 'factory' });
    expect(screen.getByRole('list', { name: 'Labels added' }).querySelectorAll('li')).toHaveLength(3);
  });

  it('rejects invalid text inline and keeps it for fixing', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const input = screen.getByLabelText('Labels');
    await user.type(input, '-bad=x{Enter}');
    expect(value()).toEqual({});
    expect(input).toHaveValue('-bad=x');
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByRole('alert')).toHaveTextContent(/start and end with a letter or digit/);
    expect(input.getAttribute('aria-describedby')).toContain('lbl-tagerr');
    await user.clear(input);
    expect(screen.queryByRole('alert')).toBeNull();
    await user.type(input, 'novalue{Enter}');
    expect(screen.getByRole('alert')).toHaveTextContent('is not key=value');
    await user.clear(input);
    await user.type(input, 'env=prod{Enter}env=dev{Enter}');
    expect(value()).toEqual({ env: 'prod' });
    expect(screen.getByRole('alert')).toHaveTextContent(/already set/);
  });

  it('removes the last chip with Backspace and any chip with its button', async () => {
    const user = userEvent.setup();
    render(<Harness initial={{ env: 'prod', team: 'data', site: 'x' }} />);
    const input = screen.getByLabelText('Labels');
    await user.click(input);
    await user.keyboard('{Backspace}');
    expect(value()).toEqual({ env: 'prod', team: 'data' });
    await user.click(screen.getByRole('button', { name: 'Remove env=prod' }));
    expect(value()).toEqual({ team: 'data' });
    expect(input).toHaveFocus();
    expect(screen.getByText('Removed env=prod')).toBeInTheDocument(); // announced
  });

  it('keeps locked chips: no remove button, Backspace skips them, the prefix cannot be added', async () => {
    const user = userEvent.setup();
    render(<Harness initial={{ 'olympos.io/cluster': 'edge', env: 'dev' }} lockedPrefix="olympos.io/" />);
    expect(screen.queryByRole('button', { name: 'Remove olympos.io/cluster=edge' })).toBeNull();
    const input = screen.getByLabelText('Labels');
    await user.click(input);
    await user.keyboard('{Backspace}{Backspace}');
    expect(value()).toEqual({ 'olympos.io/cluster': 'edge' });
    await user.type(input, 'olympos.io/tier=x{Enter}');
    expect(value()).toEqual({ 'olympos.io/cluster': 'edge' });
    expect(screen.getByRole('alert')).toHaveTextContent('reserved');
  });

  it('creates several chips from pasted a=b,c=d and keeps the invalid rest', async () => {
    render(<Harness />);
    const input = screen.getByLabelText('Labels');
    fireEvent.paste(input, { clipboardData: { getData: () => 'a=b,c=d, bad, e=f' } });
    expect(value()).toEqual({ a: 'b', c: 'd', e: 'f' });
    expect(input).toHaveValue('bad');
    expect(screen.getByRole('alert')).toHaveTextContent('"bad" is not key=value');
  });

  it('takes at most max chips: the field goes when full and comes back when one is removed', async () => {
    const user = userEvent.setup();
    render(<Harness max={1} />);
    fireEvent.paste(screen.getByLabelText('Labels'), { clipboardData: { getData: () => 'team=a,env=b' } });
    expect(value()).toEqual({ team: 'a' });
    expect(screen.getByRole('alert')).toHaveTextContent('Enter at most one label.');
    await user.click(screen.getByRole('button', { name: 'Remove team=a' }));
    const input = screen.getByLabelText('Labels');
    await user.clear(input);
    await user.type(input, 'team=payments');
    await user.tab();
    expect(value()).toEqual({ team: 'payments' });
    expect(screen.queryByRole('textbox')).toBeNull();
    expect(screen.getByRole('list', { name: 'Labels added' })).toHaveTextContent('team=payments');
    await user.click(screen.getByRole('button', { name: 'Remove team=payments' }));
    await waitFor(() => expect(screen.getByLabelText('Labels')).toHaveFocus());
  });

  it('shows chips without remove buttons when read-only', () => {
    render(<TagInput id="ro" value={{ env: 'prod' }} onChange={() => {}} readOnly />);
    expect(screen.getByText('env=prod')).toBeInTheDocument();
    expect(screen.queryByRole('button')).toBeNull();
    expect(screen.queryByRole('textbox')).toBeNull();
  });
});

function ScopeHarness() {
  const [v, setV] = useState('');
  const clusters: { labels: Record<string, string> }[] = [{ labels: { env: 'prod' } }, { labels: { env: 'prod', team: 'data' } }, { labels: { env: 'dev' } }];
  return (
    <>
      <Field label="Scope" htmlFor="sc">
        <ScopeInput id="sc" value={v} onChange={setV} clusters={clusters} />
      </Field>
      <output data-testid="sel">{v}</output>
    </>
  );
}

describe('ScopeInput', () => {
  it('uses chips for equality terms with a live match count, and an advanced selector mode', async () => {
    const user = userEvent.setup();
    render(<ScopeHarness />);
    expect(screen.getByText('All clusters · 3 clusters today')).toBeInTheDocument();
    await user.type(screen.getByLabelText('Scope'), 'env=prod{Enter}');
    expect(screen.getByTestId('sel')).toHaveTextContent('env=prod');
    expect(screen.getByText('Matches 2 clusters of 3 today')).toBeInTheDocument();
    await user.type(screen.getByLabelText('Scope'), 'team=data{Enter}');
    expect(screen.getByTestId('sel')).toHaveTextContent('env=prod,team=data');
    expect(screen.getByText('Matches 1 cluster of 3 today')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Advanced selector' }));
    const text = screen.getByLabelText('Scope');
    expect(text).toHaveValue('env=prod,team=data');
    await user.clear(text);
    await user.type(text, 'env in (prod,dev)');
    expect(screen.getByText('Matches 3 clusters of 3 today')).toBeInTheDocument();
    // set-based terms cannot be chips: the switch back is disabled with the reason shown
    expect(screen.getByRole('button', { name: 'Use label chips' })).toBeDisabled();
    expect(screen.getByText('Only key=value terms can be chips')).toBeInTheDocument();
  });
});
