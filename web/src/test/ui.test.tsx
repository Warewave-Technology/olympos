import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ChangeRequest, SecretDetail, Vault } from '../api/types';
import { Drawer, SecretValue } from '../ui/kit';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('secret values', () => {
  it('render as a fixed mask labelled "Value hidden", with no reveal control', () => {
    render(<SecretValue />);
    const el = screen.getByLabelText('Value hidden');
    expect(el).toHaveTextContent('••••••••');
    expect(screen.queryByRole('button')).toBeNull();
    // the component intentionally takes no value prop
    expect(SecretValue.length).toBe(0);
  });
});

function DrawerHarness({ onClose }: { onClose: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        open drawer
      </button>
      <Drawer
        open={open}
        onClose={() => {
          onClose();
          setOpen(false);
        }}
        eyebrow="New change request"
        title="Replace KEY"
      >
        <input aria-label="first field" />
        <input aria-label="second field" />
        <button type="button">Submit</button>
      </Drawer>
    </>
  );
}

describe('drawer focus trap', () => {
  it('is a labelled modal dialog that traps Tab, closes on Esc and restores focus', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<DrawerHarness onClose={onClose} />);
    const opener = screen.getByRole('button', { name: 'open drawer' });
    await user.click(opener);

    const dialog = screen.getByRole('dialog', { name: 'Replace KEY' });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    // first form field gets focus (not the close button)
    expect(screen.getByLabelText('first field')).toHaveFocus();

    await user.tab();
    expect(screen.getByLabelText('second field')).toHaveFocus();
    await user.tab();
    expect(screen.getByRole('button', { name: 'Submit' })).toHaveFocus();
    await user.tab(); // wraps to the first focusable (Close)
    expect(screen.getByRole('button', { name: 'Close' })).toHaveFocus();
    await user.tab({ shift: true }); // and back to the last
    expect(screen.getByRole('button', { name: 'Submit' })).toHaveFocus();

    // focus that escapes (e.g. a click outside) is pulled back in
    act(() => opener.focus());
    expect(dialog.contains(document.activeElement)).toBe(true);

    await user.keyboard('{Escape}');
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(opener).toHaveFocus();
  });
});

describe('change request drawer', () => {
  it('sends the value once, never keeps it in the DOM, and shows only the fingerprint', async () => {
    const { ChangeRequestDrawer } = await import('../pages/VaultDialogs');
    const sent: unknown[] = [];
    const fetchMock = vi.fn(async (_url: string, init: RequestInit) => {
      sent.push(JSON.parse(String(init.body)));
      const cr: Partial<ChangeRequest> = {
        id: 'cr-1',
        number: 'CR-0200',
        items: [{ id: 'i', mount: 'kv/', path: 'erp/payments', key: 'API_KEY', op: 'replace', base_version: 7, versions: [], fingerprint: 'hm:aaaa·bbbb·cccc' }],
      };
      return new Response(JSON.stringify(cr), { status: 201, headers: { 'Content-Type': 'application/json' } });
    });
    vi.stubGlobal('fetch', fetchMock);
    document.cookie = 'olympos_csrf=t; path=/';
    const vault = { id: 'v1', target: { service: 'vault', cluster_name: 'c1' } } as unknown as Vault;
    const secret = { current_version: 7, keys: ['API_KEY'] } as unknown as SecretDetail;
    const user = userEvent.setup();
    const qc = new QueryClient();
    const { createMemoryHistory, createRootRoute, createRouter, RouterProvider } = await import('@tanstack/react-router');
    const testRouter = createRouter({
      history: createMemoryHistory({ initialEntries: ['/'] }),
      routeTree: createRootRoute({
        component: () => <ChangeRequestDrawer open onClose={() => {}} vault={vault} secret={secret} mount="kv/" path="erp/payments" keyName="API_KEY" />,
      }),
    });
    render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={testRouter} />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(screen.getByLabelText('New value')).toBeInTheDocument());
    const canary = 'canary-secret-value-42';
    const v1 = screen.getByLabelText('New value') as HTMLInputElement;
    const v2 = screen.getByLabelText('Confirm value') as HTMLInputElement;
    expect(v1.type).toBe('password');
    expect(v2.type).toBe('password');

    // mismatch is caught client-side and nothing is sent
    await user.type(v1, canary);
    await user.type(v2, canary + 'x');
    await user.type(screen.getByLabelText('Justification'), 'Rotation after incident OPS-1');
    await user.click(screen.getByRole('button', { name: 'Submit for approval' }));
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.getByText('The two values do not match.')).toBeInTheDocument();

    await user.clear(v2);
    await user.type(v2, canary);
    await user.click(screen.getByRole('button', { name: 'Submit for approval' }));
    await waitFor(() => expect(screen.getByText(/Submitted/)).toBeInTheDocument());

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(sent[0]).toMatchObject({ vault_id: 'v1', items: [{ key: 'API_KEY', op: 'replace', value: canary, base_version: 7 }] });
    // after submit: the value is nowhere in the document or in any input
    expect(document.body.innerHTML).not.toContain(canary);
    for (const input of Array.from(document.querySelectorAll('input'))) expect(input.value).not.toContain(canary);
    expect(screen.getByText('hm:aaaa·bbbb·cccc')).toBeInTheDocument();
    // and not in the react-query caches
    expect(JSON.stringify(qc.getQueryCache().getAll().map((q) => q.state.data))).not.toContain(canary);
    expect(JSON.stringify(qc.getMutationCache().getAll().map((m) => m.state.variables))).not.toContain(canary);
  });
});

describe('vault key table', () => {
  it('never renders a value even if the API (wrongly) returned one', async () => {
    const { installMocks } = await import('../mocks/install');
    const db = await import('../mocks/db');
    const canary = 'leaked-value-canary';
    // simulate a misbehaving server that includes values
    for (const s of Object.values(db.secrets).flat()) (s as unknown as Record<string, unknown>).values = Object.fromEntries(s.keys.map((k) => [k, canary]));
    installMocks('1');
    window.history.pushState({}, '', '/vaults');
    const { router } = await import('../router');
    const { RouterProvider } = await import('@tanstack/react-router');
    const { ToastProvider } = await import('../ui/kit');
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <ToastProvider>
          <RouterProvider router={router} />
        </ToastProvider>
      </QueryClientProvider>,
    );
    await waitFor(() => expect(screen.getByText('PSP_API_KEY')).toBeInTheDocument(), { timeout: 5000 });
    const masks = screen.getAllByLabelText('Value hidden');
    expect(masks.length).toBeGreaterThanOrEqual(6);
    expect(document.body.innerHTML).not.toContain(canary);
    fireEvent.keyDown(document, { key: 'Escape' });
  });
});
