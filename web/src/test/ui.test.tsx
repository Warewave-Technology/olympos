import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { BackupRun, BackupRunCopy, ChangeRequest, RestoreGuide, SecretDetail, Vault } from '../api/types';
import { Drawer, SecretValue } from '../ui/kit';
import { dateTime } from '../lib/format';

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

function renderRunDialog(body: object) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })),
  );
  return import('../ui/BackupRunDialog').then(({ BackupRunDialog }) =>
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <BackupRunDialog id="r1" onClose={() => {}} />
      </QueryClientProvider>,
    ),
  );
}

const partialRun = (over: Partial<BackupRun> & { next_repair_at?: string | null } = {}) => ({
  id: 'r1', job_id: 'j1', target_service: 'billing-pg', cluster_name: 'prod', engine: 'postgresql', trigger: 'schedule', status: 'partial', scheduled_for: null, tier: 'daily',
  started_at: '2026-11-22T02:00:00Z', finished_at: '2026-11-22T02:06:40Z', bytes: 3.1e9, wire_bytes: 3.1e9, blob_path: 'p/a.zip', sha256: '9f2c4a1e5d6c7b30',
  error: 'minio-factory: PutObject: 503 SlowDown', destination_name: 'eu-offsite', repair_of: null,
  copies: [
    { destination_id: 'd1', destination_name: 'blob-weu-backups', destination_kind: 'azure_blob', status: 'succeeded', blob_path: 'p/a.zip', bytes: 3.1e9, sha256: '9f2c4a1e5d6c7b30', tier: 'daily', error: '' },
    { destination_id: 'd2', destination_name: 'minio-factory', destination_kind: 's3', status: 'failed', blob_path: '', bytes: 0, sha256: '', tier: '', error: 'PutObject: 503 SlowDown' },
  ],
  restore: { doc: 'docs/restore.md#postgresql', steps: [{ title: 'Download', commands: 'az storage blob download' }], copies: [{ destination_id: 'd1', name: 'blob-weu-backups', kind: 'azure_blob', selected: true, run_id: 'r1', taken_at: '2026-11-22T02:00:00Z' }] },
  ...over,
});

describe('repair note of a partial run', () => {
  it('says when the queued repair starts', async () => {
    await renderRunDialog(partialRun({ next_repair_at: '2026-11-22T02:11:40Z' }));
    const note = await screen.findByText(/Repair queued: next attempt at/);
    expect(note).toHaveTextContent(`Repair queued: next attempt at ${dateTime('2026-11-22T02:11:40Z')}`);
    expect(screen.queryByText(/when they are used up/)).not.toBeInTheDocument();
  });

  it('without a queued repair, says what happens to the missing copy', async () => {
    await renderRunDialog(partialRun({ next_repair_at: null }));
    expect(
      await screen.findByText(/Olympos completes missing copies with repair runs inside the job's retry window; when they are used up, the copy stays missing until the next scheduled run\./),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Repair queued/)).not.toBeInTheDocument();
  });

  it('clamps long errors: the badge carries the status only, the full text is one click away', async () => {
    const long = 'upload: ' + 'PUT https://olympos-lab-azurite.olympos.svc.cluster.local:10000/devstoreaccount1/backups/groups/olympos-lab/lab/orders-pg/postgresql/2026/11/22/x.zip '.repeat(4) + 'dial tcp 10.96.0.1:10000: connect: connection refused';
    const run = partialRun({ error: 'minio-factory: ' + long });
    run.copies![1] = { ...run.copies![1], error: long };
    const user = userEvent.setup();
    await renderRunDialog(run);
    const table = await screen.findByRole('table', { name: 'Copies' });
    // Result: a short badge, the error below it, clamped
    const badge = screen.getByText('Partial', { selector: '.badge' });
    expect(badge).toHaveTextContent(/^Partial$/);
    const cell = within(table).getAllByRole('row')[2].lastElementChild as HTMLElement;
    const clamp = cell.querySelector('.clamp') as HTMLElement;
    expect(clamp).toHaveTextContent(long);
    expect(clamp).toHaveAttribute('title', long);
    const more = within(cell).getByRole('button', { name: 'Show the full error' });
    expect(more).toHaveAttribute('aria-expanded', 'false');
    await user.click(more);
    expect(clamp).not.toHaveClass('clamp-3');
    expect(within(cell).getByRole('button', { name: 'Show less' })).toHaveAttribute('aria-expanded', 'true');
    // short errors are not clamped and have no toggle
    expect(within(within(table).getAllByRole('row')[1]).queryByRole('button')).not.toBeInTheDocument();
  });
});

describe('partial backup runs', () => {
  it('a partial run is a warning, never a success, and shows its error', async () => {
    const { RunBadge } = await import('../ui/status');
    render(<RunBadge run={{ status: 'partial', error: 'minio-factory: dial tcp: i/o timeout' }} />);
    const b = screen.getByText('Partial · minio-factory: dial tcp: i/o timeout');
    expect(b).toHaveClass('badge', 'warn');
    expect(b).not.toHaveClass('ok');
  });

  it('a long error is truncated in the badge, with the whole label as its tooltip', async () => {
    const { RunBadge } = await import('../ui/status');
    const error = 'lab-azurite: upload: ' + 'x'.repeat(200);
    render(<RunBadge run={{ status: 'partial', error }} />);
    const b = screen.getByText(`Partial · ${error}`);
    expect(b).toHaveClass('badge', 'warn', 'trunc');
    expect(b).toHaveAttribute('title', `Partial · ${error}`);
    cleanup();
    render(<RunBadge run={{ status: 'partial', error: 'short' }} />);
    expect(screen.getByText('Partial · short')).not.toHaveClass('trunc');
  });

  it('a repair waiting for its start says when it starts', async () => {
    const { RunBadge } = await import('../ui/status');
    const at = new Date(Date.now() + 5 * 60_000).toISOString();
    render(<RunBadge run={{ status: 'queued', error: '', not_before: at }} />);
    expect(screen.getByText(`Queued · starts ${dateTime(at)}`)).toHaveClass('badge', 'mute');
    cleanup();
    render(<RunBadge run={{ status: 'queued', error: '', not_before: new Date(Date.now() - 1000).toISOString() }} />);
    expect(screen.getByText('Queued')).toBeInTheDocument();
  });

  it('the run dialog lists every copy and switches the restore commands to another copy', async () => {
    const { BackupRunDialog } = await import('../ui/BackupRunDialog');
    const copy = (over: Partial<BackupRunCopy>): BackupRunCopy => ({ destination_id: 'd1', destination_name: 'blob-weu-backups', destination_kind: 'azure_blob', status: 'succeeded', blob_path: 'p/a.zip', bytes: 3.1e9, sha256: '9f2c4a1e5d6c7b30', tier: 'daily', error: '', ...over });
    const run: BackupRun = {
      id: 'r1', job_id: 'j1', target_service: 'billing-pg', cluster_name: 'prod', engine: 'postgresql', trigger: 'schedule', status: 'partial', scheduled_for: null, tier: 'daily',
      started_at: '2026-11-22T02:00:00Z', finished_at: '2026-11-22T02:06:40Z', bytes: 3.1e9, wire_bytes: 3.1e9, blob_path: 'p/a.zip', sha256: '9f2c4a1e5d6c7b30', error: 'minio-factory: PutObject: 503 SlowDown',
      destination_name: 'eu-offsite', repair_of: null,
      copies: [copy({}), copy({ destination_id: 'd2', destination_name: 'minio-factory', destination_kind: 's3', status: 'failed', blob_path: '', bytes: 0, sha256: '', tier: '', error: 'PutObject: 503 SlowDown' })],
    };
    const guide = (sel: 'd1' | 'd2'): RestoreGuide => ({
      doc: 'docs/restore.md#postgresql',
      steps: [{ title: 'Download the backup and its manifest', commands: sel === 'd1' ? 'az storage blob download --name p/a.zip' : 'aws s3 cp s3://olympos-backups/p/b.zip .' }],
      copies: [
        { destination_id: 'd1', name: 'blob-weu-backups', kind: 'azure_blob', selected: sel === 'd1', run_id: 'r1', taken_at: '2026-11-22T02:00:00Z' },
        { destination_id: 'd2', name: 'minio-factory', kind: 's3', selected: sel === 'd2', run_id: 'r2', taken_at: '2026-11-22T02:21:00Z' },
      ],
    });
    const urls: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        urls.push(url);
        const sel = new URL(url, 'http://x').searchParams.get('copy') === 'd2' ? 'd2' : 'd1';
        return new Response(JSON.stringify({ ...run, restore: guide(sel) }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }),
    );
    const user = userEvent.setup();
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <BackupRunDialog id="r1" onClose={() => {}} />
      </QueryClientProvider>,
    );
    const table = await screen.findByRole('table', { name: 'Copies' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent('blob-weu-backups');
    expect(within(rows[0]).getByText('Succeeded')).toHaveClass('ok');
    expect(rows[1]).toHaveTextContent('minio-factory');
    expect(within(rows[1]).getByText('Failed')).toHaveClass('crit');
    expect(rows[1]).toHaveTextContent('PutObject: 503 SlowDown');
    // the group marker: this run wrote to a group
    expect(screen.getByRole('img', { name: 'Destination group' })).toBeInTheDocument();

    const picker = screen.getByRole('group', { name: 'Restore from copy' });
    expect(within(picker).getByRole('radio', { name: /blob-weu-backups/ })).toBeChecked();
    const repaired = within(picker).getByRole('radio', { name: /minio-factory/ });
    expect(repaired).not.toBeChecked();
    expect(repaired.closest('label')).toHaveTextContent('Completed later by a repair, taken at');
    expect(screen.getByText('az storage blob download --name p/a.zip')).toBeInTheDocument();
    await user.click(repaired);
    expect(await screen.findByText('aws s3 cp s3://olympos-backups/p/b.zip .')).toBeInTheDocument();
    expect(urls.at(-1)).toBe('/api/v1/backup/runs/r1?copy=d2');
    expect(within(picker).getByRole('radio', { name: /minio-factory/ })).toBeChecked();
  });
});
