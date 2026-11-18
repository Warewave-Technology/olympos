import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { Destination, DestinationTest } from '../api/types';
import { DestinationDialog, joinMountPath } from '../pages/settings/DestinationDialog';
import { ToastProvider } from '../ui/kit';

type Call = { method: string; path: string; body: unknown };
let calls: Call[] = [];
let respond: (c: Call) => { status: number; body?: unknown };

const okTest: DestinationTest = { ok: true, can_delete: false, steps: [{ name: 'endpoint', ok: true, detail: 'minio:9000' }, { name: 'write', ok: true, detail: '' }, { name: 'delete_refused', ok: true, detail: '403' }], sas: null };

function saved(over: Partial<Destination>): Destination {
  return { id: 'd1', name: 'x', kind: 'azure_blob', prefix: '', endpoint_override: '', auth: 'managed_identity', account: '', container: '', sas_source: '', sas_ref: '', sas_expires_at: null, sas_permissions: '', last_test_at: null, last_test_ok: true, last_test: okTest, jobs: 0, ...over };
}

beforeEach(() => {
  calls = [];
  respond = (c) => (c.path === '/api/v1/destinations/mounts' ? { status: 200, body: { items: [{ name: 'backup-nas', path: '/mnt/nas', writable: true }, { name: 'ro', path: '/mnt/ro', writable: false }] } } : { status: 201, body: saved({ name: 'created' }) });
  document.cookie = 'olympos_csrf=t; path=/';
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      const c = { method: init?.method ?? 'GET', path: new URL(url, 'http://x').pathname, body: init?.body ? JSON.parse(String(init.body)) : undefined };
      calls.push(c);
      const r = respond(c);
      return new Response(r.body === undefined ? null : JSON.stringify(r.body), { status: r.status, headers: { 'Content-Type': 'application/json' } });
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderDialog(dest?: Destination, onClose = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <ToastProvider>
        <DestinationDialog dest={dest} onClose={onClose} />
      </ToastProvider>
    </QueryClientProvider>,
  );
  return { qc, onClose };
}
const writes = () => calls.filter((c) => c.method !== 'GET');
const noSecretAnywhere = (qc: QueryClient, secret: string) => {
  expect(document.body.innerHTML).not.toContain(secret);
  for (const i of Array.from(document.querySelectorAll('input'))) expect(i.value).not.toContain(secret);
  expect(JSON.stringify(qc.getQueryCache().getAll().map((q) => q.state.data))).not.toContain(secret);
  expect(JSON.stringify(qc.getMutationCache().getAll().map((m) => m.state.variables))).not.toContain(secret);
};

describe('destination dialog', () => {
  it('is a labelled modal with a kind selector; Azure Blob defaults to Managed Identity and sends the endpoint override', async () => {
    const user = userEvent.setup();
    const { onClose } = renderDialog();
    const dialog = screen.getByRole('dialog', { name: 'New destination' });
    expect(within(dialog).getByRole('radio', { name: /Azure Blob/ })).toBeChecked();
    expect(within(dialog).getByRole('radio', { name: /S3 \/ S3-compatible/ })).toBeInTheDocument();
    expect(within(dialog).getByRole('radio', { name: /NFS/ })).toBeInTheDocument();
    expect(within(dialog).getByRole('radio', { name: /Managed Identity/ })).toBeChecked();

    await user.type(screen.getByLabelText('Name'), 'azurite');
    await user.type(screen.getByLabelText('Storage account'), 'devstoreaccount1');
    await user.type(screen.getByLabelText('Container'), 'backups');
    await user.type(screen.getByLabelText('Endpoint override (optional)'), 'http://azurite.olympos.svc:10000/devstoreaccount1');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(writes()).toEqual([
      {
        method: 'POST',
        path: '/api/v1/destinations',
        body: { name: 'azurite', kind: 'azure_blob', prefix: 'olympos/', account: 'devstoreaccount1', container: 'backups', endpoint_override: 'http://azurite.olympos.svc:10000/devstoreaccount1', auth: 'managed_identity' },
      },
    ]);
  });

  it('Azure SAS: parses the token live, sends it once and keeps it nowhere afterwards', async () => {
    const user = userEvent.setup();
    const { qc } = renderDialog();
    const sas = 'sv=2025-01-05&sr=c&sp=rcwdl&se=2099-01-01T00:00:00Z&sig=SECRETSIG123';
    await user.type(screen.getByLabelText('Name'), 'blob');
    await user.type(screen.getByLabelText('Storage account'), 'stolymp');
    await user.type(screen.getByLabelText('Container'), 'c');
    await user.click(screen.getByRole('radio', { name: /SAS token/ }));
    expect(screen.getByRole('radio', { name: /Key Vault reference/ })).toBeChecked(); // recommended default
    await user.click(screen.getByRole('radio', { name: /Store in Olympos/ }));
    const input = screen.getByLabelText('SAS token') as HTMLInputElement;
    expect(input.type).toBe('password');
    await user.click(input);
    await user.paste(sas);
    expect(screen.getByText(/Has delete/)).toBeInTheDocument();
    expect(screen.getByText(/is not needed; remove it/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(writes()).toHaveLength(1));
    expect(writes()[0].body).toMatchObject({ kind: 'azure_blob', auth: 'sas_token', sas: { source: 'stored', value: sas } });
    noSecretAnywhere(qc, 'SECRETSIG123');
  });

  it('S3: sends endpoint, region, bucket, path-style and the secret key, then forgets the secret', async () => {
    const user = userEvent.setup();
    const { qc, onClose } = renderDialog();
    await user.click(screen.getByRole('radio', { name: /S3 \/ S3-compatible/ }));
    await user.type(screen.getByLabelText('Name'), 'minio');
    const pathStyle = screen.getByRole('checkbox', { name: /Path-style addressing/ });
    expect(pathStyle).not.toBeChecked();
    await user.type(screen.getByLabelText('Endpoint override'), 'https://minio.storage.svc:9000');
    expect(pathStyle).toBeChecked(); // S3-compatible services usually need it
    await user.type(screen.getByLabelText('Region'), 'eu-central-1');
    await user.type(screen.getByLabelText('Bucket'), 'olympos-backups');
    await user.type(screen.getByLabelText('Access key ID'), 'olympos');
    await user.click(screen.getByRole('radio', { name: /Store in Olympos/ }));
    const secret = screen.getByLabelText('Secret key') as HTMLInputElement;
    expect(secret.type).toBe('password');
    await user.type(secret, 'S3-SECRET-CANARY');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(writes()[0].body).toEqual({
      name: 'minio',
      kind: 's3',
      prefix: 'olympos/',
      endpoint_override: 'https://minio.storage.svc:9000',
      region: 'eu-central-1',
      bucket: 'olympos-backups',
      path_style: true,
      auth: 'access_key',
      access_key_id: 'olympos',
      secret_key: { source: 'stored', value: 'S3-SECRET-CANARY' },
    });
    noSecretAnywhere(qc, 'S3-SECRET-CANARY');
  });

  it('NFS: picks a writable mount from /destinations/mounts, sends the full path and shows the saved warnings', async () => {
    const user = userEvent.setup();
    respond = (c) =>
      c.path === '/api/v1/destinations/mounts'
        ? { status: 200, body: { items: [{ name: 'backup-nas', path: '/mnt/nas', writable: true }, { name: 'ro', path: '/mnt/ro', writable: false }] } }
        : { status: 201, body: saved({ name: 'nas', kind: 'nfs', auth: 'none', path: '/mnt/nas/olympos', warnings: ['Olympos can delete files on this NFS path.'], last_test: { ok: true, can_delete: true, steps: [{ name: 'path', ok: true, detail: '' }, { name: 'delete_refused', ok: false, detail: '' }], sas: null } }) };
    renderDialog();
    await user.click(screen.getByRole('radio', { name: /NFS/ }));
    expect(screen.getByText(/Olympos can delete files on this mount/)).toBeInTheDocument();
    const mount = await screen.findByRole('combobox', { name: 'Mount' });
    expect(mount).toHaveTextContent('backup-nas'); // first writable mount preselected
    await user.click(mount);
    expect(screen.getByRole('option', { name: /ro/ })).toHaveAttribute('aria-disabled', 'true');
    await user.keyboard('{Escape}');
    await user.type(screen.getByLabelText('Name'), 'nas');
    await user.clear(screen.getByLabelText('Path below the mount'));
    await user.type(screen.getByLabelText('Path below the mount'), '/olympos/');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(screen.getByRole('dialog', { name: 'Saved nas with warnings' })).toBeInTheDocument());
    expect(writes()[0].body).toEqual({ name: 'nas', kind: 'nfs', prefix: 'olympos/', auth: 'none', path: '/mnt/nas/olympos' });
    expect(screen.getByText('Olympos can delete files on this NFS path.')).toBeInTheDocument();
    expect(screen.getByText('Delete is possible (expected on NFS)')).toBeInTheDocument();
    expect(joinMountPath('/mnt/nas/', '')).toBe('/mnt/nas');
  });

  it('NFS without mounts explains the Helm nfsMounts value', async () => {
    const user = userEvent.setup();
    respond = () => ({ status: 200, body: { items: [] } });
    renderDialog();
    await user.click(screen.getByRole('radio', { name: /NFS/ }));
    expect(await screen.findByText(/No NFS mounts on the server yet/)).toBeInTheDocument();
    expect(screen.getAllByText('nfsMounts').length).toBeGreaterThan(0);
  });

  it('shows the test report from a 422 and runs Test destination in the modal', async () => {
    const user = userEvent.setup();
    const failed: DestinationTest = { ok: false, can_delete: false, error: 'connection refused', steps: [{ name: 'endpoint', ok: false, detail: 'dial tcp: connection refused' }], sas: null };
    respond = (c) => (c.path === '/api/v1/destinations/test' ? { status: 200, body: okTest } : { status: 422, body: { error: 'destination test failed', fields: {}, test: failed } });
    renderDialog();
    await user.click(screen.getByRole('radio', { name: /S3 \/ S3-compatible/ }));
    await user.type(screen.getByLabelText('Name'), 'm');
    await user.type(screen.getByLabelText('Bucket'), 'b');
    await user.type(screen.getByLabelText('Access key ID'), 'k');
    await user.type(screen.getByLabelText('Key Vault reference'), 'kv://v/s');
    await user.click(screen.getByRole('button', { name: 'Test destination' }));
    expect(await screen.findByText('Reach the S3 endpoint')).toBeInTheDocument();
    expect(calls.find((c) => c.path === '/api/v1/destinations/test')!.body).toMatchObject({ kind: 's3', secret_key: { source: 'keyvault_ref', ref: 'kv://v/s' } });
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/dial tcp: connection refused/)).toBeInTheDocument();
    expect(screen.getByText(/· failed/)).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Destination test failed.');
  });

  it('edit sends a partial PATCH without the kind or the stored secret', async () => {
    const user = userEvent.setup();
    respond = () => ({ status: 200, body: saved({ name: 'minio-2', kind: 's3' }) });
    const dest = saved({ id: 'd9', name: 'minio', kind: 's3', auth: 'access_key', prefix: 'olympos/', endpoint_override: 'https://minio:9000', bucket: 'b', region: 'us-east-1', path_style: true, access_key_id: 'k', secret_key_source: 'stored' });
    const { onClose } = renderDialog(dest);
    expect(screen.getByRole('dialog', { name: 'Edit minio' })).toBeInTheDocument();
    expect(screen.queryByRole('radio', { name: /Azure Blob/ })).toBeNull(); // kind cannot change
    expect(screen.getByLabelText('Secret key')).toHaveValue('');
    expect(screen.getByText(/A secret key is stored/)).toBeInTheDocument();
    await user.clear(screen.getByLabelText('Name'));
    await user.type(screen.getByLabelText('Name'), 'minio-2');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(writes()).toEqual([{ method: 'PATCH', path: '/api/v1/destinations/d9', body: { name: 'minio-2' } }]);
  });
});
