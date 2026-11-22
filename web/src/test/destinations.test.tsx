import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { Destination, DestinationGroup, DestinationTest } from '../api/types';
import { MeProvider } from '../auth/me';
import * as mockDb from '../mocks/db';
import { DestinationDialog, joinMountPath } from '../pages/settings/DestinationDialog';
import { DestinationGroupsCard } from '../pages/settings/DestinationGroupDialog';
import { usedByLabel } from '../ui/destinations';
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

// ------------------------------------------------------------ destination groups
describe('destination groups', () => {
  const dests = [
    saved({ id: 'd1', name: 'blob-weu-backups', kind: 'azure_blob', jobs: 9, groups: 2 }),
    saved({ id: 'd2', name: 'minio-factory', kind: 's3', auth: 'access_key', jobs: 1, groups: 1 }),
    saved({ id: 'd3', name: 'nas-factory', kind: 'nfs', auth: 'none', jobs: 0, groups: 1 }),
  ];
  const m = (d: Destination) => ({ id: d.id, name: d.name, kind: d.kind });
  const groups: DestinationGroup[] = [
    { id: 'g1', name: 'eu-offsite', description: 'Blob plus an S3 copy', members: [m(dests[0]), m(dests[1])], jobs: 5, created_at: '2026-11-01T00:00:00Z', updated_at: '2026-11-01T00:00:00Z' },
    { id: 'g2', name: 'dr-pair', description: '', members: [m(dests[2]), m(dests[0])], jobs: 0, created_at: '2026-11-01T00:00:00Z', updated_at: '2026-11-01T00:00:00Z' },
  ];
  const lists = (c: Call) =>
    c.path === '/api/v1/destination-groups' && c.method === 'GET' ? { status: 200, body: { items: groups } } : c.path === '/api/v1/destinations' ? { status: 200, body: { items: dests } } : null;

  function renderGroups(role = 'admin') {
    localStorage.setItem('olympos.mock.role', role);
    const me = mockDb.me();
    localStorage.removeItem('olympos.mock.role');
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <ToastProvider>
          <MeProvider me={me}>
            <DestinationGroupsCard />
          </MeProvider>
        </ToastProvider>
      </QueryClientProvider>,
    );
    return qc;
  }
  const members = (dialog: HTMLElement) =>
    within(within(dialog).getByRole('list', { name: 'Destinations, in order' }))
      .getAllByRole('listitem')
      .map((li) => li.querySelector('.mono')?.textContent);

  it('lists groups with their members in order, kind badges and how many jobs use them', async () => {
    respond = (c) => lists(c) ?? { status: 404 };
    renderGroups();
    const table = await screen.findByRole('table', { name: 'Destination groups' });
    const row = within(table).getByRole('row', { name: /eu-offsite/ });
    expect(within(row).getAllByText(/^(blob-weu-backups|minio-factory)$/).map((e) => e.textContent)).toEqual(['blob-weu-backups', 'minio-factory']);
    expect(within(row).getByText('Azure Blob')).toBeInTheDocument();
    expect(within(row).getByText('S3')).toBeInTheDocument();
    expect(within(row).getByText('5 jobs')).toBeInTheDocument();
    // a group in use cannot be deleted; the reason is on the control
    expect(within(row).getByRole('button', { name: 'Delete eu-offsite' })).toBeDisabled();
    expect(within(row).getByRole('button', { name: 'Delete eu-offsite' })).toHaveAttribute('title', 'Used by 5 jobs. Move them first.');
    const dr = within(table).getByRole('row', { name: /dr-pair/ });
    expect(within(dr).getAllByText(/^(nas-factory|blob-weu-backups)$/).map((e) => e.textContent)).toEqual(['nas-factory', 'blob-weu-backups']);
    expect(within(dr).getByText('0 jobs')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'New group' })).toBeInTheDocument();
  });

  it('a viewer sees the groups but no controls', async () => {
    respond = (c) => lists(c) ?? { status: 404 };
    renderGroups('viewer');
    const table = await screen.findByRole('table', { name: 'Destination groups' });
    expect(within(table).getByRole('row', { name: /eu-offsite/ })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'New group' })).toBeNull();
    expect(screen.queryByRole('button', { name: /^(Edit|Delete) / })).toBeNull();
  });

  it('create: one member is not enough, and server field errors land on their fields', async () => {
    const user = userEvent.setup();
    respond = (c) =>
      lists(c) ??
      (c.method === 'POST'
        ? { status: 422, body: { error: 'invalid destination group', fields: { name: 'a destination group named cold already exists', member_ids: 'minio-factory and nas-factory write to the same location' } } }
        : { status: 404 });
    renderGroups();
    await user.click(await screen.findByRole('button', { name: 'New group' }));
    const dialog = screen.getByRole('dialog', { name: 'New destination group' });
    await user.type(within(dialog).getByLabelText('Name'), 'cold');
    const add = within(dialog).getByRole('combobox', { name: 'Add destination' });
    await waitFor(() => expect(add).toBeEnabled());
    await user.click(add);
    await user.click(screen.getByRole('option', { name: /minio-factory/ }));
    await user.click(within(dialog).getByRole('button', { name: 'Add' }));
    expect(members(dialog)).toEqual(['minio-factory']);
    expect(within(dialog).getByText('1 of 4')).toBeInTheDocument();
    expect(within(dialog).getByRole('alert')).toHaveTextContent('A group needs 2 to 4 destinations');
    expect(within(dialog).getByRole('button', { name: 'Create group' })).toBeDisabled();

    await user.click(add);
    await user.click(screen.getByRole('option', { name: /nas-factory/ }));
    await user.click(within(dialog).getByRole('button', { name: 'Add' }));
    expect(members(dialog)).toEqual(['minio-factory', 'nas-factory']);
    expect(within(dialog).queryByText('A group needs 2 to 4 destinations')).toBeNull();
    await user.click(within(dialog).getByRole('button', { name: 'Create group' }));
    expect(await within(dialog).findByText('a destination group named cold already exists')).toBeInTheDocument();
    expect(within(dialog).getByLabelText('Name')).toHaveAttribute('aria-invalid', 'true');
    expect(within(dialog).getByText('minio-factory and nas-factory write to the same location')).toBeInTheDocument();
    expect(writes()).toEqual([{ method: 'POST', path: '/api/v1/destination-groups', body: { name: 'cold', description: '', member_ids: ['d2', 'd3'] } }]);
  });

  it('edit: reorders, adds and removes members, warns how many jobs it affects and sends only what changed', async () => {
    const user = userEvent.setup();
    respond = (c) => lists(c) ?? (c.method === 'PATCH' ? { status: 200, body: { ...groups[0], members: [m(dests[2]), m(dests[1])] } } : { status: 404 });
    renderGroups();
    await user.click(await screen.findByRole('button', { name: 'Edit eu-offsite' }));
    const dialog = screen.getByRole('dialog', { name: 'eu-offsite' });
    expect(within(dialog).getByText('Edit group')).toBeInTheDocument();
    expect(within(dialog).getByText('This change affects 5 backup jobs.')).toBeInTheDocument();
    expect(within(dialog).getByText('Existing backups are not copied to a destination you add; only new runs write to it.')).toBeInTheDocument();
    expect(members(dialog)).toEqual(['blob-weu-backups', 'minio-factory']);
    expect(within(dialog).getByRole('button', { name: 'Move blob-weu-backups up' })).toBeDisabled();
    expect(within(dialog).getByRole('button', { name: 'Move minio-factory down' })).toBeDisabled();

    const add = within(dialog).getByRole('combobox', { name: 'Add destination' });
    await waitFor(() => expect(add).toBeEnabled());
    await user.click(add);
    expect(screen.getAllByRole('option').map((o) => o.textContent)).toEqual([expect.stringContaining('nas-factory')]); // members are not offered again
    await user.click(screen.getByRole('option', { name: /nas-factory/ }));
    await user.click(within(dialog).getByRole('button', { name: 'Add' }));
    const added = within(within(dialog).getByRole('list', { name: 'Destinations, in order' })).getAllByRole('listitem')[2];
    expect(within(added).getByText('New')).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Move nas-factory up' }));
    expect(members(dialog)).toEqual(['blob-weu-backups', 'nas-factory', 'minio-factory']);
    await user.click(within(dialog).getByRole('button', { name: 'Remove blob-weu-backups' }));
    expect(members(dialog)).toEqual(['nas-factory', 'minio-factory']);
    expect(within(dialog).getByText('2 of 4')).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Save group' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(writes()).toEqual([{ method: 'PATCH', path: '/api/v1/destination-groups/g1', body: { member_ids: ['d3', 'd2'] } }]);
  });

  it('delete shows the server 409 message (a job started using the group meanwhile)', async () => {
    const user = userEvent.setup();
    respond = (c) => lists(c) ?? (c.method === 'DELETE' ? { status: 409, body: { error: 'used by 1 backup job; move it to another destination or group first' } } : { status: 404 });
    renderGroups();
    await user.click(await screen.findByRole('button', { name: 'Delete dr-pair' }));
    const confirm = screen.getByRole('dialog', { name: 'Delete dr-pair?' });
    expect(within(confirm).getByText(/The member destinations and the backups stored on them stay/)).toBeInTheDocument();
    await user.click(within(confirm).getByRole('button', { name: 'Delete group' }));
    expect(await within(confirm).findByRole('alert')).toHaveTextContent('Used by 1 backup job; move it to another destination or group first.');
    expect(writes()).toEqual([{ method: 'DELETE', path: '/api/v1/destination-groups/g2', body: undefined }]);
  });

  it('destination rows say how many groups a destination is in', () => {
    expect(usedByLabel(dests[0])).toBe('9 jobs · in 2 groups');
    expect(usedByLabel(dests[1])).toBe('1 job · in 1 group');
    expect(usedByLabel(saved({ jobs: 0, groups: 0 }))).toBe('0 jobs');
    expect(usedByLabel(saved({ jobs: 3 }))).toBe('3 jobs');
  });
});
