import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import * as db from '../mocks/db';
import { renderApp } from './renderApp';

afterEach(cleanup);

const T = { timeout: 5000 };

async function toStep2(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: 'Next: credentials' }, T));
  await screen.findByRole('heading', { name: 'Credentials' }, T);
}

describe('Backup wizard · step 2', () => {
  it('orders Username, then Password, then Databases (value chips; empty = all)', async () => {
    const user = userEvent.setup();
    await renderApp(`/backups/new?target=${db.tByService('orders-pg').id}`);
    await toStep2(user);
    await user.click(screen.getByRole('radio', { name: /Store in Olympos/ }));

    const user_ = screen.getByLabelText('Username');
    const pw = screen.getByLabelText('Password');
    const dbs = screen.getByLabelText('Databases');
    // document order: username → password → databases
    expect(user_.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(pw.compareDocumentPosition(dbs) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByText('All databases will be backed up.')).toBeInTheDocument();

    await user.type(dbs, 'orders billing{Enter}');
    const list = screen.getByRole('list', { name: 'Databases to back up' });
    expect(within(list).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['orders', 'billing']);
    expect(screen.getByText(/2 databases selected/)).toBeInTheDocument();
    // no key=value is required in this field
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('asks no credentials for a vault target and blocks Next until the vault is configured', async () => {
    const user = userEvent.setup();
    await renderApp(`/backups/new?target=${db.tByService('bao-retail').id}`);
    await toStep2(user);
    const note = await screen.findByText(/is not configured in Olympos yet/, {}, T);
    expect(note.closest('[role="alert"]')).toHaveTextContent('cce-ist-retail / security / bao-retail');
    const link = screen.getByRole('link', { name: 'Open Vaults › Configure' });
    const vault = db.vaults.find((v) => v.target.service === 'bao-retail')!;
    expect(link.getAttribute('href')).toContain(`vault=${vault.id}`);
    expect(screen.queryByLabelText('Username')).toBeNull();
    expect(screen.queryByLabelText('Password')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Test connection' })).toBeNull();
    const next = screen.getByRole('button', { name: 'Next: destination' });
    expect(next).toBeDisabled();
    expect(next).toHaveAccessibleDescription('Configure the vault first');
  });
});

describe('Backup wizard · configured vault', () => {
  it('explains the Olympos AppRole and lets the job continue without a password', async () => {
    const user = userEvent.setup();
    await renderApp(`/backups/new?target=${db.tByService('vault').id}`);
    await toStep2(user);
    await screen.findByText('No credentials needed', {}, T);
    expect(screen.getByText(/uses the Olympos AppRole of/)).toHaveTextContent('oke-fra-erp / vault / vault');
    const next = screen.getByRole('button', { name: 'Next: destination' });
    await waitFor(() => expect(next).toBeEnabled());
    await user.click(next);
    expect(await screen.findByRole('heading', { name: 'Destination & schedule' }, T)).toBeInTheDocument();
  });
});

describe('Backup wizard · destination group', () => {
  afterEach(() => localStorage.removeItem('olympos.mock.failCopy'));

  it('writes to a group (destination_group_id only); a dry run with one failed copy is not a pass', async () => {
    const user = userEvent.setup();
    const group = db.destinationGroups.find((g) => g.name === 'eu-offsite')!;
    localStorage.setItem('olympos.mock.failCopy', 'minio-factory');
    await renderApp(`/backups/new?target=${db.tByService('orders-pg').id}`);
    await toStep2(user);
    await user.type(screen.getByLabelText('Key Vault'), 'kv-platform-weu');
    await user.type(screen.getByLabelText('Secret name (holds the password)'), 'orders-backup');
    await user.type(screen.getByLabelText('Username'), 'backup_ro');
    await user.click(screen.getByRole('button', { name: 'Next: destination' }));
    await screen.findByRole('heading', { name: 'Destination & schedule' }, T);

    const radio = await screen.findByRole('radio', { name: /eu-offsite/ }, T);
    // groups are marked as such and list their members in order
    const opt = radio.closest('label')!;
    expect(within(opt).getByRole('img', { name: 'Destination group' })).toBeInTheDocument();
    expect(opt).toHaveTextContent(/blob-weu-backups.*minio-factory/);
    await user.click(radio);
    expect(radio).toBeChecked();
    await user.click(screen.getByRole('button', { name: 'Next: review' }));
    const dt = await screen.findByText('Destination', { selector: 'dt' }, T);
    expect(dt.nextElementSibling).toHaveTextContent(/eu-offsite.*blob-weu-backups.*minio-factory/);

    const sent: { method: string; path: string; body: unknown }[] = [];
    const orig = window.fetch;
    window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method && init.method !== 'GET') sent.push({ method: init.method, path: String(input), body: init.body ? JSON.parse(String(init.body)) : undefined });
      return orig(input, init);
    };
    try {
      await user.click(screen.getByRole('button', { name: 'Create job and run dry run' }));
      await waitFor(() => expect(sent.some((c) => c.path.endsWith('/run'))).toBe(true), T);
      const create = sent.find((c) => c.method === 'POST' && c.path.endsWith('/backup/jobs'))!;
      expect(create.body).toMatchObject({ destination_group_id: group.id });
      expect(create.body).not.toHaveProperty('destination_id');
      // let the mock dry run finish now
      await waitFor(() => expect(db.runs.some((r) => r.trigger === 'test')).toBe(true), T);
      const dry = db.runs.find((r) => r.trigger === 'test')!;
      dry.started_at = new Date(Date.now() - 10_000).toISOString();
      expect(await screen.findByText(/^Partial/, {}, { timeout: 6000 })).toHaveClass('warn');
      // one line per copy from the server's checklist, each size once
      expect(screen.getByText('minio-factory: dial tcp: i/o timeout')).toBeInTheDocument();
      expect(screen.getAllByText(/^Wrote .* to blob-weu-backups/)).toHaveLength(1);
      expect(screen.queryByText(/written and verified/)).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Enable backup' })).toBeDisabled();
    } finally {
      window.fetch = orig;
    }
  }, 15_000);

  it('edit keeps the stored password: the credential is left out, and a refused field is shown on its step', async () => {
    const user = userEvent.setup();
    const j = db.jobs.find((x) => x.target.service === 'billing-pg')!;
    const saved = j.credential;
    j.credential = { id: saved.id, source: 'stored', ref: '', username: 'backup' };
    await renderApp(`/backups/new?target=${j.target.id}&job=${j.id}`);
    const sent: { method: string; body: Record<string, unknown> }[] = [];
    const orig = window.fetch;
    let refuse = true; // the first save is refused on a field of step 2
    window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === 'PATCH') {
        sent.push({ method: init.method, body: JSON.parse(String(init.body)) });
        if (refuse) {
          refuse = false;
          const body = JSON.stringify({ error: 'invalid job', fields: { 'credential.username': 'not allowed here' } });
          return Promise.resolve(new Response(body, { status: 422, headers: { 'content-type': 'application/json' } }));
        }
      }
      return orig(input, init);
    };
    try {
      await toStep2(user);
      expect(screen.getByLabelText('Password')).toHaveValue('');
      // a new user needs its own password
      await user.clear(screen.getByLabelText('Username'));
      await user.type(screen.getByLabelText('Username'), 'other');
      await user.click(screen.getByRole('button', { name: 'Next: destination' }));
      expect(await screen.findByText(/Enter the password of other: the stored one belongs to backup/, {}, T)).toBeInTheDocument();
      await user.clear(screen.getByLabelText('Username'));
      await user.type(screen.getByLabelText('Username'), 'backup');
      await user.click(screen.getByRole('button', { name: 'Next: destination' }));
      await screen.findByRole('heading', { name: 'Destination & schedule' }, T);
      await user.click(screen.getByRole('button', { name: 'Next: review' }));
      await user.click(await screen.findByRole('button', { name: 'Save changes' }, T));
      await waitFor(() => expect(sent).toHaveLength(1), T);
      expect(sent[0].body).not.toHaveProperty('credential');
      // the refused field is shown where it can be fixed
      await screen.findByRole('heading', { name: 'Credentials' }, T);
      expect(screen.getByText('not allowed here')).toBeInTheDocument();
      await user.click(screen.getByRole('button', { name: 'Next: destination' }));
      await user.click(await screen.findByRole('button', { name: 'Next: review' }, T));
      await user.click(await screen.findByRole('button', { name: 'Save changes' }, T));
      await waitFor(() => expect(sent).toHaveLength(2), T);
      await screen.findByText('Backup job saved.', {}, T);
    } finally {
      window.fetch = orig;
      j.credential = saved;
    }
  }, 15_000);
});
