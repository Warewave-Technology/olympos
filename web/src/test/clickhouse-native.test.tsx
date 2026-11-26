// ClickHouse native backups in the UI (docs/design/clickhouse-native.md §10,
// docs/design/backup-wizard-clickhouse.html): the wizard's Backup method step
// and the run page of a native run.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { BackupRunDetail, Me } from '../api/types';
import { MeProvider } from '../auth/me';
import { relDateTime } from '../lib/format';
import * as db from '../mocks/db';
import { renderApp } from './renderApp';

const T = { timeout: 5000 };
const INGEST_OFF = 'olympos.mock.ingestOff';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  localStorage.removeItem(INGEST_OFF);
});

/** Target, then credentials, then the method step of a new job for events-ch (ClickHouse 24.8). */
async function toMethod(user: ReturnType<typeof userEvent.setup>) {
  await renderApp(`/backups/new?target=${db.tByService('events-ch').id}`);
  await user.click(await screen.findByRole('button', { name: 'Next: credentials' }, T));
  await screen.findByRole('heading', { name: 'Credentials' }, T);
  await user.type(screen.getByLabelText('Key Vault'), 'kv-platform-weu');
  await user.type(screen.getByLabelText('Secret name (holds the password)'), 'events-ch-backup');
  await user.type(screen.getByLabelText('Username'), 'backup');
  await user.click(screen.getByRole('button', { name: 'Next: method' }));
  await screen.findByRole('heading', { name: 'Backup method' }, T);
  // until the server says whether it takes native backups, Native waits
  await waitFor(() => expect(screen.queryByText('Checking whether this server takes native backups…')).toBeNull(), T);
}

/** From the method step to the review, once the default destination is picked. */
async function toReview(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Next: destination' }));
  await screen.findByRole('heading', { name: 'Destination & schedule' }, T);
  await waitFor(() => expect(document.querySelector('input[name="dst"]:checked')).not.toBeNull(), T);
  await user.click(screen.getByRole('button', { name: 'Next: review' }));
  await screen.findByRole('heading', { name: 'Review & test run' }, T);
}

/** An existing job of metrics-ch-dr (ClickHouse 24.8) with these engine_options, for the edit tests. */
function editJob(engine_options: Record<string, unknown>) {
  const base = db.jobs.find((x) => x.target.service === 'metrics-ch')!;
  const j = { ...base, id: `job-${Math.random().toString(16).slice(2)}`, target: db.tByService('metrics-ch-dr'), engine_options };
  db.jobs.push(j);
  return j;
}

function dropJob(j: { id: string }) {
  db.jobs.splice(db.jobs.findIndex((x) => x.id === j.id), 1);
}

/** Opens an existing job's wizard on its Backup method step. */
async function toMethodOf(user: ReturnType<typeof userEvent.setup>, j: { id: string; target: { id: string } }) {
  await renderApp(`/backups/new?target=${j.target.id}&job=${j.id}`);
  await user.click(await screen.findByRole('button', { name: /^Backup method/ }, T));
  await screen.findByRole('heading', { name: 'Backup method' }, T);
  await waitFor(() => expect(screen.queryByText('Checking whether this server takes native backups…')).toBeNull(), T);
}

/** Records the non-GET requests the page sends; `answer` may replace the response. */
function recordRequests(answer?: (method: string, path: string) => Response | undefined) {
  const sent: { method: string; path: string; body: Record<string, unknown> }[] = [];
  const orig = window.fetch;
  window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
    if (init?.method && init.method !== 'GET') {
      sent.push({ method: init.method, path: String(input), body: init.body ? JSON.parse(String(init.body)) : {} });
      const r = answer?.(init.method, String(input));
      if (r) return Promise.resolve(r);
    }
    return orig(input, init);
  };
  return { sent, restore: () => (window.fetch = orig) };
}

/** Drops the jobs a test created, so the mock target stays a candidate. */
function keepJobs() {
  const before = db.jobs.length;
  const t = db.tByService('events-ch');
  const status = t.status;
  return () => {
    db.jobs.splice(before);
    t.status = status;
  };
}

describe('Backup wizard · ClickHouse method', () => {
  it('starts a new job on Native, recommended, with incrementals off until they are picked (R42 lifted)', async () => {
    const user = userEvent.setup();
    const reset = keepJobs();
    await toMethod(user);
    expect(screen.getByText('Step 3 of 5')).toBeInTheDocument();
    // with the ingest endpoint on and ClickHouse 24.8, a new job is native: native backups are restored now (task 16)
    const native = screen.getByRole('radio', { name: /^Native/ });
    expect(native).toBeChecked();
    expect(native).toBeEnabled();
    expect(within(native.closest('label')!).getByText('Recommended')).toHaveClass('badge');
    expect(native).toHaveAccessibleDescription(/Whole databases, ClickHouse 24\.8 or later\.$/);
    expect(screen.getByRole('radio', { name: /^Logical/ })).not.toBeChecked();
    // the note on egress and the certificate
    const note = screen.getByText('Before the first native run').closest('.note')!;
    expect(note).toHaveTextContent(/ingest\.url/);
    expect(note).toHaveTextContent(/egress from the ClickHouse pods/);
    expect(note).toHaveTextContent(/openSSL\.client\.caConfig/);
    // the data skips the agent; the BACKUP statement and the run's credential do not (docs/clickhouse-backups.md, Network)
    expect(note).toHaveTextContent("The backup data does not pass through the agent; the BACKUP statement, with the run's credential, does, in the cluster's transfer mode (in the clear in compressed mode).");
    expect(note).not.toHaveTextContent('does not apply');
    // incrementals are off, and can be picked with Native (task 13)
    expect(screen.getByRole('radio', { name: /^Off/ })).toBeChecked();
    const weekly = screen.getByRole('radio', { name: /^Weekly full, daily incrementals/ });
    expect(weekly).toBeEnabled();
    expect(weekly).toHaveAccessibleDescription(/^The first run of each week and of each month, in the job's timezone, is a full backup, and so is every run that gets a weekly or monthly copy\./);
    await user.click(weekly);

    await toReview(user);
    const dt = await screen.findByText('Method', { selector: 'dt' }, T);
    expect(dt.nextElementSibling).toHaveTextContent('Native · weekly full, daily incrementals');
    // a native dry run backs up the structure only (R40)
    expect(screen.getByText(/A dry run takes a structure-only native backup \(the definitions, no data\)/)).toBeInTheDocument();

    const rec = recordRequests();
    try {
      await user.click(screen.getByRole('button', { name: 'Create job and run dry run' }));
      await waitFor(() => expect(rec.sent.some((c) => c.path.endsWith('/backup/jobs'))).toBe(true), T);
      const create = rec.sent.find((c) => c.method === 'POST' && c.path.endsWith('/backup/jobs'))!;
      expect(create.body.engine_options).toEqual({ databases: [], method: 'native', incremental: 'weekly_full_daily' });
    } finally {
      rec.restore();
      reset();
    }
  }, 15_000);

  it('starts on Logical with Native disabled, and the reason, when the ingest endpoint is off', async () => {
    localStorage.setItem(INGEST_OFF, '1');
    const user = userEvent.setup();
    await toMethod(user);
    const native = screen.getByRole('radio', { name: /^Native/ });
    await waitFor(() => expect(native).toBeDisabled());
    expect(native).not.toBeChecked();
    expect(native).toHaveAccessibleDescription(/Native backups need the ingest endpoint, which is off on this server/);
    expect(screen.getByRole('radio', { name: /^Logical/ })).toBeChecked();
    expect(screen.getByRole('radio', { name: /^Weekly full, daily incrementals/ })).toBeDisabled();
  });

  it('shows a refused method on the method step', async () => {
    const user = userEvent.setup();
    const reset = keepJobs();
    await toMethod(user);
    await user.click(screen.getByRole('radio', { name: /^Native/ }));
    await toReview(user);
    const msg = 'native backups need the ingest endpoint, which is off (set ingest.url)';
    const rec = recordRequests((method, path) =>
      method === 'POST' && path.endsWith('/backup/jobs')
        ? new Response(JSON.stringify({ error: 'invalid job', fields: { method: msg } }), { status: 422, headers: { 'content-type': 'application/json' } })
        : undefined,
    );
    try {
      await user.click(await screen.findByRole('button', { name: 'Create job and run dry run' }, T));
      await screen.findByRole('heading', { name: 'Backup method' }, T);
      const fieldset = screen.getByRole('group', { name: 'Method' });
      expect(fieldset).toHaveAccessibleDescription(msg);
      expect(screen.getByText(msg)).toBeInTheDocument();
    } finally {
      rec.restore();
      reset();
    }
  }, 15_000);

  it('keeps an existing job on its method and disables Native below ClickHouse 24.8', async () => {
    const user = userEvent.setup();
    const j = db.jobs.find((x) => x.target.service === 'metrics-ch')!; // ClickHouse 24.3, logical
    await renderApp(`/backups/new?target=${j.target.id}&job=${j.id}`);
    await user.click(await screen.findByRole('button', { name: /^Backup method/ }, T));
    await screen.findByRole('heading', { name: 'Backup method' }, T);
    const native = screen.getByRole('radio', { name: /^Native/ });
    expect(native).toBeDisabled();
    expect(native).toHaveAccessibleDescription('Native backups need ClickHouse 24.8 or later; this server runs 24.3.');
    expect(screen.getByRole('radio', { name: /^Logical/ })).toBeChecked();
  });

  it('keeps an existing logical job on Logical on 24.8 or later with the ingest endpoint on', async () => {
    const user = userEvent.setup();
    const j = editJob({ databases: ['metrics'] });
    try {
      await toMethodOf(user, j);
      const native = screen.getByRole('radio', { name: /^Native/ });
      expect(native).toBeEnabled();
      expect(native).not.toBeChecked();
      expect(screen.getByRole('radio', { name: /^Logical/ })).toBeChecked();
      expect(screen.queryByText('Before the first native run')).toBeNull();
      const weekly = screen.getByRole('radio', { name: /^Weekly full, daily incrementals/ });
      expect(weekly).toBeDisabled();
      expect(weekly).toHaveAccessibleDescription('Incrementals need the native method.');
    } finally {
      dropJob(j);
    }
  });

  it('refuses to save an existing native job while the ingest endpoint is off', async () => {
    localStorage.setItem(INGEST_OFF, '1');
    const user = userEvent.setup();
    const j = editJob({ databases: ['metrics'], method: 'native', incremental: 'weekly_full_daily' });
    try {
      await toMethodOf(user, j);
      const native = screen.getByRole('radio', { name: /^Native/ });
      expect(native).toBeChecked();
      expect(native).toHaveAccessibleDescription(/Native backups need the ingest endpoint, which is off on this server/);
      await user.click(screen.getByRole('button', { name: 'Next: destination' }));
      // still on the method step, the reason on the Method field
      expect(screen.getByRole('heading', { name: 'Backup method' })).toBeInTheDocument();
      expect(screen.getByRole('group', { name: 'Method' })).toHaveAccessibleDescription(/Native backups need the ingest endpoint, which is off on this server/);
      await user.click(screen.getByRole('radio', { name: /^Logical/ }));
      await user.click(screen.getByRole('button', { name: 'Next: destination' }));
      await screen.findByRole('heading', { name: 'Destination & schedule' }, T);
    } finally {
      dropJob(j);
    }
  });

  it('disables Native for a job with a table filter, and keeps the filter and the CA when saving', async () => {
    const user = userEvent.setup();
    const pem = '-----BEGIN CERTIFICATE-----\nMIIBlab\n-----END CERTIFICATE-----';
    const j = editJob({ databases: ['metrics'], tables: ['metrics.events', 'metrics.sessions'], ca_pem: pem });
    let refuse = true; // the first save is refused on tables
    const rec = recordRequests((method) => {
      if (method !== 'PATCH' || !refuse) return undefined;
      refuse = false;
      const body = JSON.stringify({ error: 'invalid job', fields: { tables: 'cannot be used with method "native", which backs up whole databases' } });
      return new Response(body, { status: 422, headers: { 'content-type': 'application/json' } });
    });
    try {
      await toMethodOf(user, j);
      const native = screen.getByRole('radio', { name: /^Native/ });
      expect(native).toBeDisabled();
      expect(native).toHaveAccessibleDescription(
        'This job backs up only some tables (metrics.events, metrics.sessions); native backups take whole databases. Keep Logical, or remove the table filter through the API.',
      );
      await toReview(user);
      await user.click(screen.getByRole('button', { name: 'Save changes' }));
      // a refused table filter is named on the method step
      await screen.findByRole('heading', { name: 'Backup method' }, T);
      expect(screen.getByText('Table filter: cannot be used with method "native", which backs up whole databases')).toBeInTheDocument();
      await toReview(user);
      await user.click(screen.getByRole('button', { name: 'Save changes' }));
      await waitFor(() => expect(rec.sent.filter((c) => c.method === 'PATCH')).toHaveLength(2), T);
      expect(rec.sent.at(-1)!.body.engine_options).toEqual({ databases: ['metrics'], tables: ['metrics.events', 'metrics.sessions'], ca_pem: pem, method: 'logical', incremental: '' });
    } finally {
      rec.restore();
      dropJob(j);
    }
  }, 15_000);
});

const operator = { principal: { object_id: 'o1', name: 'Op' }, is_guest: false, roles: ['operator'], grants: [], permissions: { read: true, operate: true }, dev_mode: false } as unknown as Me;

function renderRun(run: BackupRunDetail) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify(run), { status: 200, headers: { 'Content-Type': 'application/json' } })),
  );
  return import('../ui/BackupRunDialog').then(({ BackupRunDialog }) =>
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MeProvider me={operator}>
          <BackupRunDialog id="r1" onClose={() => {}} />
        </MeProvider>
      </QueryClientProvider>,
    ),
  );
}

const nativeRun = (over: Partial<BackupRunDetail> = {}): BackupRunDetail => ({
  id: 'r1', job_id: 'j1', target_service: 'metrics-ch', cluster_name: 'lab', engine: 'clickhouse', trigger: 'schedule', status: 'partial', scheduled_for: null, tier: 'daily',
  started_at: '2026-11-26T03:30:00Z', finished_at: '2026-11-26T03:31:25Z', bytes: 2.4e9, wire_bytes: 0, blob_path: 'lab/lab/metrics-ch/clickhouse/2026/11/26/r1', sha256: '5d0e8a3c4b2a19f2',
  error: 'lab-azurite: upload data/analytics/events/202611_3_3_0/data.bin: dial tcp: i/o timeout', destination_name: 'lab-copies', repair_of: null, method: 'native', objects: 1284,
  copies: [
    { destination_id: 'd1', destination_name: 'lab-minio', destination_kind: 's3', status: 'succeeded', blob_path: 'lab/lab/metrics-ch/clickhouse/2026/11/26/r1', bytes: 2.4e9, sha256: '5d0e8a3c4b2a19f2', tier: 'daily', error: '' },
    { destination_id: 'd2', destination_name: 'lab-azurite', destination_kind: 'azure_blob', status: 'failed', blob_path: '', bytes: 0, sha256: '', tier: '', error: 'upload data/analytics/events/202611_3_3_0/data.bin: dial tcp: i/o timeout' },
  ],
  // the server still builds logical commands for it: the page must not show them
  restore: { doc: 'docs/restore.md#clickhouse', steps: [{ title: 'Download the backup and its manifest', commands: 'aws s3 cp s3://backups/lab/r1 backup.zip' }], copies: [{ destination_id: 'd1', name: 'lab-minio', kind: 's3', selected: true, run_id: 'r1', taken_at: '2026-11-26T03:30:00Z' }] },
  next_repair_at: null,
  ...over,
});

describe('run page · native run', () => {
  it('shows the Native badge and the object count, says the next run is a full backup, and offers Restore… without restore commands', async () => {
    await renderRun(nativeRun());
    const dt = await screen.findByText('Method', { selector: 'dt' }, T);
    const dd = dt.nextElementSibling as HTMLElement;
    expect(within(dd).getByText('Native')).toHaveClass('badge');
    expect(dd).toHaveTextContent('1,284 objects');
    expect(screen.getByText(/A native run is not repaired: the next run is a full backup\./)).toBeInTheDocument();
    expect(screen.queryByText(/Repair queued|repair runs/)).toBeNull();
    // no logical restore guide
    expect(screen.queryByText(/To restore by hand/)).toBeNull();
    expect(screen.queryByText('Download the backup and its manifest')).toBeNull();
    expect(screen.queryByRole('group', { name: 'Restore from copy' })).toBeNull();
    // R38 lifted: a native run is restored from the UI (task 16), never by hand
    expect(screen.getByText('A native backup has no commands to restore by hand: ClickHouse reads it back through the ingest endpoint.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Restore…' })).toBeEnabled();
    expect(screen.queryByText(/Or restore by hand/)).toBeNull();
    // the tier it was written with
    expect(screen.getByText('Tier', { selector: 'dt' }).nextElementSibling).toHaveTextContent(/^daily$/);
  });

  it('says when a daily copy is kept at least as long as weekly as a chain member (R45)', async () => {
    await renderRun(nativeRun({ status: 'succeeded', error: '', copies: [nativeRun().copies![0]], kept_as: 'weekly' }));
    const dt = await screen.findByText('Tier', { selector: 'dt' }, T);
    expect(dt.nextElementSibling).toHaveTextContent('daily · kept at least as long as weekly: a later incremental is based on it');
  });

  it('shows a succeeded native run with no repair note, and a logical run with no method row', async () => {
    await renderRun(nativeRun({ status: 'succeeded', error: '', destination_name: 'lab-minio', copies: [nativeRun().copies![0]] }));
    const dt = await screen.findByText('Method', { selector: 'dt' }, T);
    expect(dt.nextElementSibling).toHaveTextContent('Native · 1,284 objects');
    expect(screen.queryByText(/the next run is a full backup/)).toBeNull();
    expect(screen.getByText('Directory', { selector: 'dt' })).toBeInTheDocument();
    cleanup();
    vi.unstubAllGlobals();
    await renderRun(nativeRun({ method: 'logical', objects: null, engine: 'postgresql', target_service: 'billing-pg', status: 'succeeded', error: '', copies: [] }));
    await screen.findByText(/To restore by hand/, {}, T);
    expect(screen.queryByText('Method', { selector: 'dt' })).toBeNull();
  });
});

/** A succeeded native run of events-ch in the mock database, first in Backups › Runs; the returned function drops it. */
function addNativeRun(over: Partial<BackupRunDetail> = {}) {
  const run: BackupRunDetail = { ...nativeRun(), id: 'native-run-1', target_service: 'events-ch', cluster_name: 'eks-fra-data', status: 'succeeded', error: '', started_at: new Date(Date.now() - 3600_000).toISOString(), copies: [nativeRun().copies![0]], ...over };
  const { restore: _, next_repair_at: __, ...stored } = run;
  db.runs.unshift(stored);
  return { run, drop: () => void db.runs.splice(db.runs.findIndex((r) => r.id === run.id), 1) };
}

async function openNativeRestore(user: ReturnType<typeof userEvent.setup>, run: BackupRunDetail) {
  await renderApp('/backups?tab=runs');
  const rows = await screen.findAllByLabelText(`Details of the ${run.target_service} run of ${relDateTime(run.started_at)}`, {}, T);
  await user.click(rows[0]);
  await user.click(await screen.findByRole('button', { name: 'Restore…' }, T));
  const dlg = await screen.findByRole('dialog', { name: `Restore ${run.target_service} into a new target` }, T);
  await user.click(within(dlg).getByRole('combobox', { name: /^Target/ }));
  await user.click(await screen.findByRole('option', { name: /\/ metrics-ch-dr/ }, T));
  await user.click(within(dlg).getByRole('radio', { name: /Store in Olympos/ }));
  await user.type(within(dlg).getByLabelText('Username'), 'admin');
  await user.type(within(dlg).getByLabelText('Password'), 'pw-native-123');
  await user.click(within(dlg).getByRole('button', { name: 'Check target' }));
  return dlg;
}

describe('restore dialog · native run', () => {
  it('lists the objects by database; a left out object shows its reason and cannot be selected', async () => {
    const user = userEvent.setup();
    const { run, drop } = addNativeRun();
    try {
      const dlg = await openNativeRestore(user, run);
      expect(within(dlg).getByText(/ClickHouse · native backup · run of/)).toBeInTheDocument();
      await within(dlg).findByText('The target can take this restore.', {}, T);
      const report = within(dlg).getByRole('region', { name: 'Target check' });
      expect(within(report).getByText("The backup's signed manifests verify: this run and every run it is based on")).toBeInTheDocument();
      // databases are what the maker selects
      const analytics = within(report).getByRole('checkbox', { name: /^analytics/ });
      expect(analytics).toBeChecked();
      expect(analytics.closest('label')).toHaveTextContent('4 of 6 objects restored');
      const objs = within(report).getByRole('list', { name: 'Objects of analytics' });
      const left = within(objs).getByText('events_all').closest('li')!;
      expect(left).toHaveTextContent('Left out');
      expect(left).toHaveTextContent('The Distributed engine is not on the restore allowlist');
      // nothing per object can be selected: no control on a left out object (nor on a restored one)
      expect(within(left).queryByRole('checkbox')).toBeNull();
      expect(within(objs).queryAllByRole('checkbox')).toHaveLength(0);
      expect(within(objs).getByText('live_events').closest('li')).toHaveTextContent('otherLeft outA live view is not restored');
      expect(within(objs).getByText('events').closest('li')).toHaveTextContent('Restored');
      expect(within(report).getByRole('list', { name: 'Objects of dicts' })).toHaveTextContent('Its ClickHouse source names a host');
      // the note on what a native restore creates
      expect(within(dlg).getByText('What a native restore creates').closest('.note')).toHaveTextContent('Left out objects are re-applied by hand after the restore.');

      // the decisions are for the selection: a view that reads a database left out is left out
      await user.click(within(report).getByRole('checkbox', { name: /^dicts/ }));
      await user.click(within(dlg).getByRole('button', { name: 'Check again' }));
      await waitFor(() => expect(within(dlg).getByRole('checkbox', { name: /^dicts/ }).closest('label')).toHaveTextContent('not selected'), T);
      expect(within(dlg).getByText('top_countries').closest('li')).toHaveTextContent('It reads dicts.countries, which is not restored');
      expect(within(dlg).queryByRole('list', { name: 'Objects of dicts' })).toBeNull();
      expect(document.body.innerHTML).not.toContain('pw-native-123');
    } finally {
      drop();
    }
  }, 20_000);

  it('refuses a copy whose manifest does not verify, with its objects all left out', async () => {
    const user = userEvent.setup();
    const { run, drop } = addNativeRun({ sha256: 'unverified' });
    try {
      const dlg = await openNativeRestore(user, run);
      await within(dlg).findByText('Invalid restore request. Check the highlighted fields.', {}, T);
      // the refusal is on the copy, shown once above the form
      expect(within(dlg).getAllByRole('alert')[0]).toHaveTextContent(/^the backup's manifest does not verify$/);
      const objs = within(dlg).getByRole('list', { name: 'Objects of analytics' });
      expect(within(objs).getAllByRole('listitem').every((li) => li.textContent?.includes("The backup's manifest does not verify"))).toBe(true);
      expect(within(dlg).queryAllByRole('checkbox', { name: /^analytics/ })).toHaveLength(0);
      expect(screen.getByRole('button', { name: 'Submit for approval' })).toBeDisabled();
      expect(within(dlg).queryByText(/signed manifests verify/)).toBeNull();
    } finally {
      drop();
    }
  }, 20_000);
});
