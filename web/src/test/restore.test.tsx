// Restore from the UI (docs/design/ui-restore.md): the dialog on a run, the
// requests on Approvals, and the waiting badge. Runs against the mock API.
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import * as db from '../mocks/db';
import { relDateTime } from '../lib/format';
import { readable } from '../ui/RestoreDialog';
import { RestoreProgressView } from '../ui/restore';
import { renderApp } from './renderApp';

afterEach(() => {
  cleanup();
  localStorage.removeItem('olympos.mock.role');
});

const T = { timeout: 5000 };
type User = ReturnType<typeof userEvent.setup>;

const billingRun = () => db.runs.find((r) => r.target_service === 'billing-pg' && r.status === 'partial')!;
const baoRun = () => db.runs.find((r) => r.target_service === 'openbao' && r.status === 'succeeded')!;

/** Opens the run's details from Backups › Runs, then its restore dialog. */
async function openRestore(user: User, run: { target_service: string; started_at: string | null }) {
  await renderApp('/backups?tab=runs');
  const rows = await screen.findAllByLabelText(`Restore commands and details of the ${run.target_service} run of ${relDateTime(run.started_at)}`, {}, T);
  await user.click(rows[0]);
  await user.click(await screen.findByRole('button', { name: 'Restore…' }, T));
  return screen.findByRole('dialog', { name: `Restore ${run.target_service} into a new target` }, T);
}

async function chooseTarget(user: User, service: string) {
  await user.click(screen.getByRole('combobox', { name: /^Target/ }));
  await user.click(await screen.findByRole('option', { name: new RegExp(`/ ${service}`) }, T));
}

const submitButton = () => screen.getByRole('button', { name: /Submit for approval|Break-glass: start now/ });

describe('restore dialog', () => {
  it('validates, shows conflicts and the non-superuser mode, and opens a request without keeping the password', async () => {
    const user = userEvent.setup();
    const dlg = await openRestore(user, billingRun());
    // a failed copy is listed but cannot be chosen
    const copy = within(dlg).getByRole('group', { name: 'Copy' });
    expect(within(copy).getByRole('radio', { name: /minio-factory/ })).toBeDisabled();
    expect(within(copy).getByRole('radio', { name: /blob-weu-backups/ })).toBeChecked();
    expect(submitButton()).toBeDisabled();

    await user.click(within(dlg).getByRole('button', { name: 'Check target' }));
    expect(await within(dlg).findByText('Choose the target to restore into.')).toBeInTheDocument();
    expect(within(dlg).getByText('Enter an admin login of the new database.')).toBeInTheDocument();

    await chooseTarget(user, 'billing-pg-dr');
    await user.click(within(dlg).getByRole('radio', { name: /Store in Olympos/ }));
    await user.type(within(dlg).getByLabelText('Username'), 'app');
    await user.type(within(dlg).getByLabelText('Password'), 'pw-canary-123');
    await user.click(within(dlg).getByRole('button', { name: 'Check target' }));

    const report = await within(dlg).findByRole('region', { name: 'Target check' }, T);
    await within(report).findByText(/already exist on the target with data in them/i, {}, T);
    const audit = within(report).getByRole('checkbox', { name: /billing_audit/ });
    expect(audit.closest('label')).toHaveTextContent('Exists with data');
    expect(within(report).getByRole('checkbox', { name: /postgres/ }).closest('label')).toHaveTextContent('Exists, empty');
    expect(within(report).getByRole('checkbox', { name: /^billing\b/ }).closest('label')).toHaveTextContent('New');
    expect(within(report).getByText('Not a superuser: owners, privileges and roles are not restored')).toBeInTheDocument();
    expect(within(report).getByText(/--no-owner --no-privileges/)).toBeInTheDocument();
    expect(within(dlg).getByRole('checkbox', { name: /Restore roles/ })).toBeDisabled();
    expect(submitButton()).toBeDisabled();

    // deselecting the conflict makes the check stale; checking again passes
    await user.click(audit);
    expect(within(report).getByText(/You changed the request since this check/)).toBeInTheDocument();
    // what the last check found stays on the deselected database
    expect(audit.closest('label')).toHaveTextContent('Exists with data');
    await user.click(within(dlg).getByRole('button', { name: 'Check again' }));
    await within(dlg).findByText('The target can take this restore.', {}, T);
    expect(submitButton()).toBeEnabled();

    await user.click(submitButton());
    expect(await within(dlg).findByText(/Explain why in at least 10 characters/)).toBeInTheDocument();
    await user.type(within(dlg).getByLabelText('Justification'), 'billing-pg lost its volume (INC-4411)');
    await user.click(submitButton());
    await screen.findByRole('heading', { name: 'Submitted for approval' }, T);

    const rq = db.restoreRequests[0];
    expect(rq.target.service).toBe('billing-pg-dr');
    expect(rq.databases).toEqual(['billing', 'postgres']);
    expect(rq.status).toBe('pending');
    // the password left only in the requests: never on the page, never in the stored request
    expect(document.body.innerHTML).not.toContain('pw-canary-123');
    expect(JSON.stringify(db.restoreRequests)).not.toContain('pw-canary-123');
  });

  it('shows the Vault checks and what the token needs; there is no database selection', async () => {
    const user = userEvent.setup();
    const dlg = await openRestore(user, baoRun());
    expect(within(dlg).getByText((_, el) => el?.id === 'rs-token-hint' && /default policy plus update and sudo on sys\/storage\/raft\/snapshot-force/.test(el.textContent ?? ''))).toBeInTheDocument();
    expect(within(dlg).getByText("After the restore")).toBeInTheDocument();
    expect(within(dlg).getByLabelText('Token of the new Vault')).toHaveAttribute('type', 'password');

    await chooseTarget(user, 'openbao-dr');
    await user.type(within(dlg).getByLabelText('Token of the new Vault'), 'nosudo-token');
    await user.click(within(dlg).getByRole('button', { name: 'Check target' }));
    const checks = await within(dlg).findByRole('list', { name: 'Vault checks' }, T);
    const rows = within(checks).getAllByRole('listitem');
    expect(rows.map((r) => r.textContent)).toEqual(['Initialized', 'Unsealed', 'Active node (not an HA standby)', 'Token holds update and sudo on sys/storage/raft/snapshot-force']);
    expect(within(rows[0]).getByLabelText('Passed')).toBeInTheDocument();
    expect(within(rows[3]).getByLabelText('Failed')).toBeInTheDocument();
    expect(within(dlg).getByText('this token needs both update and sudo on sys/storage/raft/snapshot-force on the target')).toBeInTheDocument();
    // a snapshot is all or nothing: even after the check there is no database selection
    expect(within(dlg).queryByRole('group', { name: /^Databases/ })).toBeNull();
    expect(within(dlg).queryByText(/Databases \(/)).toBeNull();
    expect(submitButton()).toBeDisabled();
  });

  it('offers break-glass to admins only, and it needs a justification', async () => {
    localStorage.setItem('olympos.mock.role', 'operator');
    const user = userEvent.setup();
    let dlg = await openRestore(user, baoRun());
    expect(within(dlg).queryByRole('checkbox', { name: /Break-glass/ })).toBeNull();
    cleanup();

    localStorage.setItem('olympos.mock.role', 'admin');
    dlg = await openRestore(user, baoRun());
    await chooseTarget(user, 'openbao-dr');
    await user.type(within(dlg).getByLabelText('Token of the new Vault'), 'hvs.restore-token');
    await user.click(within(dlg).getByRole('button', { name: 'Check target' }));
    await within(dlg).findByText('The target can take this restore.', {}, T);
    await user.click(within(dlg).getByRole('checkbox', { name: /Break-glass: start now, without a checker/ }));
    const before = db.restoreRequests.length;
    await user.click(submitButton());
    expect(await within(dlg).findByText(/Explain why in at least 10 characters/)).toBeInTheDocument();
    // nothing was opened without the justification
    expect(db.restoreRequests.length).toBe(before);

    await user.type(within(dlg).getByLabelText('Justification'), 'openbao is gone after the node pool failure (INC-4398)');
    await user.click(submitButton());
    await screen.findByRole('heading', { name: 'Break-glass restore started' }, T);
    const rq = db.restoreRequests[0];
    expect(rq.break_glass).toBe(true);
    expect(rq.status).toBe('approved');
    expect(rq.has_vault_token).toBe(true);
    expect(JSON.stringify(rq)).not.toContain('hvs.restore-token');
    expect(document.body.innerHTML).not.toContain('hvs.restore-token');
  });
});

describe('restore dialog targets and selections', () => {
  it('hides only the backup’s own target by id: the same Service in another namespace stays selectable', async () => {
    const user = userEvent.setup();
    const run = billingRun();
    const own = db.jobs.find((j) => j.id === run.job_id)!.target;
    const sibling = db.targets.find((t) => t.service === own.service && t.cluster_name === own.cluster_name && t.namespace !== own.namespace)!;
    expect(sibling).toBeTruthy();
    const dlg = await openRestore(user, run);
    await user.click(within(dlg).getByRole('combobox', { name: /^Target/ }));
    await screen.findByRole('option', { name: new RegExp(`${sibling.cluster_name} / ${sibling.namespace} / ${sibling.service}`) }, T);
    expect(screen.queryByRole('option', { name: new RegExp(`${own.cluster_name} / ${own.namespace} / ${own.service}`) })).toBeNull();
    await user.click(screen.getByRole('option', { name: new RegExp(`/ ${sibling.namespace} / `) }));
    expect(within(dlg).getByRole('combobox', { name: /^Target/ })).toHaveTextContent(`${sibling.namespace} / ${sibling.service}`);
  });

  it('does not offer a Vault that is configured in Olympos', async () => {
    const user = userEvent.setup();
    const configured = db.vaults.find((v) => v.status === 'configured' && v.target.service !== baoRun().target_service)!;
    const dlg = await openRestore(user, baoRun());
    await user.click(within(dlg).getByRole('combobox', { name: /^Target/ }));
    await screen.findByRole('option', { name: /openbao-dr/ }, T);
    expect(screen.queryByRole('option', { name: new RegExp(`${configured.target.cluster_name} / ${configured.target.namespace} / ${configured.target.service}$`) })).toBeNull();
  });

  it('starts the database selection again when the copy changes', async () => {
    const user = userEvent.setup();
    // a partial run whose missing copy a repair completed: two copies to choose from
    const repaired = db.runs.find((r) => r.status === 'partial' && db.runs.some((x) => x.repair_of === r.id && x.status === 'succeeded'))!;
    const dlg = await openRestore(user, repaired);
    await chooseTarget(user, 'billing-pg-dr');
    await user.type(within(dlg).getByLabelText('Username'), 'postgres');
    await user.type(within(dlg).getByLabelText('Key Vault'), 'kv-dr-neu');
    await user.type(within(dlg).getByLabelText('Secret name (holds the password)'), 'billing-pg-dr-admin');
    await user.click(within(dlg).getByRole('button', { name: 'Check target' }));
    const report = await within(dlg).findByRole('region', { name: 'Target check' }, T);
    await user.click(await within(report).findByRole('checkbox', { name: /billing_audit/ }, T));
    expect(within(report).getByText(/2 of 3 in the backup selected/)).toBeInTheDocument();
    // the backdrop does not drop a filled form
    await user.click(document.querySelector('.overlay')!);
    expect(screen.getByRole('dialog', { name: /Restore billing-pg into a new target/ })).toBeInTheDocument();
    // another copy: the selection is gone until the next check lists that copy's databases
    const copy = within(dlg).getByRole('group', { name: 'Copy' });
    const other = within(copy).getByRole('radio', { name: /Repair/ });
    expect(other).toBeEnabled();
    await user.click(other);
    expect(within(dlg).queryByText(/in the backup selected/)).toBeNull();
    await user.click(within(dlg).getByRole('button', { name: 'Check again' }));
    expect(await within(dlg).findByText(/3 of 3 in the backup selected/, {}, T)).toBeInTheDocument();
  });

  it('drops a machine code from a server message', () => {
    expect(readable("agent_offline: the target cluster's agent is not connected to this server")).toBe("The target cluster's agent is not connected to this server");
    expect(readable('the target cannot take this restore')).toBe('The target cannot take this restore');
  });

  it('shows a refusal once, readable, without its code', async () => {
    const user = userEvent.setup();
    const dlg = await openRestore(user, billingRun());
    await chooseTarget(user, 'billing-pg-dr');
    await user.type(within(dlg).getByLabelText('Username'), 'nobody');
    await user.type(within(dlg).getByLabelText('Key Vault'), 'kv-dr-neu');
    await user.type(within(dlg).getByLabelText('Secret name (holds the password)'), 'billing-pg-dr-admin');
    await user.click(within(dlg).getByRole('button', { name: 'Check target' }));
    const msg = await within(dlg).findByText(/^The target check failed: password authentication failed/, {}, T);
    expect(msg).toHaveTextContent(/failed for user "nobody"\.$/);
    expect(within(dlg).getAllByText(/password authentication failed/)).toHaveLength(1);
    expect(within(dlg).getByRole('combobox', { name: /^Target/ })).toHaveAttribute('aria-invalid', 'true');
  });
});

describe('restore requests on Approvals', () => {
  it('lists both kinds side by side', async () => {
    await renderApp('/approvals?view=all');
    const list = await screen.findByRole('complementary', { name: 'Requests' }, T);
    await within(list).findAllByText('Restore', {}, T);
    await within(list).findAllByText('Vault', {}, T);
    expect(within(list).getAllByText('Restore').length).toBeGreaterThan(0);
    expect(within(list).getAllByText('billing-pg-dr').length).toBeGreaterThan(0);
    expect(within(list).getByText('CR-0142')).toBeInTheDocument();
  });

  it('counts waiting restores in the sidebar badge', async () => {
    await renderApp('/approvals?view=waiting');
    const crs = db.changeRequests.filter((c) => c.status === 'pending' && c.maker.object_id !== db.people.yigit.object_id).length;
    const restores = db.restoreRequests.filter((r) => r.status === 'pending' && r.maker.object_id !== db.people.yigit.object_id).length;
    expect(restores).toBeGreaterThan(0);
    const nav = await screen.findByRole('navigation', { name: 'Main' }, T);
    await waitFor(() => expect(within(nav).getByRole('link', { name: /Approvals/ })).toHaveTextContent(`${crs + restores} waiting for you`), T);
  });

  it('shows the progress of a running restore', async () => {
    const running = db.restoreRequests.find((r) => r.status === 'running')!;
    await renderApp(`/approvals?view=all&restore=${running.id}`);
    const bar = await screen.findByRole('progressbar', { name: 'Backup read' }, T);
    expect(bar).toHaveAttribute('aria-valuenow', '45');
    expect(screen.getByText('1.4 GB of 3.1 GB read')).toBeInTheDocument();
    expect(screen.getByText(/Created on the target:/)).toHaveTextContent('Created on the target: billing');
  });

  it('never shows more read than the copy holds', () => {
    render(<RestoreProgressView engine="postgresql" progress={{ phase: 'restore', bytes: 2.1e9, total: 1e9 }} />);
    expect(screen.getByText('1 GB of 1 GB read')).toBeInTheDocument();
    expect(screen.getByRole('progressbar', { name: 'Backup read' })).toHaveAttribute('aria-valuenow', '100');
  });

  it('shows per-database results with what ClickHouse did not restore', async () => {
    const ch = db.restoreRequests.find((r) => r.engine === 'clickhouse' && r.status === 'succeeded')!;
    await renderApp(`/approvals?view=all&restore=${ch.id}`);
    const table = await screen.findByRole('table', { name: 'Restore result' }, T);
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows.map((r) => within(r).getAllByRole('cell')[0].textContent)).toEqual(['default', 'metrics']);
    expect(rows[1]).toHaveTextContent('1,284,000,112');
    const skipped = screen.getByLabelText('Not restored in metrics');
    expect(skipped).toHaveTextContent('Not restored in metrics (3) · recreate or re-apply from your schema');
    expect(skipped).toHaveTextContent('metrics.geo (dictionary): not created');
    expect(screen.getByLabelText('Notes from the restore')).toHaveTextContent('requests_by_minute__restored_data');
  });

  it('shows the checker what a native request leaves out, as recorded when it was opened', async () => {
    const rq = db.restoreRequests.find((r) => r.options.native && r.status === 'pending')!;
    await renderApp(`/approvals?view=all&restore=${rq.id}`);
    const left = await screen.findByLabelText('Left out by the native restore', {}, T);
    const list = within(left).getByRole('list', { name: 'Objects of metrics' });
    const items = within(list).getAllByRole('listitem');
    expect(items.map((li) => li.textContent)).toEqual([
      'requests_all tableLeft outThe Distributed engine is not on the restore allowlist',
      'geo dictionaryLeft outIts ClickHouse source names a host',
    ]);
    expect(within(left).queryByRole('list', { name: 'Objects of default' })).toBeNull();
    expect(left).toHaveTextContent("If the backup's check at start leaves out anything else, the restore does not start.");
    expect(screen.getByText('What a native restore creates')).toBeInTheDocument();
    expect(screen.queryByText('What a ClickHouse restore creates')).toBeNull();
    await screen.findByRole('button', { name: 'Approve restore' }, T);
    // a native restore verifies its manifests first and each object while ClickHouse reads it, not one checksum
    const note = screen.getByText(/^Approving lets the server restore this backup/);
    expect(note).toHaveTextContent('The backup’s signed manifests are verified before anything is written, and each object while ClickHouse reads it');
    expect(note).toHaveTextContent('the databases it created stay on the target');
    expect(note).not.toHaveTextContent('checksum');
  });

  it('tells the checker of a logical restore that the checksum is verified first', async () => {
    // the PostgreSQL request another person opened (an earlier test may have approved it)
    const rq = db.restoreRequests.find((r) => r.engine === 'postgresql' && r.maker.object_id === db.people.selin.object_id)!;
    const saved = rq.status;
    rq.status = 'pending';
    try {
      await renderApp(`/approvals?view=all&restore=${rq.id}`);
      await screen.findByRole('button', { name: 'Approve restore' }, T);
      const note = screen.getByText(/^Approving lets the server restore this backup/);
      expect(note).toHaveTextContent('The backup’s checksum is verified before anything is written, and the target is checked again when the restore starts.');
      expect(note).not.toHaveTextContent('signed manifests');
    } finally {
      rq.status = saved;
    }
  });

  it('says when a native request leaves nothing out', async () => {
    const rq = db.restoreRequests.find((r) => r.options.native && r.status === 'pending')!;
    const saved = rq.options.native;
    rq.options.native = { databases: ['metrics'], excluded: [] };
    try {
      await renderApp(`/approvals?view=all&restore=${rq.id}`);
      const left = await screen.findByLabelText('Left out by the native restore', {}, T);
      expect(left).toHaveTextContent('Nothing: every table, view, materialized view and dictionary of these databases is restored.');
    } finally {
      rq.options.native = saved;
    }
  });

  it('shows the unseal note on a Vault restore result', async () => {
    const v = db.restoreRequests.find((r) => r.engine === 'vault' && r.status === 'succeeded')!;
    await renderApp(`/approvals?view=all&restore=${v.id}`);
    const note = await screen.findByText("Next: unseal the new Vault with the source's keys", {}, T);
    expect(note.closest('.note')).toHaveTextContent("Unseal it with the source Vault's unseal keys, or by the source's auto-unseal");
    expect(note.closest('.note')).toHaveTextContent("Its root token, policies, auth methods and secrets become the source's.");
    expect(note.closest('.note')).toHaveTextContent('The token given for this request most likely stops working.');
    expect(screen.getAllByText('Break-glass').length).toBeGreaterThan(0);
  });

  it('hides the checker controls from the maker and shows them to another person', async () => {
    const user = userEvent.setup();
    const mine = db.restoreRequests.find((r) => r.status === 'pending' && r.maker.object_id === db.people.yigit.object_id)!;
    await renderApp(`/approvals?view=mine&restore=${mine.id}`);
    await screen.findByText('You opened this request. Another person with operate on both clusters must decide.', {}, T);
    expect(screen.queryByRole('button', { name: 'Approve restore' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Reject' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Withdraw request' })).toBeEnabled();
    cleanup();

    const other = db.restoreRequests.find((r) => r.status === 'pending' && r.maker.object_id === db.people.selin.object_id)!;
    await renderApp(`/approvals?view=all&restore=${other.id}`);
    await screen.findByRole('button', { name: 'Approve restore' }, T);
    // rejecting needs a comment
    await user.click(screen.getByRole('button', { name: 'Reject' }));
    expect(screen.getByText('Explain why you reject the request.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Approve restore' }));
    await waitFor(() => expect(other.status).toBe('approved'), T);
    expect(other.checker?.object_id).toBe(db.people.yigit.object_id);
  });
});
