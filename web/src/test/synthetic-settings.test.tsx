// Settings › Synthetic monitoring (docs/design/settings-synthetic.html), the probe state and "Install probe" in
// Settings › Clusters & agents, the Add cluster text (docs/design/dialog-add-cluster.html) and the Access role
// list, against the mock API.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import * as db from '../mocks/db';
import * as syn from '../mocks/synthetic';
import { match } from '../mocks/handlers';
import { boundLabel, matchesText } from '../pages/settings/Synthetic';
import { guestRolesText } from '../pages/settings/Access';
import { GUEST_FORBIDDEN_ROLES } from '../auth/permissions';
import { lastQueryClient, renderApp } from './renderApp';

afterEach(() => {
  cleanup();
  localStorage.removeItem('olympos.mock.role');
  vi.restoreAllMocks();
});

const T = { timeout: 5000 };
const rowOf = (table: HTMLElement, text: string) => within(table).getAllByRole('row').find((r) => within(r).queryByText(text, { exact: true }))!;

describe('Settings › Synthetic monitoring: host allowlist', () => {
  it('is a settings section and lists each rule with its type and what it matches', async () => {
    await renderApp('/settings/synthetic');
    const nav = await screen.findByRole('navigation', { name: 'Settings sections' }, T);
    expect(within(nav).getByRole('link', { name: 'Synthetic monitoring' })).toHaveAttribute('aria-current', 'page');
    expect(within(nav).getByRole('link', { name: 'Synthetic monitoring' })).toHaveAttribute('href', '/settings/synthetic');
    expect(screen.getByText('Synthetic monitoring · which hosts probes may call and the credentials they may use')).toBeInTheDocument();

    const table = await screen.findByRole('table', { name: 'Host allowlist' }, T);
    await within(table).findByText('wrw.com', { exact: true }, T);
    const cases: [string, string, string][] = [
      ['wrw.com', 'Suffix', 'wrw.com and every host under it'],
      ['*.dev.wrw.com', 'Wildcard', 'any host under dev.wrw.com, not dev.wrw.com itself'],
      ['*.prod.wrw.com', 'Wildcard', 'any host under prod.wrw.com, not prod.wrw.com itself'],
      ['partner-sftp.acme.net', 'Exact', 'only this host'],
    ];
    for (const [rule, type, matches] of cases) {
      const row = rowOf(table, rule);
      expect(row).toHaveTextContent(type);
      expect(row).toHaveTextContent(matches);
    }
    // the Scenarios column counts the scenarios with a host the rule matches
    const cells = within(rowOf(table, 'partner-sftp.acme.net')).getAllByRole('cell');
    expect(cells[3]).toHaveTextContent('1');
    expect(rowOf(table, 'partner-sftp.acme.net')).toHaveTextContent('· selin');
    // the change channel is the one grant.changed goes to
    await waitFor(() => expect(screen.getByText(/every change is/).textContent).toContain('posted to #platform-access'), T);
  });

  it('checks a host: the rule that allows it and the others that match, and a look-alike with no rule', async () => {
    const user = userEvent.setup();
    await renderApp('/settings/synthetic');
    const input = await screen.findByLabelText('Check a host', {}, T);
    const result = () => document.getElementById('al-check-res')!;
    await user.type(input, 'api.prod.wrw.com');
    await waitFor(() => expect(result()).toHaveTextContent('Allowed by *.prod.wrw.com (also wrw.com)'), T);
    await user.clear(input);
    await user.type(input, 'wrw.com.evil.io');
    await waitFor(() => expect(result()).toHaveTextContent('wrw.com.evil.io · no rule matches'), T);
    await user.clear(input);
    await user.type(input, '169.254.169.254');
    await waitFor(() => expect(result()).toHaveTextContent('169.254.169.254 · IP addresses are always denied; use a host name.'), T);
    // the always-blocked note
    const note = screen.getByText(/Always blocked, whatever the rules say/);
    expect(note).toHaveTextContent('IP literals, localhost, loopback, link-local and cloud metadata addresses (169.254.169.254), the Kubernetes API.');
    expect(note).toHaveTextContent('again on every redirect');
  });

  it('lets an admin add a rule and refuses to remove one still in use, naming what needs it', async () => {
    const user = userEvent.setup();
    await renderApp('/settings/synthetic');
    const table = await screen.findByRole('table', { name: 'Host allowlist' }, T);
    await user.click(await screen.findByRole('button', { name: 'Add rule' }, T));
    const dialog = screen.getByRole('dialog', { name: 'Add a rule' });
    await user.type(within(dialog).getByLabelText('Host'), '*.qa.wrw.com');
    // "*." picks wildcard, and the hint says what it matches
    expect(within(dialog).getByRole('radio', { name: /Wildcard/ })).toBeChecked();
    expect(within(dialog).getByText('Matches any host under qa.wrw.com, not qa.wrw.com itself.')).toBeInTheDocument();
    await waitFor(() => expect(within(dialog).getByText(/This change is/)).toHaveTextContent('This change is posted to #platform-access and recorded in the activity log.'), T);
    await user.click(within(dialog).getByRole('button', { name: 'Add rule' }));
    expect(await within(table).findByText('*.qa.wrw.com', {}, T)).toBeInTheDocument();
    expect(syn.allowlist.some((r) => r.pattern === '*.qa.wrw.com' && r.kind === 'wildcard')).toBe(true);

    // a duplicate is a field error
    await user.click(screen.getByRole('button', { name: 'Add rule' }));
    const again = screen.getByRole('dialog', { name: 'Add a rule' });
    await user.type(within(again).getByLabelText('Host'), '*.qa.wrw.com');
    await user.click(within(again).getByRole('button', { name: 'Add rule' }));
    expect(await within(again).findByText('This rule exists already.', {}, T)).toBeInTheDocument();
    await user.click(within(again).getByRole('button', { name: 'Cancel' }));

    // partner-sftp.acme.net is the only rule for the Partner SFTP scenario and partner-oauth's bound host
    await user.click(screen.getByRole('button', { name: 'Remove rule partner-sftp.acme.net' }));
    const rm = screen.getByRole('dialog', { name: 'Remove the rule partner-sftp.acme.net?' });
    await user.click(within(rm).getByRole('button', { name: 'Remove rule' }));
    const err = await within(rm).findByRole('alert', {}, T);
    expect(err).toHaveTextContent('This rule is still needed. Change these first:');
    expect(err).toHaveTextContent('Scenario: Partner SFTP');
    expect(err).toHaveTextContent('Credential: partner-oauth');
    await user.click(within(rm).getByRole('button', { name: 'Cancel' }));

    // a rule nothing needs goes
    await user.click(screen.getByRole('button', { name: 'Remove rule *.qa.wrw.com' }));
    await user.click(within(screen.getByRole('dialog', { name: 'Remove the rule *.qa.wrw.com?' })).getByRole('button', { name: 'Remove rule' }));
    await waitFor(() => expect(within(table).queryByText('*.qa.wrw.com')).not.toBeInTheDocument(), T);
  });

  it('is read-only for a viewer (no check either) and for a synthetic-editor (who may check a host)', async () => {
    localStorage.setItem('olympos.mock.role', 'viewer');
    await renderApp('/settings/synthetic');
    const table = await screen.findByRole('table', { name: 'Host allowlist' }, T);
    await within(table).findByText('wrw.com', { exact: true }, T);
    await screen.findByText('catalog-monitor', {}, T);
    expect(screen.queryByRole('button', { name: 'Add rule' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Remove rule/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'New credential' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Edit credential/ })).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Check a host')).not.toBeInTheDocument();
    expect(screen.getByText(/Always blocked, whatever the rules say/)).toBeInTheDocument();
    cleanup();

    localStorage.setItem('olympos.mock.role', 'editor');
    await renderApp('/settings/synthetic');
    expect(await screen.findByLabelText('Check a host', {}, T)).toBeInTheDocument();
    await within(await screen.findByRole('table', { name: 'Host allowlist' }, T)).findByText('wrw.com', { exact: true }, T);
    expect(screen.queryByRole('button', { name: 'Add rule' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Remove rule/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'New credential' })).not.toBeInTheDocument();
  });

  it('reads rules for people: Matches text and bound hosts in kind:pattern form', () => {
    expect(matchesText('suffix', 'wrw.com')).toBe('wrw.com and every host under it');
    expect(matchesText('wildcard', '*.dev.wrw.com')).toBe('any host under dev.wrw.com, not dev.wrw.com itself');
    expect(matchesText('exact', 'partner-sftp.acme.net')).toBe('only this host');
    expect(boundLabel({ pattern: '*.prod.wrw.com', kind: 'wildcard' }).text).toBe('*.prod.wrw.com');
    expect(boundLabel({ pattern: 'wrw.com', kind: 'suffix' })).toEqual({ text: 'wrw.com (suffix)', title: 'Suffix: wrw.com and every host under it' });
    // the stored and audited form, should it come back as is
    expect(boundLabel({ pattern: 'wildcard:*.dev.wrw.com', kind: '' }).text).toBe('*.dev.wrw.com');
    expect(boundLabel({ pattern: 'suffix:wrw.com', kind: '' }).text).toBe('wrw.com (suffix)');
    expect(boundLabel({ pattern: 'exact:api.wrw.com', kind: '' }).text).toBe('api.wrw.com');
  });
});

describe('Settings › Synthetic monitoring: credentials', () => {
  it('lists type, bound hosts, expiry and read failures, with the exception notice', async () => {
    await renderApp('/settings/synthetic');
    const table = await screen.findByRole('table', { name: 'Credentials' }, T);
    await within(table).findByText('catalog-monitor', {}, T);
    const catalog = rowOf(table, 'catalog-monitor');
    expect(catalog).toHaveTextContent('Bearer token');
    expect(within(catalog).getByText('*.prod.wrw.com')).toHaveClass('chip');
    expect(within(catalog).getByText('in 88 days')).toHaveClass('badge', 'ok');
    const search = rowOf(table, 'search-api-key');
    expect(search).toHaveTextContent('Header X-Api-Key');
    expect(search).toHaveTextContent('Key Vault reference');
    expect(search).toHaveTextContent('Could not be read 3 times in 24 h; check the Key Vault reference or secret');
    expect(within(search).getByText('never')).toBeInTheDocument();
    const reports = rowOf(table, 'reports-login');
    expect(reports).toHaveTextContent('Basic');
    expect(within(reports).getByText('in 9 days')).toHaveClass('badge', 'warn');
    const oauth = rowOf(table, 'partner-oauth');
    expect(oauth).toHaveTextContent('OAuth2 client credentials');
    expect(within(oauth).getByText('partner-sftp.acme.net')).toHaveClass('chip');
    expect(within(oauth).getByText('login.acme.net')).toHaveClass('chip');
    expect(within(oauth).getByText('token per run')).toBeInTheDocument();
    expect(screen.getByText('Stored encrypted in Olympos (or as a Key Vault reference). Values are never shown again.')).toBeInTheDocument();
    expect(screen.getByText(/This is an exception to “credentials never enter a cluster”/)).toHaveTextContent(
      'a credential is sent to the probe for one run, kept in memory only, and attached only to requests whose host matches the hosts it is bound to. It is dropped on redirects to other hosts and redacted from stored responses. Use dedicated, read-only monitoring accounts.',
    );
  });

  it('creates a credential: the secret is sent once, never kept in a cache or a URL, and never shown again', async () => {
    const user = userEvent.setup();
    await renderApp('/settings/synthetic');
    const sent: { url: string; method: string; body: string }[] = [];
    const fetchNow = window.fetch;
    vi.spyOn(window, 'fetch').mockImplementation((input, init) => {
      sent.push({ url: String(input), method: init?.method ?? 'GET', body: typeof init?.body === 'string' ? init.body : '' });
      return fetchNow(input, init);
    });
    const SECRET = 'tok-7f3c-very-secret';
    const table = await screen.findByRole('table', { name: 'Credentials' }, T);
    await user.click(await screen.findByRole('button', { name: 'New credential' }, T));
    const dlg = screen.getByRole('dialog', { name: 'New credential' });
    await user.type(within(dlg).getByLabelText('Name'), 'qa-token');
    await user.type(within(dlg).getByLabelText('Bound host 1'), '*.dev.wrw.com');
    expect(within(dlg).getByLabelText('Bound host 1 type')).toHaveValue('wildcard');
    await user.type(within(dlg).getByLabelText('Expires (optional)'), '2027-06-30');
    const tokenInput = within(dlg).getByLabelText('Token');
    expect(tokenInput).toHaveAttribute('type', 'password');
    await user.type(tokenInput, SECRET);
    await user.click(within(dlg).getByRole('button', { name: 'Create credential' }));

    await within(table).findByText('qa-token', {}, T);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    const post = sent.find((s) => s.method === 'POST' && s.url.includes('/synthetic/credentials'))!;
    expect(JSON.parse(post.body)).toMatchObject({ name: 'qa-token', kind: 'bearer', bound_hosts: [{ pattern: '*.dev.wrw.com', kind: 'wildcard' }], secret: { source: 'stored', password: SECRET } });
    expect(JSON.parse(post.body).expires_at).toMatch(/^2027-06-(29|30)T/);
    // never in a URL, the page or a cache
    expect(sent.some((s) => s.url.includes(SECRET))).toBe(false);
    expect(document.body.innerHTML).not.toContain(SECRET);
    const caches = JSON.stringify([lastQueryClient!.getQueryCache().getAll().map((q) => [q.queryKey, q.state.data]), lastQueryClient!.getMutationCache().getAll().map((m) => [m.state.variables, m.state.data])]);
    expect(caches).not.toContain(SECRET);

    // editing shows the bound hosts and the expiry, never the secret: rotating starts from an empty field
    await user.click(within(rowOf(table, 'qa-token')).getByRole('button', { name: 'Edit credential qa-token' }));
    const edit = screen.getByRole('dialog', { name: 'Edit qa-token' });
    expect(within(edit).getByLabelText('Bound host 1')).toHaveValue('*.dev.wrw.com');
    expect(within(edit).getByLabelText('Expires (optional)')).toHaveValue('2027-06-30');
    expect(within(edit).getByLabelText('Type')).toBeDisabled();
    expect(within(edit).getByText(/The value is never shown again\./)).toBeInTheDocument();
    expect(within(edit).queryByLabelText('Token')).not.toBeInTheDocument();
    await user.click(within(edit).getByRole('checkbox', { name: 'Rotate the secret' }));
    expect(within(edit).getByLabelText('Token')).toHaveValue('');
    await user.click(within(edit).getByRole('checkbox', { name: 'Rotate the secret' }));
    // a save without rotation sends no secret
    await user.clear(within(edit).getByLabelText('Expires (optional)'));
    await user.click(within(edit).getByRole('button', { name: 'Save credential' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument(), T);
    const put = sent.find((s) => s.method === 'PUT')!;
    expect(JSON.parse(put.body)).not.toHaveProperty('secret');
    expect(JSON.parse(put.body).expires_at).toBeNull();
    await waitFor(() => expect(within(rowOf(table, 'qa-token')).getByText('never')).toBeInTheDocument(), T);
  });

  it('shows field errors from the API: a bound host outside the allowlist, an OAuth2 token URL outside the bound hosts', async () => {
    const user = userEvent.setup();
    await renderApp('/settings/synthetic');
    await user.click(await screen.findByRole('button', { name: 'New credential' }, T));
    const dlg = screen.getByRole('dialog', { name: 'New credential' });
    await user.type(within(dlg).getByLabelText('Name'), 'other-oauth');
    await user.selectOptions(within(dlg).getByLabelText('Type'), 'oauth2_client_credentials');
    await user.type(within(dlg).getByLabelText('Bound host 1'), 'api.other.io');
    await user.click(within(dlg).getByRole('button', { name: 'Add host' }));
    await user.type(within(dlg).getByLabelText('Bound host 2'), 'partner-sftp.acme.net');
    await user.type(within(dlg).getByLabelText('Token URL'), 'https://login.acme.net/token');
    await user.type(within(dlg).getByLabelText('Client ID'), 'olympos');
    await user.type(within(dlg).getByLabelText('Client secret'), 'cs-123');
    await user.click(within(dlg).getByRole('button', { name: 'Create credential' }));
    expect(await within(dlg).findByText('api.other.io is not inside the allowlist: every host it matches must be allowed. Add a rule first.', {}, T)).toBeInTheDocument();
    expect(within(dlg).getByText("login.acme.net must be inside the credential's bound hosts: the client secret is sent to it")).toBeInTheDocument();
  });

  it('refuses to delete a credential a scenario uses, naming the scenarios', async () => {
    const user = userEvent.setup();
    await renderApp('/settings/synthetic');
    await user.click(await screen.findByRole('button', { name: 'Edit credential catalog-monitor' }, T));
    const dlg = screen.getByRole('dialog', { name: 'Edit catalog-monitor' });
    await user.click(within(dlg).getByRole('button', { name: 'Delete' }));
    await user.click(within(dlg).getByRole('button', { name: 'Delete credential' }));
    const err = await within(dlg).findByText('This credential is still used. Change these first:', {}, T);
    expect(err.parentElement).toHaveTextContent('Scenario: Checkout API flow');
    expect(syn.credentials.some((c) => c.name === 'catalog-monitor')).toBe(true);
  });
});

describe('Settings › Clusters & agents: the synthetic probe', () => {
  it('shows the probe state and version per cluster', async () => {
    await renderApp('/settings/clusters');
    const table = await screen.findByRole('table', { name: 'Clusters' }, T);
    await within(table).findByText('prod-aks-weu-01', {}, T);
    expect(within(table).getByRole('columnheader', { name: /Probe/ })).toBeInTheDocument();
    const cell = (name: string) => within(rowOf(table, name)).getAllByRole('cell')[6];
    expect(cell('prod-aks-weu-01')).toHaveTextContent('Installed0.3.0');
    expect(within(cell('prod-aks-weu-01')).getByText('Installed')).toHaveClass('badge', 'ok');
    expect(cell('aks-sea-apac')).toHaveTextContent('Not installed');
    expect(cell('onprem-ist-lab')).toHaveTextContent(/^Offline · 2 h0\.3\.0$/);
    expect(within(cell('onprem-ist-lab')).getByText(/Offline/)).toHaveClass('badge', 'crit');
  });

  it('installs the probe on a cluster without one: the command carries the install sets and a one-time token', async () => {
    const user = userEvent.setup();
    const c = db.byName('aks-sea-apac');
    await renderApp(`/settings/clusters?cluster=${c.id}`);
    const probe = await screen.findByLabelText('Synthetic probe', {}, T);
    expect(probe).toHaveTextContent('The synthetic probe is not installed on this cluster, so scenarios skip it.');
    expect(within(probe).queryByRole('button', { name: 'Revoke probe' })).not.toBeInTheDocument();
    await user.click(within(probe).getByRole('button', { name: 'Install probe' }));
    const dlg = screen.getByRole('dialog', { name: 'Install the synthetic probe on aks-sea-apac' });
    expect(dlg).toHaveTextContent('Upgrades the agent release with the probe enabled.');
    await user.click(within(dlg).getByRole('button', { name: 'Create install command' }));
    const cmd = await within(dlg).findByLabelText('Helm upgrade command', {}, T);
    expect(cmd.textContent).toMatch(/^helm upgrade olympos-agent \S+ -n olympos-system --reuse-values --set probe\.image\.repository=\S+ --set probe\.enabled=true --set probe\.bootstrapToken=olyb_\w+$/);
    expect(within(dlg).getByText(/^Token expires in (59|60) min · single use$/)).toBeInTheDocument();
    expect(within(dlg).getByText('Waiting for the probe to connect…')).toBeInTheDocument();
    expect(within(dlg).getByRole('button', { name: 'Copy command' })).toBeInTheDocument();
  });

  it('revokes a probe after a confirmation; a cluster without a probe has nothing to revoke (409)', async () => {
    const user = userEvent.setup();
    const c = db.byName('prod-aks-weu-01');
    await renderApp(`/settings/clusters?cluster=${c.id}`);
    const probe = await screen.findByLabelText('Synthetic probe', {}, T);
    expect(probe).toHaveTextContent('The synthetic probe is installed and connected (version 0.3.0).');
    expect(within(probe).queryByRole('button', { name: 'Install probe' })).not.toBeInTheDocument();
    await user.click(within(probe).getByRole('button', { name: 'Revoke probe' }));
    const dlg = screen.getByRole('dialog', { name: 'Revoke the probe of prod-aks-weu-01?' });
    expect(dlg).toHaveTextContent('The agent is not affected.');
    await user.click(within(dlg).getByRole('button', { name: 'Revoke probe' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument(), T);
    await waitFor(() => expect(screen.getByLabelText('Synthetic probe')).toHaveTextContent('The synthetic probe was revoked: its certificate is denied and scenarios skip this cluster.'), T);
    const table = screen.getByRole('table', { name: 'Clusters' });
    expect(within(rowOf(table, 'prod-aks-weu-01')).getAllByRole('cell')[6]).toHaveTextContent(/^Revoked$/);
    expect(within(screen.getByLabelText('Synthetic probe')).getByRole('button', { name: 'Install probe' })).toBeInTheDocument();

    const res = await match('DELETE', `/clusters/${db.byName('aks-sea-apac').id}/probe`)!.h({ method: 'DELETE', path: '', query: new URLSearchParams(), body: undefined }, { id: db.byName('aks-sea-apac').id });
    expect(res).toEqual({ status: 409, body: { error: 'no probe installed' } });
  });

  it('shows the probe to people who cannot change cluster settings', async () => {
    localStorage.setItem('olympos.mock.role', 'viewer');
    await renderApp(`/settings/clusters?cluster=${db.byName('aks-sea-apac').id}`);
    const term = await screen.findByText('Synthetic probe', { selector: 'dt' }, T);
    expect(term.nextElementSibling).toHaveTextContent('Not installed');
    expect(screen.queryByRole('button', { name: 'Install probe' })).not.toBeInTheDocument();
  });
});

describe('Add cluster and Access', () => {
  it('says the probe is installed with the agent', async () => {
    const user = userEvent.setup();
    await renderApp('/settings/clusters');
    await user.click(await screen.findByRole('button', { name: 'Add cluster' }, T));
    const dlg = screen.getByRole('dialog', { name: 'Connect a cluster to Olympos' });
    expect(dlg).toHaveTextContent('Installs the agent and the synthetic probe. Both dial out to Olympos; no inbound port is needed on the cluster.');
    await user.type(within(dlg).getByLabelText('Cluster name'), 'oke-fra-mes');
    await user.click(within(dlg).getByRole('button', { name: 'Create install command' }));
    await within(dlg).findByLabelText('Helm install command', {}, T);
    expect(dlg).toHaveTextContent('probe.enabled=true by default (synthetic monitoring).');
  });

  it('lists synthetic-editor among the roles guests cannot hold', async () => {
    const user = userEvent.setup();
    expect(guestRolesText(GUEST_FORBIDDEN_ROLES)).toBe('vault-approver, synthetic-editor and admin');
    await renderApp('/settings');
    expect(await screen.findByText(/vault-approver, synthetic-editor and admin cannot be given to guest \(#EXT#\) accounts/, {}, T)).toBeInTheDocument();
    await user.click(await screen.findByRole('button', { name: 'Grant access' }, T));
    const dlg = screen.getByRole('dialog', { name: 'Grant access to a person' });
    const role = within(dlg).getByRole('checkbox', { name: /synthetic-editor/ });
    expect(role.closest('label')).toHaveTextContent('synthetic-editor(not for guests)');
  });
});
