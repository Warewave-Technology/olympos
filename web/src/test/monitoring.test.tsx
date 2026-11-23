// Monitoring › Synthetic (docs/design/monitoring-*.html): the matrix, the scenario detail, the editor and the run
// dialog, against the mock API.
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ScenarioStep } from '../api/types';
import { toCurl } from '../lib/curl';
import * as syn from '../mocks/synthetic';
import { REASON_TEXT, reasonText, withCredentialNames } from '../ui/synthetic';
import { POLL_MARGIN_MS, shouldPoll } from '../pages/monitoring/RunDialog';
import { MONITORING_TABS } from '../pages/monitoring/tabs';
import { renderApp } from './renderApp';

afterEach(() => {
  cleanup();
  localStorage.removeItem('olympos.mock.role');
  localStorage.removeItem('olympos.mock.testRun');
});

const T = { timeout: 5000 };
const checkout = () => syn.scenarios.find((s) => s.name === 'Checkout API flow')!;
const detailOf = (scenario: string) => `/monitoring?scenario=${syn.scenarios.find((s) => s.name === scenario)!.id}`;

describe('Monitoring › Synthetic overview', () => {
  it('sits after Security in the sidebar and has a tab bar from MONITORING_TABS', async () => {
    await renderApp('/monitoring');
    const nav = await screen.findByRole('navigation', { name: 'Main' }, T);
    const labels = within(nav)
      .getAllByRole('link')
      .map((a) => a.textContent?.replace(/\d+.*$/, '').trim());
    expect(labels.indexOf('Monitoring')).toBe(labels.indexOf('Security') + 1);
    const tabs = await screen.findByRole('navigation', { name: 'Monitoring sections' }, T);
    expect(within(tabs).getAllByRole('link').map((a) => a.textContent)).toEqual(MONITORING_TABS.map((t) => t.label));
    expect(within(tabs).getByRole('link', { name: 'Synthetic' })).toHaveAttribute('aria-current', 'page');
  });

  it('shows every cell state as text and a symbol, the KPIs, and filters with the pills', async () => {
    const user = userEvent.setup();
    await renderApp('/monitoring');
    const matrix = await screen.findByRole('table', { name: 'Scenarios by cluster' }, T);
    const cell = (label: string) => within(matrix).getAllByLabelText(label)[0];
    // text (the label and the tooltip) and a symbol, never colour only
    const cases: [string, string, string][] = [
      ['prod-aks-weu-01 passing', '✓', 'c-ok'],
      ['oke-fra-erp failing', '✕', 'c-fail'],
      ['onprem-factory-01 degraded', '!', 'c-warn'],
      ['onprem-ist-lab probe offline', '·', 'c-off'],
      ['aks-sea-apac probe not installed', '∅', 'c-off'],
      ['onprem-ist-lab excluded', '–', 'c-ex'],
      ['onprem-factory-01 paused', '‖', 'c-ex'],
    ];
    for (const [label, symbol, cls] of cases) {
      const c = cell(label);
      expect(c).toHaveTextContent(symbol);
      expect(c).toHaveClass(cls);
      expect(c.getAttribute('title')).toContain(label.replace(/^(\S+) /, '$1 · '));
    }
    expect(cell('oke-fra-erp failing').getAttribute('title')).toContain('step 3: latency 912 ms > 500 ms');
    // the legend says what each symbol means
    const legend = screen.getByLabelText('Legend');
    for (const t of ['passing', 'failing', 'degraded', 'probe offline', 'probe not installed', 'excluded', 'paused']) expect(legend).toHaveTextContent(t);

    const kpis = screen.getByRole('region', { name: 'Synthetic monitoring totals' });
    expect(within(kpis).getByText('Failing now').parentElement).toHaveTextContent('Checkout API flow · 1 cluster');
    expect(within(kpis).getByText('Probes').parentElement).toHaveTextContent('10 / 12');
    expect(within(kpis).getByText('Probes').parentElement).toHaveTextContent('onprem-ist-lab probe offline');

    const rows = () => within(matrix).getAllByRole('row').slice(1);
    expect(rows()).toHaveLength(7);
    await user.click(screen.getByRole('button', { name: /^Failing · 1$/ }));
    expect(rows().map((r) => within(r).getByRole('link').textContent)).toEqual(['Checkout API flow']);
    expect(within(rows()[0]).getByText('Failing · 1 cluster')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /^Paused · 1$/ }));
    expect(rows().map((r) => within(r).getByRole('link').textContent)).toEqual(['Legacy reports portal']);
    await user.click(screen.getByRole('button', { name: /^All · 7$/ }));
    await user.type(screen.getByLabelText('Search scenarios'), 'payments');
    await waitFor(() => expect(rows().map((r) => within(r).getByRole('link').textContent)).toEqual(['Checkout API flow', 'Payments gateway TLS']));
  });

  it('opens the last run of a cell', async () => {
    const user = userEvent.setup();
    await renderApp('/monitoring');
    const matrix = await screen.findByRole('table', { name: 'Scenarios by cluster' }, T);
    await user.click(within(matrix).getAllByRole('button', { name: 'oke-fra-erp failing' })[0]);
    const dlg = await screen.findByRole('dialog', { name: 'Failed at step 3 · latency' }, T);
    await user.click(within(dlg).getByRole('button', { name: 'Back to scenario' }));
    await screen.findByRole('heading', { name: 'Steps' }, T);
    expect(screen.queryByRole('dialog')).toBeNull();
  });
});

describe('scenario detail', () => {
  it('lists the steps with the failed one marked, the clusters, the alert rule and the alert history', async () => {
    await renderApp(detailOf('Checkout API flow'));
    await screen.findByRole('heading', { name: /Checkout API flow/ }, T);
    // the status comes from the overview, which may load after the scenario
    expect(await screen.findByText('Failing in 1 of 11 clusters', {}, T)).toBeInTheDocument();
    const steps = screen.getByRole('region', { name: 'Steps' });
    const cards = within(steps).getAllByRole('listitem');
    expect(cards.map((c) => c.querySelector('b')?.textContent)).toEqual(['DNS resolve', 'GET /healthz', 'GET /v1/catalog?limit=1', 'GET /v1/items/${item}']);
    expect(cards[2]).toHaveTextContent('extract $.items[0].id → item');
    expect(cards[2]).toHaveTextContent('status = 200 · latency < 500 ms · $.items length > 0');
    expect(cards[3]).toHaveTextContent('uses value from step 3');
    await waitFor(() => expect(cards[2]).toHaveTextContent('Last run failed here on oke-fra-erp'));
    expect(cards[2]).toHaveClass('failed');

    const table = await screen.findByRole('table', { name: 'Scenario by cluster' }, T);
    const erp = within(table).getByText('oke-fra-erp').closest('tr')!;
    expect(within(erp).getByRole('button', { name: /Failed · 3rd in a row/ })).toBeInTheDocument();
    expect(erp).toHaveTextContent('3 · latency 912 ms > 500 ms');
    expect(erp).toHaveTextContent('96.4 %');
    expect(within(erp).getByRole('img', { name: /Last 24 hours, 30 minute buckets: \d+ passed, \d+ with failures/ })).toBeInTheDocument();
    expect(within(table).getByText('onprem-ist-lab').closest('tr')).toHaveTextContent('Excluded');
    expect(within(table).getByText('aks-sea-apac').closest('tr')).toHaveTextContent('Probe not installed');

    const rule = screen.getByRole('region', { name: 'Alert rule' });
    expect(rule).toHaveTextContent('3 failed runs in a row in a cluster');
    expect(rule).toHaveTextContent('#payments-alerts · #platform-oncall (critical)');
    expect(rule).toHaveTextContent('Yes, after 2 passing runs');
    const history = await screen.findByRole('list', { name: 'Alert history' }, T);
    const alerts = within(history).getAllByRole('listitem');
    expect(alerts[0]).toHaveTextContent('Firing');
    expect(alerts[0]).toHaveTextContent('oke-fra-erp · step 3 latency 912 ms > 500 ms');
    expect(alerts[1]).toHaveTextContent('Resolved');
    expect(alerts[1]).toHaveTextContent('onprem-factory-01 · step 2 Could not connect: connect timeout · 34 m');
  });

  it('shows "hidden" to a viewer for a step that uses a credential, and no edit controls', async () => {
    localStorage.setItem('olympos.mock.role', 'viewer');
    await renderApp(detailOf('Checkout API flow'));
    const steps = await screen.findByRole('region', { name: 'Steps' }, T);
    const cards = within(steps).getAllByRole('listitem');
    expect(cards[2]).toHaveTextContent('Headers and body: hidden');
    expect(cards[1]).not.toHaveTextContent('hidden');
    expect(screen.queryByRole('link', { name: 'Edit' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Run now' })).toBeNull();
  });
});

describe('run dialog', () => {
  it('shows the waterfall, the assertions and the redacted excerpt, and copies curl without the secret', async () => {
    const user = userEvent.setup();
    await renderApp(detailOf('Checkout API flow'));
    const table = await screen.findByRole('table', { name: 'Scenario by cluster' }, T);
    await user.click(within(table).getByRole('button', { name: /Failed · 3rd in a row/ }));
    const dlg = await screen.findByRole('dialog', { name: 'Failed at step 3 · latency' }, T);
    expect(dlg).toHaveTextContent('3rd failed run in a row · alert sent to #payments-alerts · probe egress 10.40.2.17');
    const wf = within(dlg).getByRole('list', { name: 'Steps' });
    const rows = within(wf).getAllByRole('button');
    expect(rows.map((r) => r.querySelector('.wf-name')?.textContent)).toEqual(['1 DNS resolve', '2 GET /healthz', '3 GET /v1/catalog?limit=1 (failed)', '4 GET /v1/items/${item}']);
    expect(rows[2]).toHaveAttribute('aria-pressed', 'true');
    expect(rows[2]).toHaveTextContent('912 ms');
    expect(rows[3]).toHaveTextContent('skipped');
    expect(within(rows[2]).getByRole('img').getAttribute('aria-label')).toMatch(/^DNS [\d.]+ ms, connect [\d.]+ ms, TLS [\d.]+ ms, waiting \(TTFB\) [\d.]+ ms, download [\d.]+ ms$/);

    const asserts = within(dlg).getByRole('list', { name: 'Step 3 assertions' });
    const items = within(asserts).getAllByRole('listitem');
    expect(items[0]).toHaveTextContent('Status code equals 200');
    expect(within(items[0]).getByLabelText('Passed')).toBeInTheDocument();
    expect(items[1]).toHaveTextContent('Latency less than 500 ms912 ms');
    expect(within(items[1]).getByLabelText('Failed')).toBeInTheDocument();
    expect(items[2]).toHaveTextContent('$.items length greater than 0');
    expect(within(dlg).getByLabelText('Response excerpt')).toHaveTextContent('set-cookie: [redacted]');

    await user.click(within(dlg).getByRole('button', { name: 'Copy as curl' }));
    const curl = await navigator.clipboard.readText();
    expect(curl).toBe(`curl 'https://api.prod.wrw.com/v1/catalog?limit=1' -H 'Accept: application/json' -H 'Authorization: Bearer '"$TOKEN"`);
    expect(within(dlg).getByRole('button', { name: 'Run again on oke-fra-erp' })).toBeInTheDocument();

    // another step: its own assertions
    await user.click(rows[1]);
    expect(within(dlg).getByRole('list', { name: 'Step 2 assertions' })).toHaveTextContent('Latency less than 300 ms');
  });

  it('shows "hidden" to a viewer and offers no curl for a credentialed step', async () => {
    localStorage.setItem('olympos.mock.role', 'viewer');
    const user = userEvent.setup();
    await renderApp(detailOf('Checkout API flow'));
    const table = await screen.findByRole('table', { name: 'Scenario by cluster' }, T);
    await user.click(within(table).getByRole('button', { name: /Failed · 3rd in a row/ }));
    const dlg = await screen.findByRole('dialog', { name: 'Failed at step 3 · latency' }, T);
    expect(dlg).toHaveTextContent('Headers and body: hidden');
    expect(within(dlg).queryByRole('button', { name: 'Copy as curl' })).toBeNull();
    expect(dlg).toHaveTextContent('Copy as curl: hidden');
    expect(within(dlg).queryByRole('button', { name: /Run again/ })).toBeNull();
    // a step without a credential still copies
    await user.click(within(within(dlg).getByRole('list', { name: 'Steps' })).getAllByRole('button')[1]);
    expect(within(dlg).getByRole('button', { name: 'Copy as curl' })).toBeInTheDocument();
  });
});

describe('scenario editor', () => {
  async function openEditor(user: ReturnType<typeof userEvent.setup>, path = `/monitoring/editor?scenario=${checkout().id}&cluster=oke-fra-erp`) {
    await renderApp(path);
    await screen.findByRole('heading', { name: /Edit scenario|New scenario/ }, T);
    return user;
  }

  it('shows where it runs live, with the names, and follows the exclusions', async () => {
    const user = await openEditor(userEvent.setup());
    const line = await screen.findByLabelText('Where the scenario runs');
    await waitFor(() => expect(line).toHaveTextContent('Runs on 11 of 12 clusters: aks-neu-dr, aks-sea-apac'), T);
    expect(line).toHaveTextContent('Excluded: onprem-ist-lab');
    await user.type(screen.getByLabelText('Exclude'), 'env=staging{Enter}');
    await waitFor(() => expect(line).toHaveTextContent('Runs on 10 of 12 clusters'), T);
    expect(line.textContent).not.toMatch(/clusters:.*aks-weu-staging.*Excluded/);
    expect(line).toHaveTextContent('Excluded: aks-weu-staging, onprem-ist-lab');
    // a bare cluster name becomes the reserved cluster label
    await user.type(screen.getByLabelText('Exclude'), 'oke-fra-erp{Enter}');
    expect(await screen.findByText('olympos.io/cluster=oke-fra-erp')).toBeInTheDocument();
    await waitFor(() => expect(line).toHaveTextContent('Runs on 9 of 12 clusters'), T);
    await user.click(screen.getByRole('radio', { name: /Clusters matching labels/ }));
    await user.type(screen.getByLabelText('Cluster labels'), 'site=factory');
    await waitFor(() => expect(line).toHaveTextContent('Runs on 1 of 12 clusters: onprem-factory-01'), T);
  });

  it('hints the allowlist per URL: the admin gets the settings link, others are told to ask an admin', async () => {
    const user = await openEditor(userEvent.setup());
    await user.click(screen.getByRole('button', { name: 'Edit step 3' }));
    expect(await screen.findByText('*.prod.wrw.com', {}, T)).toBeInTheDocument();
    expect(screen.getByText(/Host allowed by/)).toBeInTheDocument();
    const url = screen.getByLabelText('Step 3 URL');
    await user.clear(url);
    await user.type(url, 'https://api.other.io/v1');
    const hint = await screen.findByText('No rule matches api.other.io.', {}, T);
    expect(hint.parentElement).toHaveTextContent('Add a rule in Settings › Synthetic monitoring.');
    expect(within(hint.parentElement!).getByRole('link', { name: 'Settings › Synthetic monitoring' })).toHaveAttribute('href', '/settings/synthetic');

    // saving it: the API's message, with the link for an admin
    await user.click(screen.getByRole('button', { name: 'Save scenario' }));
    const err = await screen.findByText(/Host api\.other\.io is not allowed\. Add a rule in/, {}, T);
    expect(within(err).getByRole('link', { name: 'Settings › Synthetic monitoring' })).toBeInTheDocument();
    // in-cluster names are absolute
    await user.clear(url);
    await user.type(url, 'https://billing.payments.svc/x');
    expect(await screen.findByText(/write in-cluster services in full, svc\.ns\.svc\.cluster\.local/, {}, T)).toBeInTheDocument();
  });

  it('tells a synthetic-editor to ask an admin', async () => {
    localStorage.setItem('olympos.mock.role', 'editor');
    const user = await openEditor(userEvent.setup());
    await user.click(screen.getByRole('button', { name: 'Edit step 3' }));
    const url = screen.getByLabelText('Step 3 URL');
    await user.clear(url);
    await user.type(url, 'https://api.other.io/v1');
    const hint = await screen.findByText('No rule matches api.other.io.', {}, T);
    expect(hint.parentElement).toHaveTextContent('Ask an admin to add it to the synthetic allowlist.');
    expect(within(hint.parentElement!).queryByRole('link')).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Save scenario' }));
    expect(await screen.findByText('Host api.other.io is not allowed. Ask an admin to add it to the synthetic allowlist.', {}, T)).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Settings › Synthetic monitoring' })).toBeNull();
  });

  it('shows the request cap error on Every', async () => {
    // a flow that follows redirects with two retries: 5 × 3 × 6 = 90 requests a run
    const s = syn.scenarios[0];
    const heavy = { ...s, id: 'aaaaaaaa-0000-4000-8000-000000000001', name: 'Redirect chain', step_retries: 2, steps: Array.from({ length: 5 }, (_, i) => ({ kind: 'http' as const, position: i, http: { method: 'GET' as const, url: `https://api.prod.wrw.com/r${i}`, headers: {}, body: '', body_type: 'text' as const, follow_redirects: true }, assertions: [], extracts: [] })) };
    syn.scenarios.push(heavy);
    try {
      const user = await openEditor(userEvent.setup(), `/monitoring/editor?scenario=${heavy.id}`);
      await user.click(screen.getByRole('button', { name: '30 s' }));
      expect(await screen.findByText(/Up to 180 requests per minute on each cluster; the cap is 120/, {}, T)).toBeInTheDocument();
      await user.click(screen.getByRole('button', { name: 'Save scenario' }));
      expect(
        await screen.findByText('The scenario makes up to 180.0 requests per minute on each cluster; the cap is 120. Run it less often, retry less or follow fewer redirects.', {}, T),
      ).toBeInTheDocument();
    } finally {
      syn.scenarios.splice(syn.scenarios.indexOf(heavy), 1);
    }
  });

  it('runs a test on one cluster and says test runs never alert', async () => {
    const user = await openEditor(userEvent.setup());
    const panel = screen.getByRole('region', { name: 'Test run' });
    expect(panel).toHaveTextContent('Test runs never send alerts.');
    // ?cluster= picks the test-run cluster
    await waitFor(() => expect((within(panel).getByLabelText('Cluster for test run') as HTMLSelectElement).selectedOptions[0]?.textContent).toBe('oke-fra-erp'), T);
    // an offline probe cannot be picked
    expect(within(panel).getByRole('option', { name: 'onprem-ist-lab · probe offline' })).toBeDisabled();
    await user.click(within(panel).getByRole('button', { name: 'Run once' }));
    const result = await within(panel).findByLabelText('Test run result');
    await waitFor(() => expect(result).toHaveTextContent('3 GET /v1/catalog?limit=1 · 200 · 912 ms > 500 ms'), { timeout: 6000 });
    expect(result).toHaveTextContent('1 DNS resolve · 3 ms');
    expect(result).toHaveTextContent('2 GET /healthz · 200');
    expect(result).toHaveTextContent('4 GET /v1/items/${item} · skipped');
    await user.click(within(panel).getByRole('button', { name: 'Open the run details' }));
    const dlg = await screen.findByRole('dialog', { name: 'Failed at step 3 · latency' }, T);
    expect(dlg).toHaveTextContent('Test run by yigit@contoso.com · test runs never send alerts');
  });

  it('saves a new single-step scenario and opens it', async () => {
    const user = await openEditor(userEvent.setup(), '/monitoring/editor');
    await user.type(screen.getByLabelText('Name'), 'Status page');
    await user.click(screen.getByRole('button', { name: 'TCP' }));
    await user.type(screen.getByLabelText('Step 1 host'), 'partner-sftp.acme.net');
    const port = screen.getByLabelText('Step 1 port');
    await user.clear(port);
    await user.type(port, '22');
    await user.click(screen.getByRole('button', { name: 'Save scenario' }));
    await screen.findByRole('heading', { name: /Status page/ }, T);
    const saved = syn.scenarios.find((s) => s.name === 'Status page')!;
    expect(saved.type).toBe('tcp');
    expect(saved.steps).toHaveLength(1);
    expect(saved.steps[0].tcp).toEqual({ host: 'partner-sftp.acme.net', port: 22 });
    syn.scenarios.splice(syn.scenarios.indexOf(saved), 1);
  });

  it('is not open to a viewer', async () => {
    localStorage.setItem('olympos.mock.role', 'viewer');
    await renderApp('/monitoring/editor');
    expect(await screen.findByText(/You do not have access to the scenario editor/, {}, T)).toBeInTheDocument();
  });
});

describe('scenario editor, fix round 1', () => {
  async function editCheckout(path = `/monitoring/editor?scenario=${checkout().id}&cluster=oke-fra-erp`) {
    const user = userEvent.setup();
    await renderApp(path);
    await screen.findByRole('heading', { name: /Edit scenario|New scenario/ }, T);
    return user;
  }
  const setUrl = async (user: ReturnType<typeof userEvent.setup>, n: number, url: string) => {
    const el = screen.getByLabelText(`Step ${n} URL`);
    await user.clear(el);
    await user.type(el, url.replace(/[{[]/g, '$&$&'));
  };

  it('shows a test run 422 on the fields and in the test-run panel', async () => {
    const user = await editCheckout();
    await user.click(screen.getByRole('button', { name: 'Edit step 3' }));
    await setUrl(user, 3, 'https://api.other.io/v1');
    const panel = screen.getByRole('region', { name: 'Test run' });
    await waitFor(() => expect(within(panel).getByRole('button', { name: 'Run once' })).toBeEnabled(), T);
    await user.click(within(panel).getByRole('button', { name: 'Run once' }));
    const note = await within(panel).findByText('Not run: the draft has errors.', {}, T);
    expect(note.closest('[role=alert]')).toHaveTextContent('Step 3 url: Host api.other.io is not allowed. Add a rule in Settings › Synthetic monitoring.');
    // and on the field itself
    await waitFor(() => expect(screen.getByLabelText('Step 3 URL')).toHaveAttribute('aria-invalid', 'true'));
    expect(screen.getAllByText(/Host api\.other\.io is not allowed/).length).toBeGreaterThanOrEqual(2);
    // the save summary stays empty: this was the test run
    expect(screen.queryByText(/Could not save|invalid scenario/i)).toBeNull();
  });

  it('says why a test run was not run on 409 and 429', async () => {
    const user = await editCheckout();
    const panel = screen.getByRole('region', { name: 'Test run' });
    await waitFor(() => expect(within(panel).getByRole('button', { name: 'Run once' })).toBeEnabled(), T);
    localStorage.setItem('olympos.mock.testRun', '409');
    await user.click(within(panel).getByRole('button', { name: 'Run once' }));
    expect(await within(panel).findByText("Not run: The cluster's probe is not online: oke-fra-erp is offline. Pick a cluster whose probe is online.", {}, T)).toBeInTheDocument();
    localStorage.setItem('olympos.mock.testRun', '429');
    await user.click(within(panel).getByRole('button', { name: 'Run once' }));
    expect(await within(panel).findByText('Not run: At most 6 test runs a minute; wait a moment.', {}, T)).toBeInTheDocument();
    expect(panel).toHaveTextContent('Test runs never send alerts.');
  });

  it('shows the taint rule on the URL, the header row and the body, naming the credential', async () => {
    const user = await editCheckout();
    await user.click(screen.getByRole('button', { name: 'Edit step 4' }));
    // ${item} comes from step 3 (catalog-monitor, bound to *.prod.wrw.com); send it to search.wrw.com
    await setUrl(user, 4, 'https://search.wrw.com/items/${item}');
    await user.selectOptions(screen.getByLabelText('Step 4 method'), 'POST');
    await user.click(screen.getByRole('button', { name: '+ Add header' }));
    const rows = screen.getAllByLabelText(/^Step 4 header \d+ name$/);
    await user.type(rows[rows.length - 1], 'X-Item');
    await user.type(screen.getAllByLabelText(/^Step 4 header \d+ value$/).at(-1)!, '$' + '{{item}');
    const body = screen.getByLabelText('Body');
    await user.type(body, '{{"id":"$' + '{{item}"}');
    // the step's own credential is bound to *.prod.wrw.com: take it off
    await user.selectOptions(screen.getAllByLabelText('Auth').at(-1)!, '');
    await user.click(screen.getByRole('button', { name: 'Save scenario' }));
    const msg = "comes from a step that uses credential catalog-monitor, so it may only be sent to that credential's bound hosts";
    await waitFor(() => expect(screen.getByLabelText('Step 4 URL')).toHaveAttribute('aria-invalid', 'true'), T);
    const value = screen.getAllByLabelText(/^Step 4 header \d+ value$/).at(-1)!;
    expect(value).toHaveAttribute('aria-invalid', 'true');
    expect(document.getElementById(value.getAttribute('aria-describedby')!)).toHaveTextContent('${item} ' + msg);
    expect(body).toHaveAttribute('aria-invalid', 'true');
    expect(document.getElementById(body.getAttribute('aria-describedby')!)).toHaveTextContent('${item} ' + msg);
    expect(screen.getByText(/Check the highlighted fields/)).toBeInTheDocument();
    // the mock follows spec.ValidateTaint: on a bound host the same variable is fine
    await setUrl(user, 4, 'https://api.prod.wrw.com/v1/items/${item}');
    expect(screen.getByLabelText('Step 4 URL')).not.toHaveAttribute('aria-invalid');
  });

  it('keeps an error on its step when the steps are reordered', async () => {
    const user = await editCheckout();
    await user.click(screen.getByRole('button', { name: 'Edit step 3' }));
    await setUrl(user, 3, 'https://api.other.io/v1');
    await user.click(screen.getByRole('button', { name: 'Save scenario' }));
    await waitFor(() => expect(screen.getByLabelText('Step 3 URL')).toHaveAttribute('aria-invalid', 'true'), T);
    await user.click(screen.getByRole('button', { name: 'Move step 3 up' }));
    expect(screen.getByLabelText('Step 2 URL')).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByLabelText('Step 2 URL')).toHaveValue('https://api.other.io/v1');
    expect(screen.getByRole('button', { name: 'Edit step 3' }).closest('li')).not.toHaveClass('failed');
  });

  it('sends a scenario back with its headers and credential, and leaves enabled out unless changed', async () => {
    const user = await editCheckout();
    await user.click(screen.getByRole('button', { name: 'Save scenario' }));
    await screen.findByRole('heading', { name: 'Alert rule' }, T);
    const body = syn.lastPut.body as Record<string, unknown> & { steps: ScenarioStep[] };
    expect('enabled' in body).toBe(false);
    expect('store_responses' in body).toBe(false);
    const s = checkout();
    expect(s.steps[2].http?.headers).toEqual({ Accept: 'application/json' });
    expect(s.steps[2].credential_id).toBe(syn.credentials[0].id);
    expect(s.steps[3].credential?.name).toBe('catalog-monitor');
  });

  it('turns response excerpts off, and says what that means', async () => {
    const user = await editCheckout();
    const box = screen.getByRole('checkbox', { name: 'Store response excerpts' });
    expect(box).toBeChecked();
    await user.click(box);
    expect(screen.getByText(/Off: no response excerpts or response text are kept for this scenario\. A privacy control/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save scenario' }));
    await screen.findByRole('heading', { name: 'Alert rule' }, T);
    expect((syn.lastPut.body as { store_responses?: boolean }).store_responses).toBe(false);
    expect(checkout().store_responses).toBe(false);
    checkout().store_responses = true;
  });

  it('warns and refuses a save over the per-cluster cap', async () => {
    const user = await editCheckout();
    await user.click(screen.getByRole('button', { name: '30 s' }));
    expect(await screen.findByText('Over the cap of 600 requests per minute per cluster on eks-fra-data (608/min).', {}, T)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save scenario' }));
    expect(await screen.findByText('Over the cap of 600 requests per minute per cluster on eks-fra-data (608/min). Run it less often, retry less, or pause other scenarios there.', {}, T)).toBeInTheDocument();
  });

  it('tells a scoped synthetic-editor what scope all clusters needs', async () => {
    localStorage.setItem('olympos.mock.role', 'scoped');
    // a scenario on all clusters is not theirs to edit
    await renderApp(`/monitoring/editor?scenario=${checkout().id}`);
    expect(await screen.findByText(/You cannot edit this scenario: it runs on clusters outside your synthetic-editor scope/, {}, T)).toBeInTheDocument();
    cleanup();
    const user = await editCheckout('/monitoring/editor');
    expect(screen.getByRole('radio', { name: /All clusters/ }).closest('label')).toHaveTextContent('Needs the synthetic-editor role with scope all');
    await user.type(screen.getByLabelText('Name'), 'Staging health');
    await setUrl(user, 1, 'https://api.prod.wrw.com/healthz');
    await user.click(screen.getByRole('button', { name: 'Save scenario' }));
    expect(await screen.findByText('A scenario that runs on all clusters needs the synthetic-editor role with scope all. Choose clusters matching labels in your scope.', {}, T)).toBeInTheDocument();
    await user.click(screen.getByRole('radio', { name: /Clusters matching labels/ }));
    await user.type(screen.getByLabelText('Cluster labels'), 'env=staging');
    await user.click(screen.getByRole('button', { name: 'Save scenario' }));
    await screen.findByRole('heading', { name: /Staging health/ }, T);
    syn.scenarios.splice(syn.scenarios.findIndex((s) => s.name === 'Staging health'), 1);
  });

  it('shows an error where the credentials could not be loaded', async () => {
    localStorage.setItem('olympos.mock.credentials', 'fail');
    try {
      const user = await editCheckout();
      await user.click(screen.getByRole('button', { name: 'Edit step 3' }));
      expect(await screen.findByText(/Could not load the credentials/, {}, T)).toBeInTheDocument();
    } finally {
      localStorage.removeItem('olympos.mock.credentials');
    }
  });
});

describe('delete scenario', () => {
  it('asks for the name, says what goes with it, and deletes', async () => {
    const extra = { ...checkout(), id: 'aaaaaaaa-0000-4000-8000-000000000002', name: 'Old probe check' };
    syn.scenarios.push(extra);
    const user = userEvent.setup();
    await renderApp(detailOf('Old probe check'));
    await user.click(await screen.findByRole('button', { name: 'Delete' }, T));
    const dlg = screen.getByRole('dialog', { name: 'Delete Old probe check?' });
    expect(dlg).toHaveTextContent('Its runs and its alert history are deleted with it; this cannot be undone.');
    const go = within(dlg).getByRole('button', { name: 'Delete scenario' });
    expect(go).toBeDisabled();
    await user.type(within(dlg).getByLabelText(/Type Old probe check to confirm/), 'Old probe chec');
    expect(go).toBeDisabled();
    await user.type(within(dlg).getByLabelText(/Type Old probe check to confirm/), 'k');
    await user.click(go);
    await screen.findByRole('table', { name: 'Scenarios by cluster' }, T);
    expect(syn.scenarios.some((s) => s.id === extra.id)).toBe(false);
    await waitFor(() => expect(screen.queryByRole('link', { name: 'Old probe check' })).toBeNull(), T);
  });

  it('is not offered to a viewer', async () => {
    localStorage.setItem('olympos.mock.role', 'viewer');
    await renderApp(detailOf('Checkout API flow'));
    await screen.findByRole('region', { name: 'Steps' }, T);
    expect(screen.queryByRole('button', { name: 'Delete' })).toBeNull();
  });
});

describe('toCurl', () => {
  const step = (p: Partial<ScenarioStep> = {}, headers: Record<string, string> | null = { Accept: 'application/json' }): ScenarioStep => ({
    kind: 'http',
    http: { method: 'GET', url: 'https://api.prod.wrw.com/v1/items/${item}', headers, body: '', body_type: 'text', follow_redirects: false },
    assertions: [],
    extracts: [],
    ...p,
  });
  it('puts $TOKEN, $USERNAME and $PASSWORD where the credential goes', () => {
    const ref = (kind: string, header_name = '') => ({ id: 'c', name: 'n', kind, header_name });
    expect(toCurl(step({ credential: ref('bearer') }))).toBe(`curl 'https://api.prod.wrw.com/v1/items/\${item}' -H 'Accept: application/json' -H 'Authorization: Bearer '"$TOKEN"`);
    expect(toCurl(step(), ref('oauth2_client_credentials'))).toContain(`-H 'Authorization: Bearer '"$TOKEN"`);
    expect(toCurl(step(), ref('header', 'X-Api-Key'))).toContain(`-H 'X-Api-Key: '"$TOKEN"`);
    // the header name is single-quoted: a backtick or $ in it never runs or expands; only $TOKEN does
    expect(toCurl(step({}, {}), ref('header', 'X-`id`$HOME'))).toBe(`curl 'https://api.prod.wrw.com/v1/items/\${item}' -H 'X-\`id\`$HOME: '"$TOKEN"`);
    expect(toCurl(step({}, {}), ref('header', "X-it's"))).toContain(`-H 'X-it'\\''s: '"$TOKEN"`);
    expect(toCurl(step(), ref('basic'))).toContain(`-u "$USERNAME:$PASSWORD"`);
    // a header of the same name in the step never wins over the variable
    const c = toCurl(step({}, { authorization: 'Bearer literal' }), ref('bearer'));
    expect(c).not.toContain('literal');
    expect(c).toContain('$TOKEN');
  });
  it('quotes for the shell, sends the method and body, follows redirects, and skips hidden headers', () => {
    const post = step({ http: { method: 'POST', url: "https://x.wrw.com/q?a=1&b='2'", headers: { 'X-Trace': "it's" }, body: '{"q":1}', body_type: 'json', follow_redirects: true } });
    expect(toCurl(post)).toBe(`curl -X POST -L --max-redirs 5 'https://x.wrw.com/q?a=1&b='\\''2'\\''' -H 'X-Trace: it'\\''s' -H 'Content-Type: application/json' --data-raw '{"q":1}'`);
    expect(toCurl(step({ http: { method: 'HEAD', url: 'https://x.wrw.com/', headers: null, body: null } }))).toBe(`curl --head 'https://x.wrw.com/'`);
    expect(toCurl({ kind: 'dns', dns: { name: 'x', record_type: 'A' }, assertions: [], extracts: [] })).toBe('');
  });
});

describe('helpers', () => {
  it('names credentials by name in a message that holds their id', () => {
    const id = syn.credentials[0].id;
    expect(withCredentialNames(`\${item} comes from a step that uses credential ${id}, so …`, syn.credentials)).toBe('${item} comes from a step that uses credential catalog-monitor, so …');
    expect(withCredentialNames('credential 00000000-0000-4000-8000-000000000000', syn.credentials)).toBe('credential 00000000-0000-4000-8000-000000000000');
  });
  it('stops polling a run at its deadline', () => {
    const running = { status: 'running' } as Parameters<typeof shouldPoll>[0];
    expect(shouldPoll(running, 1000, 2000)).toBe(true);
    expect(shouldPoll(running, 2000, 2000)).toBe(false);
    expect(shouldPoll({ status: 'passed' } as Parameters<typeof shouldPoll>[0], 0, 2000)).toBe(false);
    expect(shouldPoll(running, 1e12)).toBe(true);
    expect(POLL_MARGIN_MS).toBeGreaterThan(0);
  });
});

describe('codes', () => {
  it('reads as text', () => {
    expect(reasonText('assertion_failed: latency 912 ms > 500 ms')).toBe('latency 912 ms > 500 ms');
    expect(reasonText('connect_error: connect timeout')).toBe('Could not connect: connect timeout');
    expect(reasonText('credential_unavailable')).toBe('The credential could not be read');
    expect(reasonText('rate_limit')).toBe('Held back by a request cap');
    expect(reasonText('something_new: x')).toBe('something_new: x');
  });
  it('covers every failure, skip, error and blocked code of the API', () => {
    const codes = [
      ...['host_not_allowed', 'ip_denied', 'redirect_blocked', 'dns_error', 'connect_error', 'tls_error', 'timeout', 'assertion_failed', 'invalid_request', 'credential_error', 'runner_panic'],
      ...['probe_offline', 'probe_disconnected', 'scenario_disabled', 'credential_unavailable', 'not_dispatched', 'probe_busy', 'allowlist_stale', 'credentials_unreadable', 'invalid_scenario', 'rejected'],
      ...['credential_expired', 'credential_error', 'dispatch_error', 'no_result', 'invalid_result'],
      'rate_limit',
      'no_longer_monitored',
    ];
    for (const c of codes) expect(REASON_TEXT[c], c).toBeTruthy();
  });
});
