// Docs tour: walks through Olympos in the kind lab the way a new user would
// and saves a screenshot at every step, for README.md, docs/getting-started.md and the feature docs.
// The tour is also a check: if a step no longer works, the tour fails.
//
//   ./test/e2e/env.sh                     # fresh lab, Olympos reset to empty
//   cd web && pnpm docs-tour              # writes ../docs/images/*.png
//
// Needs Google Chrome (or CHROME=/path/to/chrome) and the lab kubeconfig
// (test/e2e/.work/kubeconfig-env). Lab values only: nothing here is a real
// credential, and tokens are masked in the images.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const URL = process.env.OLYMPOS_URL ?? 'http://127.0.0.1:28080';
const OUT = process.env.OUT ?? join(ROOT, 'docs', 'images');
const KUBECONFIG = join(ROOT, 'test', 'e2e', '.work', 'kubeconfig-env');
const ONLY = process.env.STAGES?.split(',');
const PEOPLE = {
  admin: { oid: '00000000-0000-0000-0000-00000000ad01', name: 'Lab Admin' },
  approver: { oid: '00000000-0000-0000-0000-0000000000a2', name: 'Ali Approver' },
};
const env = readFileSync(join(ROOT, 'test', 'e2e', '.work', 'ENV.md'), 'utf8');
const vaultToken = (name) => env.match(new RegExp(`${name} +\\([^)]+\\): +(\\S+)`))?.[1];
// The lab's native-ready ClickHouse (24.8 or later, trusting the Olympos CA) and its lab password.
const NATIVE_CH = process.env.NATIVE_CH ?? 'native-ch';
const NATIVE_CH_PASSWORD = 'CANARY-lab-native-ch-password';

mkdirSync(OUT, { recursive: true });
const browser = await chromium.launch(process.env.CHROME ? { executablePath: process.env.CHROME } : { channel: 'chrome' });

async function signIn(who) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: 'dark', timezoneId: 'UTC', locale: 'en-US' });
  const page = await ctx.newPage();
  const p = PEOPLE[who];
  await page.goto(`${URL}/auth/dev-login?oid=${p.oid}&name=${encodeURIComponent(p.name)}`);
  await page.waitForLoadState('networkidle');
  return page;
}

/** Saves docs/images/<name>.png of the page or of one element. */
async function shot(page, name, target) {
  await page.waitForLoadState('networkidle');
  // Pages show "Loading …" placeholders while queries run.
  await page
    .getByText(/^Loading\b/)
    .first()
    .waitFor({ state: 'detached', timeout: 60_000 })
    .catch(() => {});
  await page.waitForTimeout(400); // let transitions settle
  const file = join(OUT, `${name}.png`);
  if (!target) {
    await page.screenshot({ path: file, animations: 'disabled' });
  } else {
    // Dialogs scroll inside a fixed-height panel: make the window tall enough
    // that the whole panel fits, then capture just the panel.
    const size = page.viewportSize();
    await page.setViewportSize({ width: size.width, height: 2400 });
    await page.waitForTimeout(300);
    await target.screenshot({ path: file, animations: 'disabled' });
    await page.setViewportSize(size);
  }
  console.log(`  ${name}.png`);
}

/** Replaces one-time tokens in the page text (they are single use and lab only, but look like secrets). */
async function maskTokens(page) {
  await page.evaluate(() => {
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = w.nextNode(); n; n = w.nextNode()) n.nodeValue = n.nodeValue.replace(/olyb_[A-Za-z0-9_-]{8,}/g, 'olyb_••••••••');
  });
}

/** Runs the agent install command the UI generated, against one lab cluster. */
function runInstall(command, kubeContext) {
  const args = command.replace(/\\\n/g, ' ').trim().split(/\s+/);
  if (args[0] !== 'helm') throw new Error(`unexpected install command: ${command.slice(0, 40)}`);
  execFileSync('helm', [...args.slice(1), '--kube-context', kubeContext], { cwd: ROOT, env: { ...process.env, KUBECONFIG }, stdio: 'inherit' });
}

async function addCluster(page, { name, labels, kubeContext, bench = false, shots = false }) {
  await page.goto(`${URL}/?add=true`);
  await page.getByLabel('Cluster name').fill(name);
  const labelInput = page.getByRole('textbox', { name: 'Labels' });
  for (const l of labels) {
    await labelInput.fill(l);
    await labelInput.press('Enter');
  }
  if (bench) await page.getByLabel('Enable kube-bench on this cluster').check();
  if (shots) await shot(page, 'start-02-add-cluster', page.getByRole('dialog'));
  await page.getByRole('button', { name: 'Create install command' }).click();
  const pre = page.getByRole('dialog').locator('pre');
  await pre.waitFor();
  const command = await pre.textContent();
  if (shots) {
    await maskTokens(page);
    await shot(page, 'start-03-install-command', page.getByRole('dialog'));
  }
  runInstall(command, kubeContext);
  await page.getByText(/Agent connected/).waitFor({ timeout: 120_000 });
  if (shots) await shot(page, 'start-04-agent-connected', page.getByRole('dialog'));
  await page.getByRole('button', { name: 'Done' }).click();
}

/** Prints the main area's text (DEBUG=1), to see what a step shows. */
async function dump(page, label) {
  if (!process.env.DEBUG) return;
  const dlg = page.getByRole('dialog');
  const where = (await dlg.count()) ? dlg.first() : page.locator('main');
  console.log(`---- ${label}\n${(await where.innerText()).slice(0, 2500)}`);
}

/** Opens a cluster's Backups view and the wizard for one discovered target. */
async function openWizard(page, cluster, target) {
  await page.goto(`${URL}/backups`);
  await page.getByText(cluster, { exact: true }).first().click();
  await page.getByRole('link', { name: `Configure backup for ${target}` }).click();
  await page.getByText(/^step 1 of [45]$/i).waitFor(); // a ClickHouse target has a Backup method step
}

const stages = {
  async clusters() {
    const page = await signIn('admin');
    await shot(page, 'start-01-empty');
    await addCluster(page, { name: 'edge', labels: ['env=lab', 'team=shop'], kubeContext: 'kind-olympos-edge', shots: true });
    await addCluster(page, { name: 'lab', labels: ['env=lab', 'team=platform'], kubeContext: 'kind-olympos-lab', bench: true });
    await page.goto(URL);
    await page
      .getByText('2 agents online')
      .or(page.getByText(/2 clusters reporting/))
      .first()
      .waitFor({ timeout: 60_000 });
    await shot(page, 'dashboard');
  },

  async destination() {
    const page = await signIn('admin');
    await page.goto(`${URL}/settings/destinations`);
    await page
      .getByRole('button', { name: /New destination/ })
      .first()
      .click();
    const dlg = page.getByRole('dialog');
    await dlg.getByText('S3 / S3-compatible', { exact: true }).click();
    await dlg.getByLabel('Name', { exact: true }).fill('lab-minio');
    await dlg.getByLabel(/Endpoint override/).fill('http://minio.olympos.svc:9000');
    await dlg.getByLabel('Region', { exact: true }).fill('us-east-1');
    await dlg.getByLabel('Bucket', { exact: true }).fill('backups');
    await dlg.getByLabel(/Path-style/).check({ force: true });
    await dlg.getByLabel('Access key ID', { exact: true }).fill('olympos-backup');
    await dlg.getByText('Store in Olympos', { exact: true }).click(); // the lab has no Azure Key Vault
    await dlg.getByLabel('Secret key', { exact: true }).fill('lab-backup-secret-key');
    await shot(page, 'start-05-destination', dlg);
    await dlg.getByRole('button', { name: /Test/ }).click();
    await dlg
      .getByText(/can delete|cannot delete|Passed|passed/i)
      .first()
      .waitFor({ timeout: 60_000 });
    await shot(page, 'start-06-destination-tested', dlg);
    await dlg.getByRole('button', { name: /^Save/ }).click();
    await page
      .getByRole('dialog')
      .waitFor({ state: 'detached', timeout: 60_000 })
      .catch(() => {});
  },

  async backup() {
    const page = await signIn('admin');
    // Olympos' own database first: the Dashboard asks for it until it is set.
    await page.goto(`${URL}/backups`);
    const self = page.locator('section.self-backup');
    await self.waitFor();
    if (!(await self.getByRole('button', { name: 'Change' }).count())) {
      await self.getByRole('combobox', { name: 'Destination' }).or(self.getByLabel('Destination')).first().click();
      await page.getByRole('option', { name: /lab-minio/ }).click();
      await shot(page, 'start-07-olympos-backup', self);
      await self.getByRole('button', { name: 'Back up Olympos here' }).click();
      await self.getByRole('button', { name: 'Change' }).waitFor();
    }

    await openWizard(page, 'lab', 'orders-pg');
    await shot(page, 'start-08-backup-target');
    await page.getByRole('button', { name: 'Next: credentials' }).click();
    await page.getByText('Store in Olympos', { exact: true }).click(); // the lab has no Azure Key Vault
    await page.getByLabel('Username', { exact: true }).fill('backup');
    await page.getByLabel('Password', { exact: true }).fill('CANARY-lab-pg-password');
    await page.getByRole('button', { name: 'Test connection' }).click();
    await page
      .getByLabel('Privileges')
      .waitFor({ timeout: 60_000 })
      .catch(() => {});
    await dump(page, 'credentials tested');
    await shot(page, 'start-09-backup-credentials');
    await page.getByRole('button', { name: 'Next: destination' }).click();
    await page.getByText('Daily 02:00', { exact: true }).first().click();
    await dump(page, 'destination step');
    await shot(page, 'start-10-backup-schedule');
    await page.getByRole('button', { name: /^Next/ }).click();
    await page.getByRole('button', { name: 'Create job and run dry run' }).click();
    await page.getByRole('button', { name: 'Enable backup' }).and(page.locator(':enabled')).waitFor({ timeout: 180_000 });
    await dump(page, 'dry run done');
    await shot(page, 'start-11-backup-dry-run');
    await page.getByRole('button', { name: 'Enable backup' }).click();
    await page.waitForURL(/\/backups(?!\/new)/, { timeout: 30_000 });
  },

  // Vault: configure with a root token (used once), then a change request.
  async vault() {
    const page = await signIn('admin');
    await page.goto(`${URL}/vaults`);
    await page.getByText('vault', { exact: true }).first().waitFor({ timeout: 60_000 });
    await labVault(page).click(); // not restore-vault, the new Vault in the same namespace
    await page.getByText('lab/lab/vault').first().waitFor();
    await shot(page, 'start-13-vaults');
    await page
      .locator('main')
      .getByRole('button', { name: /^Configure/ })
      .first()
      .click();
    const dlg = page.getByRole('dialog');
    await dlg.getByLabel(/Root token/).fill(vaultToken('lab/vault'));
    await dlg.getByRole('button', { name: 'List KV mounts' }).click();
    await dlg.getByText('secret/', { exact: false }).first().waitFor({ timeout: 60_000 });
    await dump(page, 'mounts listed');
    await maskTokens(page);
    await shot(page, 'start-14-vault-configure', dlg);
    await dlg.getByRole('button', { name: 'Configure', exact: true }).click();
    await dlg.getByText('Configured', { exact: true }).waitFor({ timeout: 120_000 });
    await shot(page, 'start-15-vault-configured', dlg);
    await page.keyboard.press('Escape');
    await page.goto(`${URL}/vaults`);
    await labVault(page).click();
    await page.waitForTimeout(2000);
    await dump(page, 'vault configured');
  },

  // A second person who may approve Vault changes on env=lab clusters.
  async access() {
    const approver = await signIn('approver'); // first sign-in creates the principal ("no access" until granted)
    await approver.context().close();
    const page = await signIn('admin');
    await page.goto(`${URL}/settings`);
    await page.getByRole('button', { name: 'Grant access' }).first().click();
    const dlg = page.getByRole('dialog');
    await dlg.getByLabel('Person').fill('Ali');
    await dlg.getByRole('option', { name: /Ali Approver/ }).click();
    await dlg.getByLabel('vault-approver').check();
    const scope = dlg.getByRole('textbox', { name: 'Scope (cluster labels)' });
    await scope.fill('env=lab');
    await scope.press('Enter');
    await dump(page, 'grant dialog');
    await shot(page, 'start-16-grant-access', dlg);
    await dlg.getByRole('button', { name: 'Grant access' }).click();
    await dlg.waitFor({ state: 'detached' });
    await shot(page, 'settings-access');
  },

  // Maker: request a new value for one key. Values never show, only keys.
  async change() {
    const page = await signIn('admin');
    await page.goto(`${URL}/vaults`);
    await labVault(page).click();
    await page.getByRole('button', { name: 'Replace db_password' }).click();
    const dlg = page.getByRole('dialog');
    await dlg.getByLabel('New value', { exact: true }).fill('lab-rotated-value-2026');
    await dlg.getByLabel('Confirm value', { exact: true }).fill('lab-rotated-value-2026');
    await dlg.getByLabel('Justification', { exact: true }).fill('Quarterly rotation, OPS-1234');
    await dump(page, 'change dialog');
    await shot(page, 'start-17-change-request', dlg);
    await dlg
      .getByRole('button', { name: /Submit|Request/ })
      .last()
      .click();
    await page
      .getByText('Submitted for approval')
      .or(page.getByText(/waits for a second person/))
      .first()
      .waitFor({ timeout: 30_000 })
      .catch(() => {});
    await page.waitForTimeout(800);
    await dump(page, 'after submit');
    await shot(page, 'start-18-change-submitted');
    await page.keyboard.press('Escape');
  },

  // The maker follows the request under "Opened by me" but cannot approve it, admin included.
  async makerView() {
    const page = await signIn('admin');
    await page.goto(`${URL}/approvals?view=mine`);
    await page.getByText('Replace db_password').first().click();
    await page.getByText('Pending approval').first().waitFor();
    await dump(page, 'maker view of request');
    await shot(page, 'start-19-maker-cannot-approve');
  },

  // Checker: a second person reviews the HMAC fingerprint and approves.
  async approve() {
    const page = await signIn('approver');
    await page.goto(`${URL}/approvals`);
    await page.getByText('secret/shop/payments').first().click();
    await page.waitForTimeout(800);
    await dump(page, 'approver drawer');
    await shot(page, 'approvals');
    await page
      .getByRole('button', { name: /^Approve/ })
      .first()
      .click();
    const confirm = page.getByRole('dialog').getByRole('button', { name: /^Approve/ });
    if (await confirm.count()) await confirm.last().click();
    await page.getByText('Nothing waits for you').waitFor({ timeout: 120_000 });
    await page.goto(`${URL}/approvals?view=all`);
    await page.getByText('Replace db_password').first().click();
    await page
      .getByText(/^Applied/)
      .first()
      .waitFor({ timeout: 120_000 });
    await dump(page, 'applied');
    await shot(page, 'start-20-change-applied');
  },

  // Audits: a Kubescape and a kube-bench schedule, each run once now.
  async audit() {
    const page = await signIn('admin');
    for (const tool of ['kubescape', 'kube-bench']) {
      await page.goto(`${URL}/audit`);
      await page.getByRole('button', { name: 'New schedule' }).first().click();
      const dlg = page.getByRole('dialog');
      await dlg.locator(`input[name="tool"]`).nth(['kubescape', 'polaris', 'kube-bench'].indexOf(tool)).check({ force: true });
      if (tool === 'kubescape') await shot(page, 'start-21-audit-schedule', dlg);
      await dlg
        .getByRole('button', { name: /^(Create|Save)/ })
        .last()
        .click();
      await dlg.waitFor({ state: 'detached' });
      const label = tool === 'kubescape' ? 'Kubescape' : 'kube-bench';
      await page
        .getByRole('button', { name: new RegExp(`^Run ${label} now`) })
        .first()
        .click();
    }
    // kube-bench runs a Job per node; Kubescape scans through the read-only proxy.
    await page.waitForTimeout(5000);
    for (let i = 0; i < 60; i++) {
      await page.goto(`${URL}/audit`);
      await page
        .getByText(/^Loading/)
        .first()
        .waitFor({ state: 'detached', timeout: 30_000 })
        .catch(() => {});
      const text = await page.locator('main').innerText();
      if (!/queued|running|Loading/i.test(text)) break;
      await page.waitForTimeout(10_000);
    }
    await dump(page, 'audit done');
    await shot(page, 'audit');
    // Keep the raw reports too (redacted), on the lab's MinIO.
    const raw = page.getByRole('region', { name: 'Raw reports' });
    await raw.getByRole('button', { name: 'Choose a destination' }).click();
    await raw.getByRole('combobox', { name: 'Raw reports destination' }).click();
    await page.getByRole('option', { name: /lab-minio/ }).click();
    await raw.getByRole('button', { name: 'Save' }).click();
    await raw.getByText(/^Stored on/).waitFor();
    await shot(page, 'audit-raw-reports', raw);
  },

  // Security: images with CVEs, Kyverno, NetworkPolicy, sensitive data.
  async security() {
    const page = await signIn('admin');
    for (let i = 0; i < 60; i++) {
      await page.goto(`${URL}/security`);
      await page
        .getByText(/^Loading/)
        .first()
        .waitFor({ state: 'detached', timeout: 30_000 })
        .catch(() => {});
      const text = await page.locator('main').innerText();
      if (!/Scanning|pending scan|Queued|Loading/i.test(text) && /critical|high/i.test(text)) break;
      await page.waitForTimeout(10_000);
    }
    await shot(page, 'security-overview');
    // One cluster: images by digest with CVEs, then its NetworkPolicies.
    await page.getByText('edge', { exact: true }).first().click();
    await page.getByRole('tab', { name: /^Images/ }).waitFor();
    await shot(page, 'security');
    await page.getByRole('tab', { name: /^Network policies/ }).click();
    await page.waitForLoadState('networkidle');
    await dump(page, 'netpol tab');
    await shot(page, 'security-netpol-namespaces');
    await page
      .getByText(/^All · \d+/)
      .first()
      .click();
    await page
      .locator('main')
      .getByRole('row')
      .filter({ has: page.getByText('secure', { exact: true }) })
      .first()
      .click();
    await page.waitForLoadState('networkidle');
    await dump(page, 'netpol namespace');
    await shot(page, 'security-netpol');
    // Kyverno runs on the lab cluster.
    await page.goto(`${URL}/security`);
    await page.getByText('lab', { exact: true }).first().click();
    await page.getByRole('tab', { name: /^Kyverno policies/ }).click();
    await page.waitForLoadState('networkidle');
    await shot(page, 'security-kyverno');
    await page
      .locator('main')
      .getByRole('row')
      .filter({ has: page.getByText('require-app-label', { exact: true }) })
      .first()
      .click();
    await page.waitForLoadState('networkidle');
    await dump(page, 'kyverno policy');
    await shot(page, 'security-kyverno-policy');
  },

  // First real backup: Run now, then the run's restore commands.
  async firstRun() {
    const page = await signIn('admin');
    await page.goto(`${URL}/backups?tab=jobs`);
    await page.getByRole('button', { name: 'Run orders-pg now' }).click();
    await page.waitForTimeout(1000);
    await page.goto(`${URL}/backups?tab=runs`);
    const done = page.getByRole('row').filter({ hasText: 'orders-pg' }).filter({ hasText: 'Succeeded' }).filter({ hasNotText: 'test' });
    await done.first().waitFor({ timeout: 180_000 });
    await shot(page, 'backups-runs');
    await page
      .getByRole('row', { name: /Restore commands and details of the orders-pg run/ })
      .first()
      .click();
    await page.getByRole('dialog').waitFor();
    await dump(page, 'run dialog');
    await shot(page, 'start-12-backup-restore-commands', page.getByRole('dialog'));
    await page.keyboard.press('Escape');
    await page.goto(`${URL}/backups`);
    await shot(page, 'backups');
  },

  // Two copies of every backup: Azurite next to MinIO, a group of both, a job
  // that writes to it. Then Azurite is taken off the network for one run:
  // the run ends Partial and a repair run writes the missing copy.
  async groups() {
    const page = await signIn('admin');
    await page.goto(`${URL}/settings/destinations`);
    await page
      .getByRole('button', { name: /New destination/ })
      .first()
      .click();
    let dlg = page.getByRole('dialog');
    await dlg.getByText('Azure Blob', { exact: true }).click();
    await dlg.getByLabel('Name', { exact: true }).fill('lab-azurite');
    await dlg.getByLabel('Storage account', { exact: true }).fill('devstoreaccount1');
    await dlg.getByLabel('Container', { exact: true }).fill('backups');
    await dlg.getByLabel(/Endpoint override/).fill('http://azurite.olympos.svc:10000/devstoreaccount1');
    await dlg.getByText('SAS token', { exact: true }).click();
    await dlg.getByText('Store in Olympos', { exact: true }).click();
    await dlg.getByLabel('SAS token', { exact: true }).fill(azuriteSas());
    await dlg.getByRole('button', { name: /^Save/ }).click();
    await dlg.waitFor({ state: 'detached', timeout: 60_000 });

    const groups = page.getByRole('region', { name: 'Groups' });
    await groups.getByRole('button', { name: 'New group' }).first().click();
    dlg = page.getByRole('dialog');
    await dlg.getByLabel('Name', { exact: true }).fill('lab-copies');
    await dlg.getByLabel('Description', { exact: true }).fill('MinIO and Azurite');
    for (const name of ['lab-minio', 'lab-azurite']) {
      await dlg.getByRole('combobox', { name: 'Add destination' }).click();
      await page.getByRole('option', { name: new RegExp(name) }).click();
      await dlg.getByRole('button', { name: 'Add', exact: true }).click();
    }
    await dump(page, 'group dialog');
    await shot(page, 'start-22-destination-group', dlg);
    await dlg.getByRole('button', { name: 'Create group' }).click();
    await dlg.waitFor({ state: 'detached', timeout: 30_000 });
    await groups.getByText('lab-copies').first().waitFor();
    await shot(page, 'start-23-destination-groups');

    // A second database, backed up to the group from the start.
    await openWizard(page, 'edge', 'payments-pg');
    await page.getByRole('button', { name: 'Next: credentials' }).click();
    await page.getByText('Store in Olympos', { exact: true }).click();
    await page.getByLabel('Username', { exact: true }).fill('backup');
    await page.getByLabel('Password', { exact: true }).fill('edge-pg-password');
    await page.getByRole('button', { name: 'Test connection' }).click();
    await page.getByLabel('Privileges').waitFor({ timeout: 60_000 });
    await page.getByRole('button', { name: 'Next: destination' }).click();
    await page.locator('label.opt').filter({ hasText: 'lab-copies' }).click();
    await dump(page, 'destination step with a group');
    await shot(page, 'start-24-backup-group');
    await page.getByRole('button', { name: /^Next/ }).click();
    await page.getByRole('button', { name: 'Create job and run dry run' }).click();
    await page.getByRole('button', { name: 'Enable backup' }).and(page.locator(':enabled')).waitFor({ timeout: 180_000 });
    await dump(page, 'group dry run done');
    await shot(page, 'start-25-backup-group-dry-run');
    await page.getByRole('button', { name: 'Enable backup' }).click();
    await page.waitForURL(/\/backups(?!\/new)/, { timeout: 30_000 });

    // A run with two copies.
    const ok = await runJob(page, 'payments-pg', (r) => !r.repair_of);
    if (ok.status !== 'succeeded') throw new Error(`group run ended ${ok.status}: ${ok.error}`);
    await openRun(page, 'payments-pg', (rows) => rows.filter({ hasText: '2 of 2 copies' }).filter({ hasNotText: 'Repair' }));
    await dump(page, 'group run dialog');
    await shot(page, 'start-26-run-copies', page.getByRole('dialog'));
    await page.keyboard.press('Escape');
  },

  // Azurite unreachable for one run: the run is Partial, and the first repair
  // run, queued for 5 minutes later, writes the missing copy once Azurite is back.
  async partial() {
    const page = await signIn('admin');
    // Off the network, data kept (Azurite holds it in memory): the Service
    // loses its endpoints. Kept-alive connections close after 90 s idle.
    azurite(false);
    let partial;
    try {
      await page.waitForTimeout(100_000);
      partial = await runJob(page, 'payments-pg', (r) => !r.repair_of);
      if (partial.status !== 'partial') throw new Error(`expected a partial run, got ${partial.status}: ${partial.error}`);
    } finally {
      azurite(true);
    }
    await page.goto(URL);
    const attention = page.getByRole('region', { name: 'Needs attention' });
    await attention.getByText('Backup incomplete').waitFor({ timeout: 30_000 });
    await shot(page, 'start-27-backup-incomplete', attention);
    // The repair waits in the queue (Queued · starts …), and the partial run says when.
    await page.goto(`${URL}/backups?tab=runs`);
    await page.getByRole('row').filter({ hasText: 'payments-pg' }).filter({ hasText: 'Repair' }).filter({ hasText: 'Queued · starts' }).first().waitFor();
    await shot(page, 'start-28-partial-and-repair');
    await openRun(page, 'payments-pg', (rows) => rows.filter({ hasText: 'Partial' }));
    await page.getByRole('dialog').locator('.note').filter({ hasText: 'Repair queued: next attempt at' }).waitFor();
    await dump(page, 'partial run dialog');
    await shot(page, 'start-29-partial-run', page.getByRole('dialog'));
    await page.keyboard.press('Escape');
    // The repair starts 5 minutes after the partial run and writes only the missing copy.
    const repair = await waitRun(page, 'payments-pg', (r) => r.repair_of === partial.id, 600_000);
    if (repair.status !== 'succeeded') throw new Error(`repair ended ${repair.status}: ${repair.error}`);

    // Olympos' own database to the group as well.
    await page.goto(`${URL}/backups`);
    const self = page.locator('section.self-backup');
    await self.getByRole('button', { name: 'Change' }).click();
    await self.getByRole('combobox', { name: 'Destination' }).click();
    await page.getByRole('option', { name: /lab-copies/ }).click();
    await self.getByRole('button', { name: 'Save', exact: true }).click();
    await self.getByRole('button', { name: 'Change' }).waitFor();
    await self.getByRole('button', { name: 'Run now' }).click();
    await self.getByRole('button', { name: 'Restore commands' }).waitFor({ timeout: 180_000 });
    await self.getByRole('button', { name: 'Restore commands' }).click();
    await page.getByRole('dialog').getByText('Restore from copy').waitFor();
    await dump(page, 'self restore');
    await shot(page, 'start-30-olympos-restore-copy', page.getByRole('dialog'));
    await page.keyboard.press('Escape');
  },

  // Restore from the UI: orders-pg into the new restore-pg, with a check, a
  // second person's approval and the result. The approver needs operate on
  // both clusters (vault-approver is for Vault changes only).
  async restore() {
    const admin = await signIn('admin');
    // Ali signed in during the access stage, so the principal exists.
    await apiCall(admin, 'POST', '/grants', { object_id: PEOPLE.approver.oid, roles: ['operator'], scope: 'env=lab' }, [201, 409]);

    // Something to restore: two tables in orders, then a fresh backup.
    // orders-pg keeps its data across lab resets (and TestM8Restores checks
    // its own table only), so the tables are dropped before and after.
    const dropPG = () => labSQL('orders-pg', ['DROP TABLE IF EXISTS orders, customers']);
    dropPG();
    try {
      labSQL('orders-pg', [
        'CREATE TABLE IF NOT EXISTS customers (id int PRIMARY KEY, name text NOT NULL)',
        'CREATE TABLE IF NOT EXISTS orders (id int PRIMARY KEY, customer_id int REFERENCES customers, total numeric(10,2), placed_at timestamptz)',
        "INSERT INTO customers SELECT g, 'customer ' || g FROM generate_series(1, 500) g ON CONFLICT DO NOTHING",
        "INSERT INTO orders SELECT g, 1 + g % 500, (g % 97) * 1.25, timestamptz '2026-11-01' + g * interval '1 minute' FROM generate_series(1, 20000) g ON CONFLICT DO NOTHING",
      ]);
      const run = await runJob(admin, 'orders-pg', (r) => !r.repair_of);
      if (run.status !== 'succeeded') throw new Error(`orders-pg run ended ${run.status}: ${run.error}`);

      const pg = await openRestoreDialog(admin, 'orders-pg', 'restore-pg');
      await pg.getByText('Store in Olympos', { exact: true }).click(); // the lab has no Azure Key Vault
      await pg.getByLabel('Username', { exact: true }).fill('postgres');
      await pg.getByLabel('Password', { exact: true }).fill('CANARY-lab-restore-pg-password');
      await checkTarget(pg);
      await pg.getByLabel('Justification', { exact: true }).fill('INC-2041: orders-pg volume lost, restore into restore-pg');
      await dump(admin, 'restore dialog checked');
      await shot(admin, 'restore-01-dialog', pg);
      const pgID = await submitRestore(admin, pg);

      // The checker: another person with operate on both clusters.
      const approver = await signIn('approver');
      await approver.goto(`${URL}/approvals?restore=${pgID}`);
      await approver.getByRole('button', { name: 'Approve restore' }).waitFor();
      await dump(approver, 'restore waiting for the checker');
      await shot(approver, 'restore-02-approvals');
      await approver.getByRole('button', { name: 'Approve restore' }).click();
      await waitRestoreDone(approver, pgID);
      await approver.goto(`${URL}/approvals?view=all&restore=${pgID}`);
      await approver.getByRole('heading', { name: 'Result' }).waitFor();
      await dump(approver, 'restore result');
      await shot(approver, 'restore-03-result', approver.locator('.split-detail'));
    } finally {
      dropPG();
    }
  },

  // ClickHouse: tables come back with their data; a view, a materialized
  // view's definition, a Merge table and column defaults are reported.
  // metrics-ch has no TLS, so the lab cluster uses compressed transfer mode.
  // A database of its own: metrics-ch keeps its data across lab resets.
  async restoreClickHouse() {
    const admin = await signIn('admin');
    const approver = await signIn('approver');
    const lab = (await apiCall(admin, 'GET', '/clusters')).items.find((c) => c.name === 'lab');
    const dropCH = () => chSQL('metrics-ch', 'backup', 'CANARY-lab-ch-password', ['DROP DATABASE IF EXISTS analytics SYNC']);
    dropCH();
    try {
      await apiCall(admin, 'PATCH', `/clusters/${lab.id}`, { transfer_mode: 'compressed' });
      chSQL('metrics-ch', 'backup', 'CANARY-lab-ch-password', [
        'CREATE DATABASE IF NOT EXISTS analytics',
        'CREATE TABLE IF NOT EXISTS analytics.events (d Date, service LowCardinality(String), v UInt64) ENGINE = MergeTree PARTITION BY toYYYYMM(d) ORDER BY (service, d)',
        "INSERT INTO analytics.events SELECT toDate('2026-10-01') + number % 60, ['api', 'web', 'worker'][1 + number % 3], number FROM numbers(30000)",
        'CREATE TABLE IF NOT EXISTS analytics.sessions (d Date, user String, hits UInt32 DEFAULT 1) ENGINE = ReplacingMergeTree ORDER BY (d, user) TTL d + INTERVAL 2 YEAR',
        "INSERT INTO analytics.sessions SELECT toDate('2026-10-01') + number % 30, concat('u', toString(number % 900)), number FROM numbers(4000)",
        'CREATE MATERIALIZED VIEW IF NOT EXISTS analytics.events_daily ENGINE = SummingMergeTree ORDER BY (service, d) AS SELECT d, service, count() AS n FROM analytics.events GROUP BY d, service',
        "INSERT INTO analytics.events SELECT toDate('2026-11-01') + number % 20, ['api', 'web'][1 + number % 2], number FROM numbers(6000)",
        'CREATE VIEW IF NOT EXISTS analytics.errors_by_day AS SELECT d, count() AS n FROM analytics.events WHERE v % 100 = 0 GROUP BY d',
        "CREATE TABLE IF NOT EXISTS analytics.all_events AS analytics.events ENGINE = Merge('analytics', '^events$')",
      ]);
      const chJob = await ensureJobAPI(admin, 'metrics-ch', {
        credential: { source: 'stored', username: 'backup', password: 'CANARY-lab-ch-password' },
        engine_options: { databases: ['analytics'] },
      });
      await runJobAPI(admin, chJob, 'metrics-ch');
      const ch = await openRestoreDialog(admin, 'metrics-ch', 'restore-ch');
      await ch.getByText('Store in Olympos', { exact: true }).click();
      await ch.getByLabel('Username', { exact: true }).fill('restore');
      await ch.getByLabel('Password', { exact: true }).fill('CANARY-lab-restore-ch-password');
      await checkTarget(ch);
      await ch.getByLabel('Justification', { exact: true }).fill('INC-2041: metrics-ch lost with the node, restore into restore-ch');
      const chID = await submitRestore(admin, ch);
      await apiCall(approver, 'POST', `/restores/${chID}/approve`, { comment: 'Checked the target' });
      await waitRestoreDone(admin, chID);
      await admin.goto(`${URL}/approvals?view=all&restore=${chID}`);
      await admin.getByRole('heading', { name: 'Result' }).waitFor();
      await dump(admin, 'clickhouse restore result');
      await shot(admin, 'restore-04-clickhouse-result', admin.locator('.split-detail'));
    } finally {
      await apiCall(admin, 'PATCH', `/clusters/${lab.id}`, { transfer_mode: 'e2e-tls' });
      dropCH();
    }
  },

  // ClickHouse native (docs/design/backup-wizard-clickhouse.html): the Backup
  // method step of the wizard, then a native run and its run page. Needs the
  // server's ingest endpoint (ingest.url) and a native-ready ClickHouse in the
  // lab; ClickHouse reaches the endpoint directly, not through the agent.
  // A lab without them skips the stage, so the later stages still run.
  async clickhouseNative() {
    const page = await signIn('admin');
    const ingest = (await apiCall(page, 'GET', '/backup/settings')).ingest_enabled;
    const target = (await apiCall(page, 'GET', '/targets')).items.find((x) => x.service === NATIVE_CH && x.cluster_name === 'lab' && x.status !== 'gone');
    if (!ingest || !target) {
      console.log(`  skipped: ${!ingest ? 'the lab server has no ingest.url (native ClickHouse backups are off)' : `no ${NATIVE_CH} target in the lab cluster`}`);
      await page.context().close();
      return;
    }
    const dropCH = () => chSQL(NATIVE_CH, 'backup', NATIVE_CH_PASSWORD, ['DROP DATABASE IF EXISTS shop SYNC']);
    dropCH();
    try {
      chSQL(NATIVE_CH, 'backup', NATIVE_CH_PASSWORD, [
        'CREATE DATABASE IF NOT EXISTS shop',
        'CREATE TABLE IF NOT EXISTS shop.orders (id UInt64, placed Date, total Decimal(10, 2) CODEC(ZSTD(3)), note String DEFAULT \'\') ENGINE = MergeTree PARTITION BY toYYYYMM(placed) ORDER BY id TTL placed + INTERVAL 5 YEAR',
        "INSERT INTO shop.orders (id, placed, total) SELECT number, toDate('2026-10-01') + number % 60, (number % 97) * 1.25 FROM numbers(20000)",
        'CREATE VIEW IF NOT EXISTS shop.orders_by_day AS SELECT placed, count() AS n FROM shop.orders GROUP BY placed',
      ]);
      await openWizard(page, 'lab', NATIVE_CH);
      await page.getByRole('button', { name: 'Next: credentials' }).click();
      await page.getByText('Store in Olympos', { exact: true }).click(); // the lab has no Azure Key Vault
      await page.getByLabel('Username', { exact: true }).fill('backup');
      await page.getByLabel('Password', { exact: true }).fill(NATIVE_CH_PASSWORD);
      const dbs = page.getByLabel('Databases', { exact: true });
      await dbs.fill('shop');
      await dbs.press('Enter');
      await page.getByRole('button', { name: 'Next: method' }).click();
      await page.getByRole('heading', { name: 'Backup method' }).waitFor();
      // a new job starts on Logical until native restore lands (R42); incrementals are not available yet
      await page.getByRole('radio', { name: /^Logical/ }).and(page.locator(':checked')).waitFor();
      await page.getByText('Native', { exact: true }).click();
      await page.getByRole('radio', { name: /^Native/ }).and(page.locator(':checked')).waitFor();
      await dump(page, 'native method step');
      await shot(page, 'clickhouse-native-01-method');
      await page.getByRole('button', { name: 'Next: destination' }).click();
      await page.locator('label.opt').filter({ hasText: 'lab-copies' }).click();
      await page.getByRole('button', { name: /^Next/ }).click();
      await page.getByText('Native · every run a full backup').waitFor();
      await page.getByRole('button', { name: 'Create job and run dry run' }).click();
      await page.getByRole('button', { name: 'Enable backup' }).and(page.locator(':enabled')).waitFor({ timeout: 300_000 });
      await dump(page, 'native dry run done');
      await page.getByRole('button', { name: 'Enable backup' }).click();
      await page.waitForURL(/\/backups(?!\/new)/, { timeout: 30_000 });

      // A native run: the run page shows the Native badge and the object count, and no restore commands.
      const run = await runJob(page, NATIVE_CH, (r) => !r.repair_of);
      if (run.status !== 'succeeded' || run.method !== 'native' || !run.objects) throw new Error(`native run ended ${run.status} (${run.method}, ${run.objects} objects): ${run.error}`);
      await openRun(page, NATIVE_CH, (rows) => rows.filter({ hasText: 'Succeeded' }).filter({ hasNotText: 'test' }));
      const dlg = page.getByRole('dialog');
      await dlg.getByText(/^· [\d,]+ objects?$/).waitFor();
      await dlg.getByText('Native restore is not available yet; the backup is kept.', { exact: false }).waitFor();
      await dump(page, 'native run dialog');
      await shot(page, 'clickhouse-native-02-run', dlg);
      await page.keyboard.press('Escape');
    } finally {
      dropCH();
    }
  },

  // Vault: lab/vault's snapshot into restore-vault, a new Vault that is
  // initialized, unsealed and not configured in Olympos.
  async restoreVault() {
    const admin = await signIn('admin');
    const approver = await signIn('approver');
    const vJob = await ensureJobAPI(admin, 'vault', {});
    await runJobAPI(admin, vJob, 'vault');
    const vt = await openRestoreDialog(admin, 'vault', 'restore-vault');
    await vt.getByLabel('Token of the new Vault', { exact: true }).fill(vaultToken('lab/restore-vault'));
    await checkTarget(vt);
    await vt.getByLabel('Justification', { exact: true }).fill('INC-2042: lab vault storage corrupted, restore its snapshot into restore-vault');
    const vID = await submitRestore(admin, vt);
    await apiCall(approver, 'POST', `/restores/${vID}/approve`, { comment: 'Source keys are with the platform team' });
    await waitRestoreDone(admin, vID);
    await admin.goto(`${URL}/approvals?view=all&restore=${vID}`);
    await admin.getByRole('heading', { name: 'Result' }).waitFor();
    await dump(admin, 'vault restore result');
    await shot(admin, 'restore-05-vault-result', admin.locator('.split-detail'));
  },

  // Synthetic monitoring (docs/synthetic-monitoring.md): both clusters got a
  // probe with their agent in the clusters stage. synth-web answers every
  // *.olympos-lab.test name in each cluster; edge's is switched to 500, so the
  // shop flow fails there while it passes on lab.
  async monitoring() {
    const admin = await signIn('admin');
    await until(admin, 180_000, 'both probes online', async () => {
      const cs = (await apiCall(admin, 'GET', '/clusters')).items;
      return ['lab', 'edge'].every((n) => cs.find((c) => c.name === n)?.probe_status === 'online');
    });
    const labID = (await apiCall(admin, 'GET', '/clusters')).items.find((c) => c.name === 'lab').id;
    synthWeb('lab', 'ok');
    synthWeb('edge', 'ok');
    try {
      const rules = (await apiCall(admin, 'GET', '/synthetic/allowlist')).items;
      for (const r of [
        { pattern: 'olympos-lab.test', kind: 'suffix', note: 'Lab: synth-web answers every name in every cluster' },
        { pattern: '*.shop.svc.cluster.local', kind: 'wildcard', note: 'In-cluster shop services' },
      ]) {
        if (!rules.some((x) => x.pattern === r.pattern && x.kind === r.kind)) await apiCall(admin, 'POST', '/synthetic/allowlist', r);
      }
      // Lab values only (synth-web takes any token); Olympos never shows them again.
      const creds = (await apiCall(admin, 'GET', '/synthetic/credentials')).items;
      const inDays = (n) => new Date(Date.now() + n * 86_400_000).toISOString();
      const ensureCred = async (body) => creds.find((c) => c.name === body.name)?.id ?? (await apiCall(admin, 'POST', '/synthetic/credentials', body)).id;
      const shopToken = await ensureCred({
        name: 'shop-api-token',
        kind: 'bearer',
        bound_hosts: [{ kind: 'suffix', pattern: 'olympos-lab.test' }],
        secret: { source: 'stored', password: 'lab-only-shop-token' },
        expires_at: inDays(90),
      });
      await ensureCred({
        name: 'status-page-key',
        kind: 'header',
        header_name: 'X-Api-Key',
        bound_hosts: [{ kind: 'exact', pattern: 'status.olympos-lab.test' }],
        secret: { source: 'stored', password: 'lab-only-status-key' },
        expires_at: inDays(10),
      });

      const status200 = { subject: 'status_code', operator: 'equals', value: '200' };
      const http = (url, extra = {}) => ({ kind: 'http', http: { method: 'GET', url }, assertions: [status200], ...extra });
      const scenarios = [
        {
          name: 'Shop items API',
          type: 'http_flow',
          owner_selector: 'team=shop',
          steps: [
            http('http://shop.olympos-lab.test/health'),
            http('http://shop.olympos-lab.test/api/items', {
              credential_id: shopToken,
              assertions: [status200, { subject: 'json:$.count', operator: 'equals', value: '2' }, { subject: 'latency_ms', operator: 'less_than', value: '500' }],
            }),
          ],
        },
        {
          name: 'Storefront DNS',
          type: 'dns',
          owner_selector: 'team=shop',
          steps: [{ kind: 'dns', dns: { name: 'storefront.olympos-lab.test', record_type: 'A' }, assertions: [{ subject: 'record_count', operator: 'greater_than', value: '0' }] }],
        },
        {
          name: 'Checkout health',
          type: 'http',
          owner_selector: 'team=platform',
          exclude_selectors: ['olympos.io/cluster=edge'],
          steps: [http('http://checkout.olympos-lab.test/health', { assertions: [status200, { subject: 'latency_ms', operator: 'less_than', value: '300' }] })],
        },
        {
          name: 'Payments gateway port',
          type: 'tcp',
          owner_selector: 'team=payments',
          enabled: false,
          steps: [{ kind: 'tcp', tcp: { host: 'payments.olympos-lab.test', port: 80 }, assertions: [{ subject: 'connects', operator: 'equals', value: 'true' }] }],
        },
      ];
      const alerts = { cluster_fail_after: 3, fleet_critical_clusters: 2, recovery_after: 2, send_recovery: true };
      const existing = (await apiCall(admin, 'GET', '/synthetic/scenarios')).items;
      const ids = {};
      for (const sc of scenarios) {
        ids[sc.name] =
          existing.find((x) => x.name === sc.name)?.id ??
          (await apiCall(admin, 'POST', '/synthetic/scenarios', { interval_seconds: 30, timeout_seconds: 10, run_on: 'all', store_responses: true, alerts, ...sc })).id;
      }
      const shop = ids['Shop items API'];

      // A few passing runs everywhere, then edge's synth-web answers 500:
      // after three failed runs the shop flow's edge cell reads failing.
      await until(admin, 180_000, 'shop flow passing on both clusters', () => cellStates(admin, shop, (s) => s.lab === 'passing' && s.edge === 'passing'));
      await admin.waitForTimeout(60_000);
      synthWeb('edge', '500');
      await until(admin, 300_000, 'shop flow failing on edge', () => cellStates(admin, shop, (s) => s.lab === 'passing' && s.edge === 'failing'));

      await admin.goto(`${URL}/monitoring`);
      await admin.getByRole('table', { name: 'Scenarios by cluster' }).waitFor();
      await dump(admin, 'monitoring overview');
      await shot(admin, 'monitoring-01-overview');

      await admin.goto(`${URL}/monitoring?scenario=${shop}`);
      await admin.getByRole('table', { name: 'Scenario by cluster' }).waitFor();
      await dump(admin, 'scenario detail');
      await shot(admin, 'monitoring-02-scenario');

      await admin.goto(`${URL}/monitoring/editor?scenario=${shop}`);
      await admin.getByRole('heading', { name: 'Basics' }).waitFor();
      await dump(admin, 'scenario editor');
      // The editor is taller than the window: a taller window, with the sidebar.
      await admin.setViewportSize({ width: 1440, height: 1250 });
      await shot(admin, 'monitoring-03-editor');
      await admin.setViewportSize({ width: 1440, height: 900 });

      // A passing run on lab: the echoed token and the cookie are redacted.
      const run = (await apiCall(admin, 'GET', `/synthetic/runs?scenario_id=${shop}&cluster_id=${labID}&status=passed&limit=1`)).items[0];
      await admin.goto(`${URL}/monitoring?scenario=${shop}&run=${run.id}`);
      await admin.getByRole('dialog').getByLabel('Response excerpt').first().waitFor();
      await dump(admin, 'run detail');
      await shot(admin, 'monitoring-04-run', admin.getByRole('dialog'));

      await admin.goto(`${URL}/settings/synthetic`);
      await admin.getByRole('table', { name: 'Credentials' }).waitFor();
      await dump(admin, 'synthetic settings');
      await shot(admin, 'monitoring-05-settings');
    } finally {
      synthWeb('edge', 'ok');
    }
  },

  // Add cluster for Argo CD or Flux (docs/install.md, "Install with Argo CD or Flux"): the GitOps tab of the
  // install command. Creates a cluster it never installs, masks the token, and revokes the cluster again.
  async installGitOps() {
    const admin = await signIn('admin');
    const NAME = 'oke-fra-gitops';
    for (const c of (await apiCall(admin, 'GET', '/clusters')).items.filter((x) => x.name === NAME && x.status !== 'revoked')) {
      await apiCall(admin, 'DELETE', `/clusters/${c.id}`, undefined, [200, 204]);
    }
    await admin.goto(`${URL}/?add=true`);
    await admin.getByLabel('Cluster name').fill(NAME);
    const labelInput = admin.getByRole('textbox', { name: 'Labels' });
    await labelInput.fill('env=prod');
    await labelInput.press('Enter');
    await admin.getByRole('button', { name: 'Create install command' }).click();
    await admin.getByRole('dialog').locator('pre').first().waitFor();
    const dlg = admin.getByRole('dialog');
    await dlg.getByRole('button', { name: 'GitOps (Argo CD, Flux)' }).click();
    await dlg.getByLabel('Chart values').waitFor();
    await maskTokens(admin);
    await admin.evaluate(() => {
      // the CA is long and says nothing in an image
      for (const pre of document.querySelectorAll('pre')) pre.textContent = pre.textContent.replace(/serverCA: (\S{24})\S+/, 'serverCA: $1…');
    });
    await dump(admin, 'gitops install');
    await shot(admin, 'install-gitops', dlg);
    await dlg.getByRole('button', { name: 'Done' }).click();
    const c = (await apiCall(admin, 'GET', '/clusters')).items.find((x) => x.name === NAME && x.status !== 'revoked');
    if (c) await apiCall(admin, 'DELETE', `/clusters/${c.id}`, undefined, [200, 204]);
  },

  // A credential that cannot be resolved (docs/synthetic-monitoring.md, "Credentials that cannot be
  // resolved"): a Key Vault reference to a secret that the lab's local Key Vault does not have. Needs the
  // probes online and the olympos-lab.test allowlist rule (monitoring stage). Removes what it creates.
  async monitoringCredential() {
    const admin = await signIn('admin');
    await until(admin, 180_000, 'both probes online', async () => {
      const cs = (await apiCall(admin, 'GET', '/clusters')).items;
      return ['lab', 'edge'].every((n) => cs.find((c) => c.name === n)?.probe_status === 'online');
    });
    const NAME = 'search-api-key';
    const SCENARIO = 'Search API';
    // A rerun after a failed one: scenario first, a credential in use cannot be deleted.
    const cleanup = async () => {
      for (const sc of (await apiCall(admin, 'GET', '/synthetic/scenarios')).items.filter((x) => x.name === SCENARIO)) {
        await apiCall(admin, 'DELETE', `/synthetic/scenarios/${sc.id}`, undefined, [200, 204, 404]);
      }
      for (const c of (await apiCall(admin, 'GET', '/synthetic/credentials')).items.filter((x) => x.name === NAME)) {
        await apiCall(admin, 'DELETE', `/synthetic/credentials/${c.id}`, undefined, [200, 204, 404]);
      }
    };
    try {
      await cleanup();
      const rules = (await apiCall(admin, 'GET', '/synthetic/allowlist')).items;
      if (!rules.some((x) => x.pattern === 'olympos-lab.test' && x.kind === 'suffix')) {
        await apiCall(admin, 'POST', '/synthetic/allowlist', { pattern: 'olympos-lab.test', kind: 'suffix', note: 'Lab: synth-web answers every name in every cluster' });
      }
      const cred = await apiCall(admin, 'POST', '/synthetic/credentials', {
        name: NAME,
        kind: 'header',
        header_name: 'X-Api-Key',
        bound_hosts: [{ kind: 'suffix', pattern: 'olympos-lab.test' }],
        secret: { source: 'keyvault_ref', ref: 'kv://lab/search-api-key' }, // not in the lab's Key Vault
      });
      await apiCall(admin, 'POST', '/synthetic/scenarios', {
        name: SCENARIO,
        type: 'http',
        owner_selector: 'team=shop',
        interval_seconds: 30,
        timeout_seconds: 10,
        run_on: 'all',
        store_responses: true,
        alerts: { cluster_fail_after: 3, fleet_critical_clusters: 2, recovery_after: 2, send_recovery: true },
        steps: [
          {
            kind: 'http',
            http: { method: 'GET', url: 'http://shop.olympos-lab.test/api/items' },
            credential_id: cred.id,
            assertions: [{ subject: 'status_code', operator: 'equals', value: '200' }],
          },
        ],
      });

      // The first run that reaches the credential finds the secret missing.
      await until(admin, 180_000, 'the credential to be reported as cannot be resolved', async () => {
        const c = (await apiCall(admin, 'GET', '/synthetic/credentials')).items.find((x) => x.id === cred.id);
        return c?.resolve_state === 'broken';
      });
      await admin.goto(`${URL}/settings/synthetic?credential=${cred.id}`);
      const card = admin.getByRole('region', { name: 'Credentials' });
      await card.getByText('Cannot be resolved').waitFor({ timeout: 180_000 });
      await dump(admin, 'credential that cannot be resolved');
      await shot(admin, 'monitoring-06-credential-broken', card);

      await admin.goto(URL);
      const strip = admin.getByRole('region', { name: 'Needs attention' });
      await strip.getByText('Synthetic credential').waitFor({ timeout: 60_000 });
      await dump(admin, 'dashboard');
      await shot(admin, 'monitoring-07-attention', strip);
    } finally {
      await cleanup();
    }
  },
};

/** Switches a lab cluster's synth-web (test/e2e/cmd/synth-web) to ok, 500 or slow. */
function synthWeb(cluster, mode) {
  execFileSync('kubectl', ['--context', `kind-olympos-${cluster}`, '-n', 'lab', 'exec', 'deploy/synth-web', '--', '/synth-web', 'toggle', mode], {
    env: { ...process.env, KUBECONFIG },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
}

/** Waits until check() resolves true, every 3 s. */
async function until(page, timeout, what, check) {
  const end = Date.now() + timeout;
  while (!(await check())) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await page.waitForTimeout(3000);
  }
}

/** pick() of a scenario's matrix cells by cluster name (GET /synthetic/overview). */
async function cellStates(page, scenarioID, pick) {
  const ov = await apiCall(page, 'GET', '/synthetic/overview');
  const names = Object.fromEntries(ov.clusters.map((c) => [c.id, c.name]));
  const row = ov.scenarios.find((x) => x.id === scenarioID);
  return pick(Object.fromEntries((row?.cells ?? []).map((c) => [names[c.cluster_id], c.state])));
}

/** The lab cluster's vault (lab/vault) in the Vaults list. */
function labVault(page) {
  return page.getByRole('button', { name: /^lab \/ lab \/ vault, / });
}

/** A state-changing (or GET) API call with the page's session; expect lists the accepted status codes. */
async function apiCall(page, method, path, data, expect = [200, 201, 202]) {
  const csrf = (await page.context().cookies()).find((c) => c.name === 'olympos_csrf')?.value ?? '';
  const res = await page.request.fetch(`${URL}/api/v1${path}`, { method, data, headers: { 'X-CSRF-Token': csrf } });
  if (!expect.includes(res.status())) throw new Error(`${method} ${path}: ${res.status()} ${(await res.text()).slice(0, 300)}`);
  const text = await res.text();
  return text ? JSON.parse(text) : {};
}

/** The lab cluster's discovered target of a service. */
async function labTargetAPI(page, service) {
  const t = (await apiCall(page, 'GET', '/targets')).items.find((x) => x.service === service && x.cluster_name === 'lab' && x.status !== 'gone');
  if (!t) throw new Error(`target ${service} not discovered`);
  return t;
}

/** The job of a lab target (created on lab-minio when there is none). */
async function ensureJobAPI(page, service, extra) {
  const target = await labTargetAPI(page, service);
  const jobs = (await apiCall(page, 'GET', '/backup/jobs')).items;
  const job = jobs.find((j) => j.target.id === target.id);
  if (job) return job.id;
  const dest = (await apiCall(page, 'GET', '/destinations')).items.find((d) => d.name === 'lab-minio');
  const j = await apiCall(page, 'POST', '/backup/jobs', { target_id: target.id, destination_id: dest.id, cron: '0 3 * * *', timezone: 'UTC', enabled: true, ...extra });
  return j.id;
}

/** Run now on a job through the API, then waits until that run has finished. */
async function runJobAPI(page, jobID, service) {
  const queued = await apiCall(page, 'POST', `/backup/jobs/${jobID}/run`, { trigger: 'manual' });
  const r = await waitRun(page, service, (x) => x.id === queued.id);
  if (r.status !== 'succeeded') throw new Error(`${service} run ended ${r.status}: ${r.error}`);
  return r;
}

/** Opens the details of a service's newest succeeded run and its Restore… dialog with the target chosen. */
async function openRestoreDialog(page, service, target) {
  await openRun(page, service, (rows) => rows.filter({ hasText: 'Succeeded' }).filter({ hasNotText: 'test' }));
  await page.getByRole('dialog').getByRole('button', { name: 'Restore…' }).click();
  const dlg = page.getByRole('dialog');
  await dlg.getByText(`Restore ${service} into a new target`).waitFor();
  await dlg.getByRole('combobox', { name: /^Target/ }).click();
  await page.getByRole('option', { name: new RegExp(`/ ${target}\\b`) }).click();
  return dlg;
}

async function checkTarget(dlg) {
  await dlg.getByRole('button', { name: 'Check target' }).click();
  await dlg.getByText('The target can take this restore.').waitFor({ timeout: 120_000 });
}

/** Submits the restore dialog and returns the request's id. */
async function submitRestore(page, dlg) {
  await dlg.getByRole('button', { name: /^(Submit for approval|Break-glass: start now)$/ }).click();
  await page.getByRole('dialog').getByRole('link', { name: 'Open request' }).click();
  await page.waitForURL(/restore=/);
  const id = new globalThis.URL(page.url()).searchParams.get('restore');
  if (!id) throw new Error('no restore request id');
  return id;
}

/** Waits until a restore request has ended; it must have succeeded. */
async function waitRestoreDone(page, id, timeout = 600_000) {
  const end = Date.now() + timeout;
  for (;;) {
    const rq = await apiCall(page, 'GET', `/restores/${id}`);
    if (rq.status === 'succeeded') return rq;
    if (!['pending', 'approved', 'running'].includes(rq.status)) throw new Error(`restore ${id} ended ${rq.status}: ${rq.error}`);
    if (Date.now() > end) throw new Error(`restore ${id} still ${rq.status}`);
    await page.waitForTimeout(3000);
  }
}

/** Runs SQL statements in a lab PostgreSQL target as its backup user (lab values). */
function labSQL(statefulset, statements) {
  for (const sql of statements)
    execFileSync('kubectl', ['--context', 'kind-olympos-lab', '-n', 'lab', 'exec', `statefulset/${statefulset}`, '--', 'psql', '-U', 'backup', '-d', 'orders', '-v', 'ON_ERROR_STOP=1', '-qc', sql], {
      env: { ...process.env, KUBECONFIG },
      stdio: ['ignore', 'ignore', 'inherit'],
    });
}

/** Runs ClickHouse statements in a lab ClickHouse target (lab values). */
function chSQL(deploy, user, password, statements) {
  for (const sql of statements)
    execFileSync('kubectl', ['--context', 'kind-olympos-lab', '-n', 'lab', 'exec', `deploy/${deploy}`, '--', 'clickhouse-client', '--user', user, '--password', password, '--query', sql], {
      env: { ...process.env, KUBECONFIG },
      stdio: ['ignore', 'ignore', 'inherit'],
    });
}

/** The lab's Azurite SAS from ENV.md (lab only: signed with Azurite's well-known key). */
function azuriteSas() {
  const sas = env.match(/^\s*SAS: (\S+)/m)?.[1];
  if (!sas) throw new Error('no Azurite SAS in test/e2e/.work/ENV.md: run ./test/e2e/env.sh');
  return sas;
}

/** kubectl in the lab cluster's olympos namespace. */
function lab(...args) {
  execFileSync('kubectl', ['--context', 'kind-olympos-lab', '-n', 'olympos', ...args], { env: { ...process.env, KUBECONFIG }, stdio: 'inherit' });
}

/** Takes the lab's Azurite off the network (a Service without endpoints) or puts it back. */
function azurite(on) {
  lab('patch', 'service', 'azurite', '--type', 'merge', '-p', JSON.stringify({ spec: { selector: { app: on ? 'azurite' : 'azurite-stopped' } } }));
}

/** Runs of one target, newest first, through the API (the page's session). */
async function runsOf(page, service) {
  const res = await page.request.get(`${URL}/api/v1/backup/runs?limit=20`);
  if (!res.ok()) throw new Error(`GET /backup/runs: ${res.status()}`);
  return (await res.json()).items.filter((r) => r.target_service === service && r.trigger !== 'test');
}

/** Waits for the newest run of service that matches pick and has finished. */
async function waitRun(page, service, pick, timeout = 240_000) {
  const end = Date.now() + timeout;
  for (;;) {
    const r = (await runsOf(page, service)).find(pick);
    if (r && !['queued', 'running'].includes(r.status)) return r;
    if (Date.now() > end) throw new Error(`no finished ${service} run: ${JSON.stringify(r ?? null)}`);
    await page.waitForTimeout(2000);
  }
}

/** Run now on a job, then waits until that run has finished. */
async function runJob(page, service, pick) {
  const before = new Set((await runsOf(page, service)).map((r) => r.id));
  await page.goto(`${URL}/backups?tab=jobs`);
  await page.getByRole('button', { name: `Run ${service} now` }).click();
  return waitRun(page, service, (r) => !before.has(r.id) && pick(r));
}

/** Opens the newest run of a target on the Runs tab that which() keeps. */
async function openRun(page, service, which) {
  await page.goto(`${URL}/backups?tab=runs`);
  const rows = page.getByRole('row', { name: new RegExp(`(Restore commands and details|Details) of the ${service} run`) });
  await which(rows).first().click();
  await page.getByRole('dialog').waitFor();
}

try {
  for (const [name, run] of Object.entries(stages)) {
    if (ONLY && !ONLY.includes(name)) continue;
    console.log(`== ${name}`);
    await run();
  }
} finally {
  await browser.close();
}
void vaultToken;
