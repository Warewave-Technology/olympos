// Docs tour: walks through Olympos in the kind lab the way a new user would
// and saves a screenshot at every step, for README.md and docs/getting-started.md.
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
  await page.getByText('STEP 1 OF 4').waitFor();
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
    await page
      .getByRole('button', { name: /lab · Vault/ })
      .or(page.getByText('lab · Vault'))
      .first()
      .click();
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
    await page.getByText('lab · Vault').first().click();
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
    await page.getByText('lab · Vault').first().click();
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
};

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
