// Settings › Synthetic monitoring (docs/design/settings-synthetic.html; docs/design/synthetic-monitoring.md §6.1,
// §6.2): the global host allowlist with "Check a host", the always-blocked note, and the credentials scenarios may
// use, with the exception notice. Admins (scope all) change both; editors and readers with scope all see them.
//
// A credential's secret is write-only: it lives only in its password input (DOM), never in React state, a query
// cache or a URL. It is read when the request leaves, dropped from the body once sent, and wiped when the dialog
// closes (the RestoreDialog pattern). Nothing ever shows it again.
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError, api } from '../../api/client';
import type { AllowKind, AllowRule, AllowRuleInput, Channel, CredentialKind, HostCheck, InUse, ItemList, SecretSource, SyntheticCredential, SyntheticCredentialInput } from '../../api/types';
import { useCan } from '../../auth/me';
import { daysUntil, plural, shortDate } from '../../lib/format';
import { CheckIcon, IconClose } from '../../ui/icons';
import { Badge, Chip, EmptyState, Field, FormError, Modal, Spinner, aria, fieldError, sentence, useAction, useToast, type Tone } from '../../ui/kit';
import { DataTable } from '../../ui/DataTable';
import { SettingsLayout } from './SettingsLayout';

// ------------------------------------------------------------ shared text

const KIND_LABEL: Record<AllowKind, string> = { exact: 'Exact', wildcard: 'Wildcard', suffix: 'Suffix' };
const KIND_TONE: Record<AllowKind, Tone> = { exact: 'ok', wildcard: 'mute', suffix: 'info' };

/** What a rule matches, in words (the mockup's "Matches" column). */
export function matchesText(kind: AllowKind, pattern: string): string {
  if (kind === 'suffix') return `${pattern} and every host under it`;
  if (kind === 'wildcard') {
    const base = pattern.replace(/^\*\./, '');
    return `any host under ${base}, not ${base} itself`;
  }
  return 'only this host';
}

/**
 * A bound host as people read it. The API returns {pattern, kind}; the stored and audited form is
 * "<kind>:<pattern>" (hostallow.FormatRule), which is read here too.
 */
export function boundLabel(b: { pattern: string; kind: string }): { text: string; title: string } {
  let { pattern, kind } = b;
  const m = /^(exact|wildcard|suffix):(.+)$/.exec(pattern);
  if (m) [, kind, pattern] = m;
  const k = (kind === 'wildcard' || kind === 'suffix' ? kind : 'exact') as AllowKind;
  return { text: k === 'suffix' ? `${pattern} (suffix)` : pattern, title: `${KIND_LABEL[k]}: ${matchesText(k, pattern)}` };
}

export const CRED_KIND_LABEL: Record<CredentialKind, string> = {
  bearer: 'Bearer token',
  basic: 'Basic',
  header: 'Header',
  oauth2_client_credentials: 'OAuth2 client credentials',
};

/** The secret field of each kind, and whether the kind has a user name (the login, or the OAuth2 client id). */
const SECRET_OF: Record<CredentialKind, { label: string; user?: string; userPh?: string }> = {
  bearer: { label: 'Token' },
  basic: { label: 'Password', user: 'Username', userPh: 'synthetic-monitor' },
  header: { label: 'Header value' },
  oauth2_client_credentials: { label: 'Client secret', user: 'Client ID', userPh: 'olympos-synthetic' },
};

/** credential_expiring fires 14 and 3 days before: from 14 days on, the badge warns. */
function expiry(c: SyntheticCredential, now = Date.now()): { text: string; tone: Tone | null } {
  if (!c.expires_at) return { text: c.kind === 'oauth2_client_credentials' ? 'token per run' : 'never', tone: null };
  const d = daysUntil(c.expires_at, now);
  if (c.expired || d === null || new Date(c.expires_at).getTime() <= now) return { text: 'expired', tone: 'crit' };
  const text = d < 1 ? 'today' : `in ${plural(d, 'day')}`;
  return { text, tone: d <= 14 ? 'warn' : 'ok' };
}

/** "Nov 21 · Selin A.": the date and who did it (created_by_name is the display-name snapshot). */
function byLine(at: string, name: string): string {
  const who = (name || '').trim();
  return who ? `${shortDate(at)} · ${who}` : shortDate(at);
}

/**
 * A 409 for something still in use (InUse): what needs it, by name. Other errors as usual. The server's sentence
 * already names them; the names are listed so they can be read (and copied) one by one.
 */
function InUseError({ error, lead }: { error: unknown; lead: string }) {
  const b = error instanceof ApiError && error.status === 409 ? (error.body as Partial<InUse> | undefined) : undefined;
  const scen = Array.isArray(b?.scenarios) ? b.scenarios : [];
  const creds = Array.isArray(b?.credentials) ? b.credentials : [];
  if (!scen.length && !creds.length) return <FormError error={error} />;
  return (
    <div className="note crit" role="alert">
      <b>{lead}</b>
      <ul className="note-list">
        {scen.length > 0 && (
          <li>
            {scen.length === 1 ? 'Scenario' : 'Scenarios'}: {scen.map((n) => <Chip key={n}>{n}</Chip>)}
          </li>
        )}
        {creds.length > 0 && (
          <li>
            {creds.length === 1 ? 'Credential' : 'Credentials'}: {creds.map((n) => <Chip key={n}>{n}</Chip>)}
          </li>
        )}
      </ul>
    </div>
  );
}

// ------------------------------------------------------------ page

export function SyntheticSettingsPage() {
  const canAdmin = useCan('admin_global');
  const canCheck = useCan('synthetic_edit');
  const chanQ = useQuery({ queryKey: ['channels'], queryFn: () => api.get<ItemList<Channel>>('/notifications/channels'), retry: false });
  const channel = chanQ.data?.items.find((c) => (c.routes as string[]).includes('synthetic.allowlist_changed'))?.name;
  return (
    <SettingsLayout current="synthetic" sub="Synthetic monitoring · which hosts probes may call and the credentials they may use">
      <AllowlistCard canAdmin={canAdmin} canCheck={canCheck} channel={channel} />
      <CredentialsCard canAdmin={canAdmin} />
    </SettingsLayout>
  );
}

// ------------------------------------------------------------ allowlist

function AllowlistCard({ canAdmin, canCheck, channel }: { canAdmin: boolean; canCheck: boolean; channel?: string }) {
  const q = useQuery({ queryKey: ['synthetic', 'allowlist'], queryFn: () => api.get<ItemList<AllowRule> & { version: number }>('/synthetic/allowlist') });
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<AllowRule | null>(null);
  return (
    <section className="card" aria-labelledby="al-t">
      <div className="card-head">
        <div className="head-text">
          <h2 id="al-t">Host allowlist</h2>
          <div className="desc">
            Global. A scenario step can only call a host that matches a rule here. Admins only; every change is {channel ? <>posted to <span className="mono">{channel}</span></> : 'recorded in the activity log'}.
          </div>
        </div>
        {canAdmin && (
          <button type="button" className="btn pri" onClick={() => setAdding(true)}>
            Add rule
          </button>
        )}
      </div>
      <DataTable
        label="Host allowlist"
        what="the host allowlist"
        rows={q.data?.items}
        loading={q.isPending}
        error={q.isError ? q.error : undefined}
        onRetry={() => q.refetch()}
        rowKey={(r) => r.id}
        pageSize={false}
        initialSort={null}
        empty={
          <EmptyState
            title="No rules yet"
            action={
              canAdmin ? (
                <button type="button" className="btn pri" onClick={() => setAdding(true)}>
                  Add rule
                </button>
              ) : undefined
            }
          >
            Probes cannot call any host until a rule allows it. {canAdmin ? 'Add one for the hosts your scenarios check.' : 'Ask an admin to add the hosts your scenarios check.'}
          </EmptyState>
        }
        columns={[
          {
            id: 'rule',
            header: 'Rule',
            sortValue: (r) => r.pattern,
            className: 'wrap',
            cell: (r) => (
              <>
                <span className="mono">{r.pattern}</span>
                {r.note && <div className="muted small">{r.note}</div>}
              </>
            ),
          },
          { id: 'kind', header: 'Type', sortValue: (r) => r.kind, cell: (r) => <Badge tone={KIND_TONE[r.kind]}>{KIND_LABEL[r.kind] ?? r.kind}</Badge> },
          { id: 'matches', header: 'Matches', className: 'wrap', cell: (r) => matchesText(r.kind, r.pattern) },
          { id: 'scenarios', header: 'Scenarios', align: 'num', sortValue: (r) => r.scenarios, defaultDir: 'desc', cell: (r) => r.scenarios },
          { id: 'added', header: 'Added', sortValue: (r) => r.created_at, defaultDir: 'desc', className: 'mono', cell: (r) => byLine(r.created_at, r.created_by_name) },
          {
            id: 'actions',
            header: 'Actions',
            srOnlyHeader: true,
            align: 'actions',
            hidden: !canAdmin,
            cell: (r) => (
              <button type="button" className="btn sm" onClick={() => setRemoving(r)} aria-label={`Remove rule ${r.pattern}`}>
                Remove
              </button>
            ),
          },
        ]}
      />
      <div className={`allow-foot${canCheck ? '' : ' single'}`}>
        {canCheck && <HostCheckBox />}
        <div className="note">
          Always blocked, whatever the rules say: IP literals, <span className="mono">localhost</span>, loopback, link-local and cloud metadata addresses (<span className="mono">169.254.169.254</span>), the Kubernetes API. The check runs on the hostname <b>and</b> on the resolved IP at connect time, and again on every redirect.
        </div>
      </div>
      {adding && <AddRuleDialog onClose={() => setAdding(false)} channel={channel} />}
      {removing && <RemoveRuleDialog rule={removing} onClose={() => setRemoving(null)} />}
    </section>
  );
}

/** "Check a host" (POST /synthetic/allowlist/check, editors and admins): which rule allows it, and the others that match too. */
function HostCheckBox() {
  const [text, setText] = useState('');
  const host = text.trim();
  const [debounced, setDebounced] = useState(host);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(host), 350);
    return () => clearTimeout(t);
  }, [host]);
  const q = useQuery({
    queryKey: ['synthetic', 'allowlist-check', debounced],
    queryFn: () => api.post<HostCheck>('/synthetic/allowlist/check', { host: debounced }),
    enabled: !!debounced,
    staleTime: 60_000,
    retry: false,
  });
  let result: ReactNode = null;
  if (host && (host !== debounced || q.isPending))
    result = (
      <>
        <Spinner label="Checking the allowlist" /> Checking {host}…
      </>
    );
  else if (host && q.isError) {
    // a 4xx says what is wrong with the input (422 on host); anything else is the server or the network
    const e = q.error;
    const msg = e instanceof ApiError && e.status >= 400 && e.status < 500 ? (fieldError(e, 'host') === 'required' ? 'Enter a host name, or a URL with one.' : sentence(fieldError(e, 'host') ?? e.message)) : null;
    result = msg ? (
      <>
        <CheckIcon ok={false} label="Not checked" />
        <span>{msg}</span>
      </>
    ) : (
      <span className="muted">Could not check the host now.</span>
    );
  }
  else if (host && q.data) {
    const h = q.data;
    result =
      h.allowed && h.rule ? (
        <>
          <CheckIcon ok label="Allowed" />
          <span>
            Allowed by <span className="mono">{h.rule.pattern}</span>
            {h.also.length > 0 && (
              <>
                {' '}
                (also{' '}
                {h.also.map((r, i) => (
                  <span key={r.id}>
                    {i > 0 && ', '}
                    <span className="mono">{r.pattern}</span>
                  </span>
                ))}
                )
              </>
            )}
          </span>
        </>
      ) : (
        <>
          <CheckIcon ok={false} label="Not allowed" />
          <span>
            <span className="mono">{h.host || host}</span> · {h.denied_reason === 'no_rule' || !h.message ? 'no rule matches' : h.message}
          </span>
        </>
      );
  }
  return (
    <div>
      <label className="lbl" htmlFor="al-check">
        Check a host
      </label>
      <input id="al-check" className="in mono" value={text} onChange={(e) => setText(e.target.value)} placeholder="api.prod.wrw.com" autoComplete="off" spellCheck={false} aria-describedby="al-check-res" />
      <div className="chk" id="al-check-res" role="status" aria-live="polite" style={{ marginTop: 6, minHeight: 20 }}>
        {result ?? <span className="muted small">Type a host name or a URL to see which rule allows it.</span>}
      </div>
    </div>
  );
}

function AddRuleDialog({ onClose, channel }: { onClose: () => void; channel?: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [pattern, setPattern] = useState('');
  const [kind, setKind] = useState<AllowKind>('exact');
  const [note, setNote] = useState('');
  const [local, setLocal] = useState<Record<string, string>>({});
  const ref = useRef<HTMLInputElement>(null);
  const add = useMutation({
    mutationFn: (b: AllowRuleInput) => api.post<AllowRule>('/synthetic/allowlist', b),
    onSuccess: (r) => {
      toast(`Added the ${r.kind} rule ${r.pattern}.`);
      void qc.invalidateQueries({ queryKey: ['synthetic'] });
      onClose();
    },
  });
  // Typing "*." picks wildcard: it is the only kind that pattern can be.
  const onPattern = (v: string) => {
    setPattern(v);
    if (v.trim().startsWith('*.')) setKind('wildcard');
  };
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const p = pattern.trim();
    const er: Record<string, string> = {};
    if (!p) er.pattern = 'Enter a host name.';
    else if (kind === 'wildcard' && !p.startsWith('*.')) er.pattern = 'A wildcard rule starts with *. (for example *.dev.wrw.com).';
    else if (kind !== 'wildcard' && p.includes('*')) er.pattern = 'Only a wildcard rule has a *. Choose Wildcard, or remove the *.';
    setLocal(er);
    if (Object.keys(er).length) {
      ref.current?.focus();
      return;
    }
    add.mutate({ pattern: p, kind, note: note.trim() });
  };
  const fe = (n: string) => local[n] ?? fieldError(add.error, n);
  const preview = pattern.trim() ? matchesText(kind, pattern.trim().toLowerCase()) : null;
  const opts: { k: AllowKind; t2: string }[] = [
    { k: 'exact', t2: 'That host only.' },
    { k: 'wildcard', t2: 'Any host under the name, at any depth, but not the name itself. Write *.dev.wrw.com.' },
    { k: 'suffix', t2: 'The name and every host under it. Never notwrw.com or wrw.com.evil.io: matching is by whole labels.' },
  ];
  return (
    <Modal open onClose={onClose} eyebrow="Host allowlist" title="Add a rule" description="Probes may call a host only when a rule matches it. Matching is on the lower-cased host name, by whole DNS labels." initialFocus={ref} closeOnBackdrop={!pattern && !note}>
      <form onSubmit={submit} className="stack-sm" style={{ gap: 18 }} noValidate>
        <Field label="Host" htmlFor="ar-pattern" error={fe('pattern')} hint={preview ? `Matches ${preview}.` : 'For example partner-sftp.acme.net, *.dev.wrw.com or wrw.com.'}>
          <input ref={ref} className="in mono" {...aria('ar-pattern', fe('pattern'), true)} value={pattern} onChange={(e) => onPattern(e.target.value)} autoComplete="off" spellCheck={false} placeholder="*.dev.wrw.com" />
        </Field>
        <fieldset className="opts" aria-describedby={fe('kind') ? 'ar-kind-err' : undefined}>
          <legend className="lbl">Type</legend>
          {opts.map((o) => (
            <label className="opt" key={o.k}>
              <input type="radio" name="ar-kind" checked={kind === o.k} onChange={() => setKind(o.k)} />
              <span>
                <span className="t1">{KIND_LABEL[o.k]}</span>
                <span className="t2">{o.t2}</span>
              </span>
            </label>
          ))}
          {fe('kind') && (
            <div className="field-error" id="ar-kind-err" role="alert">
              {fe('kind')}
            </div>
          )}
        </fieldset>
        <Field label="Note (optional)" htmlFor="ar-note" error={fe('note')}>
          <input className="in" {...aria('ar-note', fe('note'))} value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} placeholder="What these hosts are, or a ticket" />
        </Field>
        <FormError error={add.error && !fieldError(add.error, 'pattern') && !fieldError(add.error, 'kind') && !fieldError(add.error, 'note') ? add.error : null} />
        <div className="note">{channel ? <>This change is posted to <span className="mono">{channel}</span> and recorded in the activity log.</> : 'This change is recorded in the activity log and emits synthetic.allowlist_changed.'}</div>
        <div className="end">
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn pri" disabled={add.isPending}>
            Add rule
          </button>
        </div>
      </form>
    </Modal>
  );
}

function RemoveRuleDialog({ rule, onClose }: { rule: AllowRule; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const remove = useMutation({
    mutationFn: () => api.del(`/synthetic/allowlist/${rule.id}`),
    onSuccess: () => {
      toast(`Removed the rule ${rule.pattern}.`);
      void qc.invalidateQueries({ queryKey: ['synthetic'] });
      onClose();
    },
  });
  return (
    <Modal open onClose={onClose} size="narrow" danger eyebrow="Host allowlist" title={`Remove the rule ${rule.pattern}?`} description={<>It matches {matchesText(rule.kind, rule.pattern)}. A rule that a scenario or a credential still needs cannot be removed.</>}>
      <div className="stack-sm" style={{ gap: 18 }}>
        {rule.scenarios > 0 && !remove.error && (
          <div className="note">
            {plural(rule.scenarios, 'scenario')} {rule.scenarios === 1 ? 'reaches' : 'reach'} a host this rule matches. Removing it is refused if no other rule allows {rule.scenarios === 1 ? 'that host' : 'those hosts'}.
          </div>
        )}
        <InUseError error={remove.error} lead="This rule is still needed. Change these first:" />
        <div className="end">
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="btn danger" onClick={() => remove.mutate()} disabled={remove.isPending}>
            Remove rule
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ------------------------------------------------------------ credentials

function CredentialsCard({ canAdmin }: { canAdmin: boolean }) {
  const q = useQuery({ queryKey: ['synthetic', 'credentials'], queryFn: () => api.get<ItemList<SyntheticCredential>>('/synthetic/credentials') });
  // undefined: closed; null: a new credential
  const [editing, setEditing] = useState<SyntheticCredential | null | undefined>(undefined);
  return (
    <section className="card" aria-labelledby="cr-t">
      <div className="card-head">
        <div className="head-text">
          <h2 id="cr-t">Credentials</h2>
          <div className="desc">Stored encrypted in Olympos (or as a Key Vault reference). Values are never shown again.</div>
        </div>
        {canAdmin && (
          <button type="button" className="btn pri" onClick={() => setEditing(null)}>
            New credential
          </button>
        )}
      </div>
      <DataTable
        label="Credentials"
        what="credentials"
        rows={q.data?.items}
        loading={q.isPending}
        error={q.isError ? q.error : undefined}
        onRetry={() => q.refetch()}
        rowKey={(c) => c.id}
        pageSize={false}
        initialSort={{ id: 'name', dir: 'asc' }}
        onRowClick={canAdmin ? (c) => setEditing(c) : undefined}
        rowLabel={(c) => `Edit credential ${c.name}`}
        empty={
          <EmptyState
            title="No credentials yet"
            action={
              canAdmin ? (
                <button type="button" className="btn pri" onClick={() => setEditing(null)}>
                  New credential
                </button>
              ) : undefined
            }
          >
            A scenario step can send a bearer token, a basic login, a header or an OAuth2 client credential, attached only to the hosts it is bound to.
          </EmptyState>
        }
        columns={[
          {
            id: 'name',
            header: 'Name',
            sortValue: (c) => c.name,
            cell: (c) => (
              <>
                {canAdmin ? (
                  <button type="button" className="link-btn mono" onClick={() => setEditing(c)} aria-label={`Edit credential ${c.name}`}>
                    {c.name}
                  </button>
                ) : (
                  <span className="mono">{c.name}</span>
                )}
                {c.source === 'keyvault_ref' && <div className="muted small">Key Vault reference</div>}
                {c.resolve_failures_24h > 0 && (
                  <div className="hint-line ico-warn cred-warn">
                    <CheckIcon ok={false} warn label="Warning" />
                    <span>Could not be read {plural(c.resolve_failures_24h, 'time')} in 24 h; check the Key Vault reference or secret</span>
                  </div>
                )}
              </>
            ),
          },
          {
            id: 'kind',
            header: 'Type',
            sortValue: (c) => CRED_KIND_LABEL[c.kind] ?? c.kind,
            className: 'wrap',
            style: { minWidth: 120 },
            cell: (c) => (
              <>
                {CRED_KIND_LABEL[c.kind] ?? c.kind}
                {c.kind === 'header' && c.header_name && <span className="mono muted"> {c.header_name}</span>}
              </>
            ),
          },
          {
            id: 'hosts',
            header: 'Bound to hosts',
            className: 'wrap',
            searchText: (c) => c.bound_hosts.map((b) => b.pattern).join(' '),
            cell: (c) =>
              c.bound_hosts.map((b) => {
                const l = boundLabel(b);
                return (
                  <span key={`${b.kind}:${b.pattern}`} className="chip" title={l.title}>
                    {l.text}
                  </span>
                );
              }),
          },
          {
            id: 'scenarios',
            header: 'Scenarios',
            align: 'num',
            sortValue: (c) => c.scenarios.length,
            defaultDir: 'desc',
            cell: (c) => <span title={c.scenarios.map((s) => s.name).join(', ') || undefined}>{c.scenarios.length}</span>,
          },
          { id: 'rotated', header: 'Rotated', sortValue: (c) => c.rotated_at ?? c.created_at, defaultDir: 'desc', className: 'mono', cell: (c) => shortDate(c.rotated_at ?? c.created_at) },
          {
            id: 'expires',
            header: 'Expires',
            sortValue: (c) => c.expires_at,
            cell: (c) => {
              const x = expiry(c);
              return x.tone ? <Badge tone={x.tone}>{x.text}</Badge> : <span className="muted">{x.text}</span>;
            },
          },
        ]}
      />
      <div className="note warn card-note">
        This is an exception to “credentials never enter a cluster”: a credential is sent to the probe for one run, kept in memory only, and attached only to requests whose host matches the hosts it is bound to. It is dropped on redirects to other hosts and redacted from stored responses. Use dedicated, read-only monitoring accounts.
      </div>
      {editing !== undefined && <CredentialDialog key={editing?.id ?? 'new'} cred={editing ?? undefined} onClose={() => setEditing(undefined)} />}
    </section>
  );
}

const KV_RE = /^[a-zA-Z0-9-]{3,24}$/;
const SECRET_RE = /^[a-zA-Z0-9-]{1,127}$/;

/** yyyy-mm-dd of a timestamp, in local time (for <input type="date">). */
function dateInput(iso: string | null): string {
  if (!iso) return '';
  const d = new Date(iso);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

type BoundRow = { pattern: string; kind: AllowKind };

/** New credential, or edit one (metadata, and the secret only when it is rotated). */
function CredentialDialog({ cred, onClose }: { cred?: SyntheticCredential; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const editing = !!cred;
  const [name, setName] = useState(cred?.name ?? '');
  const [kind, setKind] = useState<CredentialKind>(cred?.kind ?? 'bearer');
  const [header, setHeader] = useState(cred?.header_name ?? '');
  const [tokenUrl, setTokenUrl] = useState(cred?.oauth_token_url ?? '');
  const [scopes, setScopes] = useState(cred?.oauth_scopes ?? '');
  const [bound, setBound] = useState<BoundRow[]>(cred ? cred.bound_hosts.map((b) => ({ pattern: b.pattern, kind: b.kind })) : [{ pattern: '', kind: 'exact' }]);
  const [expires, setExpires] = useState(dateInput(cred?.expires_at ?? null));
  const [rotate, setRotate] = useState(!editing);
  const [source, setSource] = useState<SecretSource>(cred?.source ?? 'stored');
  const [username, setUsername] = useState('');
  const [kvName, setKvName] = useState('');
  const [secretName, setSecretName] = useState('');
  const [errs, setErrs] = useState<Record<string, string>>({});
  const [deleting, setDeleting] = useState(false);
  const [dirty, setDirty] = useState(false);
  const secretRef = useRef<HTMLInputElement | null>(null);
  const nameRef = useRef<HTMLInputElement>(null);
  const save = useAction<SyntheticCredential>();
  const del = useMutation({
    mutationFn: () => api.del(`/synthetic/credentials/${cred!.id}`),
    onSuccess: () => {
      toast(`Deleted the credential ${cred!.name} and its secret.`);
      void qc.invalidateQueries({ queryKey: ['synthetic', 'credentials'] });
      close();
    },
  });
  const touch = () => setDirty(true);
  const wipe = () => {
    if (secretRef.current) secretRef.current.value = '';
  };
  const close = () => {
    wipe();
    onClose();
  };
  // A callback ref: React calls it with null when the secret input leaves the DOM (rotation turned off, source
  // switched, the dialog closed or unmounted), and the value is wiped right then.
  const secretInput = useCallback((el: HTMLInputElement | null) => {
    if (!el && secretRef.current) secretRef.current.value = '';
    secretRef.current = el;
  }, []);

  const sec = SECRET_OF[kind];
  const validate = (): Record<string, string> => {
    const e: Record<string, string> = {};
    if (!name.trim()) e.name = 'Enter a name.';
    if (!bound.some((b) => b.pattern.trim())) e.bound_hosts = 'Add at least one host the credential may be sent to.';
    bound.forEach((b, i) => {
      const p = b.pattern.trim();
      if (p && b.kind === 'wildcard' && !p.startsWith('*.')) e[`bound_hosts.${i}`] = 'A wildcard starts with *. (for example *.dev.wrw.com).';
      else if (p && b.kind !== 'wildcard' && p.includes('*')) e[`bound_hosts.${i}`] = 'Only a wildcard has a *.';
    });
    if (kind === 'header' && !header.trim()) e.header_name = 'Enter the header name, for example X-Api-Key.';
    if (kind === 'oauth2_client_credentials' && !/^https:\/\//i.test(tokenUrl.trim())) e.oauth_token_url = 'Enter the https:// token URL. It must be allowlisted and inside the bound hosts.';
    // the API refuses a past expiry on create and on update: it would mean nothing
    // An unchanged date keeps the stored timestamp (see the body below), which may be later today: check that one.
    const keptExpiry = !!cred?.expires_at && expires === dateInput(cred.expires_at);
    const expiryAt = keptExpiry ? new Date(cred!.expires_at!).getTime() : new Date(`${expires}T00:00:00`).getTime();
    if (expires && expiryAt <= Date.now()) e.expires_at = 'Choose a date in the future, or leave it empty.';
    if (rotate) {
      if (sec.user && !username.trim()) e['secret.username'] = `Enter the ${sec.user.toLowerCase()}.`;
      if (source === 'keyvault_ref') {
        if (!KV_RE.test(kvName.trim())) e['secret.ref'] = 'Key Vault names are 3–24 letters, digits and dashes.';
        else if (!SECRET_RE.test(secretName.trim())) e.secretName = 'Secret names use letters, digits and dashes.';
      } else if (!secretRef.current?.value) e['secret.password'] = `Enter the ${sec.label.toLowerCase()}.`;
    }
    return e;
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const v = validate();
    setErrs(v);
    if (Object.keys(v).length) {
      if (v.name) nameRef.current?.focus();
      return;
    }
    const body: SyntheticCredentialInput = {
      name: name.trim(),
      kind,
      bound_hosts: bound.filter((b) => b.pattern.trim()).map((b) => ({ pattern: b.pattern.trim(), kind: b.kind })),
      header_name: kind === 'header' ? header.trim() : '',
      oauth_token_url: kind === 'oauth2_client_credentials' ? tokenUrl.trim() : '',
      oauth_scopes: kind === 'oauth2_client_credentials' ? scopes.trim() : '',
      // an unchanged date keeps the stored time; a new one is the start of that day, local time
      expires_at: !expires ? null : cred?.expires_at && expires === dateInput(cred.expires_at) ? cred.expires_at : new Date(`${expires}T00:00:00`).toISOString(),
    };
    if (rotate) {
      const user = sec.user ? { username: username.trim() } : {};
      body.secret = source === 'keyvault_ref' ? { source, ref: `kv://${kvName.trim()}/${secretName.trim()}`, ...user } : { source, ...user, password: secretRef.current?.value ?? '' };
    }
    const r = await save.run(() => (editing ? api.put<SyntheticCredential>(`/synthetic/credentials/${cred!.id}`, body) : api.post<SyntheticCredential>('/synthetic/credentials', body)));
    // The secret leaves the body as soon as the request is sent.
    if (body.secret) body.secret.password = undefined;
    if (!r) return;
    wipe();
    toast(editing ? (rotate ? `Saved ${r.name} with a new secret. It is not shown again.` : `Saved ${r.name}.`) : `Created ${r.name}. Its secret is stored and not shown again.`);
    void qc.invalidateQueries({ queryKey: ['synthetic', 'credentials'] });
    void qc.invalidateQueries({ queryKey: ['synthetic', 'allowlist'] });
    onClose();
  };

  const fe = (n: string) => errs[n] ?? fieldError(save.error, n);
  const shown = new Set(['name', 'kind', 'bound_hosts', 'header_name', 'oauth_token_url', 'oauth_scopes', 'expires_at', 'secret', 'secret.source', 'secret.username', 'secret.password', 'secret.ref']);
  const unshownField = save.error instanceof ApiError && Object.keys(save.error.fields).some((k) => !shown.has(k) && !k.startsWith('bound_hosts.'));
  const setRow = (i: number, p: Partial<BoundRow>) => {
    setBound((rows) => rows.map((r, j) => (j === i ? { ...r, ...p } : r)));
    touch();
  };

  return (
    <Modal
      open
      onClose={close}
      size="wide"
      eyebrow="Synthetic credential"
      title={editing ? `Edit ${cred!.name}` : 'New credential'}
      description="Scenario steps attach it only to requests whose host matches its bound hosts. The value is write-only: it is never shown again."
      initialFocus={nameRef}
      closeOnBackdrop={!dirty}
    >
      <form onSubmit={submit} className="stack-sm" style={{ gap: 18 }} noValidate>
        <div className="grid-2">
          <Field label="Name" htmlFor="cr-name" error={fe('name')}>
            <input
              ref={nameRef}
              className="in mono"
              {...aria('cr-name', fe('name'))}
              value={name}
              onChange={(e) => {
                setName(e.target.value);
                touch();
              }}
              placeholder="catalog-monitor"
              autoComplete="off"
              spellCheck={false}
            />
          </Field>
          <Field label="Type" htmlFor="cr-kind" error={fe('kind')} hint={editing ? 'The type of a credential cannot change.' : undefined}>
            <select
              className="in"
              {...aria('cr-kind', fe('kind'), editing)}
              value={kind}
              disabled={editing}
              onChange={(e) => {
                setKind(e.target.value as CredentialKind);
                touch();
              }}
            >
              {(Object.keys(CRED_KIND_LABEL) as CredentialKind[]).map((k) => (
                <option key={k} value={k}>
                  {CRED_KIND_LABEL[k]}
                </option>
              ))}
            </select>
          </Field>
        </div>
        {kind === 'header' && (
          <Field label="Header name" htmlFor="cr-header" error={fe('header_name')} hint="The request header that carries the value. Host, Cookie and the framing headers cannot.">
            <input
              className="in mono"
              {...aria('cr-header', fe('header_name'), true)}
              value={header}
              onChange={(e) => {
                setHeader(e.target.value);
                touch();
              }}
              placeholder="X-Api-Key"
              autoComplete="off"
              spellCheck={false}
            />
          </Field>
        )}

        <fieldset className="plain" aria-describedby={fe('bound_hosts') ? 'cr-bound-err' : 'cr-bound-hint'}>
          <legend className="lbl">Bound to hosts</legend>
          <div className="stack-sm">
            {bound.map((b, i) => {
              const err = fe(`bound_hosts.${i}`);
              return (
                <div key={i}>
                  <div className="bound-row">
                    <input
                      className="in mono"
                      aria-label={`Bound host ${i + 1}`}
                      aria-invalid={err ? true : undefined}
                      aria-describedby={err ? `cr-bound-${i}-err` : undefined}
                      value={b.pattern}
                      onChange={(e) => setRow(i, { pattern: e.target.value, ...(e.target.value.trim().startsWith('*.') ? { kind: 'wildcard' as const } : {}) })}
                      placeholder={i === 0 ? '*.prod.wrw.com' : 'login.acme.net'}
                      autoComplete="off"
                      spellCheck={false}
                    />
                    <select className="in" aria-label={`Bound host ${i + 1} type`} value={b.kind} onChange={(e) => setRow(i, { kind: e.target.value as AllowKind })}>
                      {(Object.keys(KIND_LABEL) as AllowKind[]).map((k) => (
                        <option key={k} value={k}>
                          {KIND_LABEL[k]}
                        </option>
                      ))}
                    </select>
                    <button
                      type="button"
                      className="btn icon"
                      aria-label={`Remove bound host ${i + 1}`}
                      disabled={bound.length === 1}
                      onClick={() => {
                        setBound((rows) => rows.filter((_, j) => j !== i));
                        touch();
                      }}
                    >
                      <IconClose />
                    </button>
                  </div>
                  {err && (
                    <div className="field-error" id={`cr-bound-${i}-err`} role="alert">
                      {err}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          <div className="spread" style={{ marginTop: 8 }}>
            {fe('bound_hosts') ? (
              <div className="field-error" id="cr-bound-err" role="alert">
                {fe('bound_hosts')}
              </div>
            ) : (
              <div className="field-hint" id="cr-bound-hint" style={{ marginTop: 0 }}>
                Each must be inside the host allowlist. The credential is dropped on a redirect to any other host.
              </div>
            )}
            <button
              type="button"
              className="btn sm"
              disabled={bound.length >= 20}
              onClick={() => {
                setBound((rows) => [...rows, { pattern: '', kind: 'exact' }]);
                touch();
              }}
            >
              Add host
            </button>
          </div>
        </fieldset>

        {kind === 'oauth2_client_credentials' && (
          <div className="grid-2">
            <Field label="Token URL" htmlFor="cr-token" error={fe('oauth_token_url')} hint="https, allowlisted and inside the bound hosts: the client secret is sent to it.">
              <input
                className="in mono"
                {...aria('cr-token', fe('oauth_token_url'), true)}
                value={tokenUrl}
                onChange={(e) => {
                  setTokenUrl(e.target.value);
                  touch();
                }}
                placeholder="https://login.acme.net/oauth2/token"
                autoComplete="off"
                spellCheck={false}
              />
            </Field>
            <Field label="Scopes (optional)" htmlFor="cr-scopes" error={fe('oauth_scopes')}>
              <input
                className="in mono"
                {...aria('cr-scopes', fe('oauth_scopes'))}
                value={scopes}
                onChange={(e) => {
                  setScopes(e.target.value);
                  touch();
                }}
                placeholder="sftp.read"
                autoComplete="off"
                spellCheck={false}
              />
            </Field>
          </div>
        )}

        <fieldset className="plain">
          <legend className="lbl">Secret</legend>
          {editing && (
            <div className="secret-state">
              <span>
                {cred!.source === 'keyvault_ref' ? 'A Key Vault reference' : 'Stored encrypted in Olympos'}
                {cred!.rotated_at ? `, rotated ${shortDate(cred!.rotated_at)}` : `, set ${shortDate(cred!.created_at)}`}. The value is never shown again.
              </span>
              <label className="chk">
                <input
                  type="checkbox"
                  checked={rotate}
                  onChange={(e) => {
                    setRotate(e.target.checked);
                    if (!e.target.checked) wipe();
                    touch();
                  }}
                />
                Rotate the secret
              </label>
            </div>
          )}
          {rotate && (
            <div className="stack-sm" style={{ gap: 14 }}>
              <div className="inline" role="radiogroup" aria-label="Where the secret is kept">
                <label className="chk">
                  <input
                    type="radio"
                    name="cr-src"
                    checked={source === 'stored'}
                    onChange={() => {
                      setSource('stored');
                      touch();
                    }}
                  />
                  Stored in Olympos (encrypted)
                </label>
                <label className="chk">
                  <input
                    type="radio"
                    name="cr-src"
                    checked={source === 'keyvault_ref'}
                    onChange={() => {
                      wipe();
                      setSource('keyvault_ref');
                      touch();
                    }}
                  />
                  Key Vault reference
                </label>
              </div>
              <div className={source === 'keyvault_ref' ? (sec.user ? 'grid-3' : 'grid-2') : sec.user ? 'grid-2' : undefined}>
                {sec.user && (
                  <Field label={sec.user} htmlFor="cr-user" error={fe('secret.username')} hint={editing ? `Needed again with a new secret: the API never returns the ${sec.user.toLowerCase()}.` : undefined}>
                    <input
                      className="in mono"
                      {...aria('cr-user', fe('secret.username'), editing)}
                      value={username}
                      onChange={(e) => {
                        setUsername(e.target.value);
                        touch();
                      }}
                      placeholder={sec.userPh}
                      autoComplete="off"
                      spellCheck={false}
                    />
                  </Field>
                )}
                {source === 'keyvault_ref' ? (
                  <>
                    <Field label="Key Vault" htmlFor="cr-kv" error={fe('secret.ref')}>
                      <input
                        className="in mono"
                        {...aria('cr-kv', fe('secret.ref'))}
                        value={kvName}
                        onChange={(e) => {
                          setKvName(e.target.value);
                          touch();
                        }}
                        placeholder="kv-olympos-weu"
                        autoComplete="off"
                        spellCheck={false}
                      />
                    </Field>
                    <Field label={`Secret name (holds the ${sec.label.toLowerCase()})`} htmlFor="cr-sec" error={fe('secretName')}>
                      <input
                        className="in mono"
                        {...aria('cr-sec', fe('secretName'))}
                        value={secretName}
                        onChange={(e) => {
                          setSecretName(e.target.value);
                          touch();
                        }}
                        placeholder={`${name.trim() || 'synthetic'}-secret`}
                        autoComplete="off"
                        spellCheck={false}
                      />
                    </Field>
                  </>
                ) : (
                  <Field label={sec.label} htmlFor="cr-secret" error={fe('secret.password')} hint="Sent over TLS, stored encrypted, never shown again.">
                    <input ref={secretInput} className="in mono" type="password" {...aria('cr-secret', fe('secret.password'), true)} onChange={touch} autoComplete="off" data-1p-ignore="true" data-lpignore="true" spellCheck={false} />
                  </Field>
                )}
              </div>
            </div>
          )}
          {fe('secret') && (
            <div className="field-error" role="alert">
              {fe('secret')}
            </div>
          )}
        </fieldset>

        <Field label="Expires (optional)" htmlFor="cr-exp" error={fe('expires_at')} hint="synthetic.credential_expiring is sent 14 and 3 days before. Leave empty for no expiry.">
          <input
            className="in mono"
            type="date"
            {...aria('cr-exp', fe('expires_at'), true)}
            value={expires}
            onChange={(e) => {
              setExpires(e.target.value);
              touch();
            }}
            style={{ maxWidth: 220 }}
          />
        </Field>

        {save.error instanceof ApiError && save.error.status === 409 ? (
          <InUseError error={save.error} lead="These bound hosts would break scenarios that use this credential. Change these first:" />
        ) : (
          <FormError error={save.error && (!(save.error instanceof ApiError) || Object.keys(save.error.fields).length === 0 || unshownField) ? save.error : null} />
        )}
        {deleting && (
          <div className="note crit" role="group" aria-label="Delete credential">
            <div className="stack-sm">
              <span>
                Delete <span className="mono">{cred!.name}</span> and its secret? This cannot be undone. A credential that a scenario still uses cannot be deleted.
              </span>
              <InUseError error={del.error} lead="This credential is still used. Change these first:" />
              <div className="end">
                <button type="button" className="btn sm" onClick={() => setDeleting(false)}>
                  Keep it
                </button>
                <button type="button" className="btn sm danger" onClick={() => del.mutate()} disabled={del.isPending}>
                  Delete credential
                </button>
              </div>
            </div>
          </div>
        )}
        <div className="foot-actions">
          {editing && !deleting ? (
            <button
              type="button"
              className="btn danger"
              onClick={() => {
                del.reset();
                setDeleting(true);
              }}
            >
              Delete
            </button>
          ) : (
            <span />
          )}
          <div className="inline">
            <button type="button" className="btn" onClick={close}>
              Cancel
            </button>
            <button type="submit" className="btn pri" disabled={save.pending}>
              {editing ? 'Save credential' : 'Create credential'}
            </button>
          </div>
        </div>
      </form>
    </Modal>
  );
}
