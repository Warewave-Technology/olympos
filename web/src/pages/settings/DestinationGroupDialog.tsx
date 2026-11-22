// Settings › Destinations › Groups: a backup job can write to a group, and one dump
// then goes to every member in order (docs/design/destination-groups.md).
import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { Destination, DestinationGroup, DestinationGroupInput, ItemList } from '../../api/types';
import { useCan } from '../../auth/me';
import { plural } from '../../lib/format';
import { DataTable } from '../../ui/DataTable';
import { GroupName, KIND_LABEL, KindBadge } from '../../ui/destinations';
import { IconArrowDown, IconArrowUp, IconClose } from '../../ui/icons';
import { Badge, EmptyState, Field, FormError, Modal, aria, fieldError, useAction, useToast } from '../../ui/kit';
import { Select } from '../../ui/Select';

const MIN_MEMBERS = 2;
const MAX_MEMBERS = 4;

const groupsQuery = { queryKey: ['destination-groups'], queryFn: () => api.get<ItemList<DestinationGroup>>('/destination-groups') };

/** Why a group cannot be deleted. */
const inUse = (jobs: number) => `Used by ${plural(jobs, 'job')}. Move ${jobs === 1 ? 'it' : 'them'} first.`;

/** Members in order: "1 [Azure Blob] blob-weu-backups → 2 [S3] minio-factory". */
export function GroupMembers({ group }: { group: Pick<DestinationGroup, 'members'> }) {
  return (
    <span className="member-path">
      {group.members.map((m, i) => (
        <span key={m.id} className="inline-sm">
          {i > 0 && (
            <span className="muted" aria-hidden="true">
              →
            </span>
          )}
          <span className="muted">{i + 1}</span>
          <KindBadge kind={m.kind} />
          <span className="mono">{m.name}</span>
        </span>
      ))}
    </span>
  );
}

/** The Groups card of Settings › Destinations: list, create, edit, delete (admins). */
export function DestinationGroupsCard() {
  const canAdmin = useCan('admin_global');
  const q = useQuery(groupsQuery);
  const [editing, setEditing] = useState<DestinationGroup | 'new' | null>(null);
  const [deleting, setDeleting] = useState<DestinationGroup | null>(null);
  const newButton = canAdmin && (
    <button type="button" className="btn pri" onClick={() => setEditing('new')}>
      New group
    </button>
  );
  return (
    <section className="card" aria-labelledby="grp-t">
      <div className="card-head">
        <div>
          <h2 id="grp-t">Groups</h2>
          <div className="desc">A backup job can write to a group. One dump goes to every member, in the order shown.</div>
        </div>
        {newButton}
      </div>
      <DataTable
        label="Destination groups"
        what="destination groups"
        rows={q.data?.items}
        loading={q.isPending}
        error={q.isError ? q.error : undefined}
        onRetry={() => q.refetch()}
        rowKey={(g) => g.id}
        initialSort={{ id: 'name', dir: 'asc' }}
        empty={
          <EmptyState title="No groups yet" action={newButton || undefined}>
            Group two to four destinations, of any kind, to keep every backup in more than one place: a job that writes to a group sends one dump to each member.
          </EmptyState>
        }
        columns={[
          {
            id: 'name',
            header: 'Name',
            sortValue: (g) => g.name,
            searchText: (g) => `${g.name} ${g.description} ${g.members.map((m) => m.name).join(' ')}`,
            className: 'wrap',
            style: { minWidth: 120 },
            cell: (g) => (
              <>
                <GroupName name={g.name} />
                {g.description && <div className="muted small">{g.description}</div>}
              </>
            ),
          },
          { id: 'members', header: 'Members', className: 'wrap', cell: (g) => <GroupMembers group={g} /> },
          { id: 'jobs', header: 'Used by', sortValue: (g) => g.jobs, defaultDir: 'desc', cell: (g) => plural(g.jobs, 'job') },
          {
            id: 'actions',
            header: 'Actions',
            srOnlyHeader: true,
            align: 'actions',
            hidden: !canAdmin,
            cell: (g) => (
              <>
                <button type="button" className="btn sm" onClick={() => setEditing(g)} aria-label={`Edit ${g.name}`}>
                  Edit
                </button>
                <button
                  type="button"
                  className="btn sm"
                  onClick={() => setDeleting(g)}
                  aria-label={`Delete ${g.name}`}
                  disabled={g.jobs > 0}
                  title={g.jobs > 0 ? inUse(g.jobs) : undefined}
                  aria-describedby={g.jobs > 0 ? `g-del-why-${g.id}` : undefined}
                >
                  Delete
                </button>
                {g.jobs > 0 && (
                  <span id={`g-del-why-${g.id}`} className="sr-only">
                    {inUse(g.jobs)}
                  </span>
                )}
              </>
            ),
          },
        ]}
      />
      <div className="card-foot">Every run writes each member and verifies each copy by size and hash. A missing copy is retried by repair runs 5 minutes, 30 minutes and 2 hours later, inside the job&apos;s retry window; they write only to that destination, and the original run stays Partial as the record.</div>
      {canAdmin && editing && <DestinationGroupDialog key={editing === 'new' ? 'new' : editing.id} group={editing === 'new' ? undefined : editing} onClose={() => setEditing(null)} />}
      {canAdmin && deleting && <DeleteGroupDialog group={deleting} onClose={() => setDeleting(null)} />}
    </section>
  );
}

function DeleteGroupDialog({ group, onClose }: { group: DestinationGroup; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const del = useAction<boolean>();
  const doDelete = async () => {
    const ok = await del.run(async () => {
      await api.del(`/destination-groups/${group.id}`);
      return true;
    });
    if (ok) {
      void qc.invalidateQueries({ queryKey: ['destination-groups'] });
      void qc.invalidateQueries({ queryKey: ['destinations'] });
      toast(`Deleted group ${group.name}.`);
      onClose();
    }
  };
  return (
    <Modal open onClose={onClose} size="narrow" danger eyebrow="Delete group" eyebrowTone="crit" title={`Delete ${group.name}?`}>
      <p className="muted small" style={{ margin: 0 }}>
        Only the group is removed. The member destinations and the backups stored on them stay.
      </p>
      <FormError error={del.error} />
      <div className="end">
        <button type="button" className="btn" onClick={onClose} data-autofocus>
          Keep it
        </button>
        <button type="button" className="btn danger" onClick={() => void doDelete()} disabled={del.pending}>
          {del.pending ? 'Deleting…' : 'Delete group'}
        </button>
      </div>
    </Modal>
  );
}

/** Create or edit a destination group: name, description and 2–4 ordered members. */
export function DestinationGroupDialog({ group, onClose }: { group?: DestinationGroup; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const editing = !!group;
  const [name, setName] = useState(group?.name ?? '');
  const [description, setDescription] = useState(group?.description ?? '');
  const [members, setMembers] = useState<string[]>(group?.members.map((m) => m.id) ?? []);
  const [pick, setPick] = useState('');
  const save = useAction<DestinationGroup>();
  const destQ = useQuery({ queryKey: ['destinations'], queryFn: () => api.get<ItemList<Destination>>('/destinations') });

  // Names and kinds: the destination list, falling back to what the group read carries.
  const known = new Map<string, { name: string; kind: Destination['kind'] }>();
  for (const m of group?.members ?? []) known.set(m.id, { name: m.name, kind: m.kind });
  for (const d of destQ.data?.items ?? []) known.set(d.id, { name: d.name, kind: d.kind });
  const original = new Set(group?.members.map((m) => m.id) ?? []);
  const available = (destQ.data?.items ?? []).filter((d) => !members.includes(d.id));
  const full = members.length >= MAX_MEMBERS;
  const countErr = members.length > 0 && (members.length < MIN_MEMBERS || members.length > MAX_MEMBERS) ? `A group needs ${MIN_MEMBERS} to ${MAX_MEMBERS} destinations` : undefined;
  const fe = (n: string) => fieldError(save.error, n);
  const membersErr = countErr ?? fe('member_ids');
  const valid = name.trim() !== '' && members.length >= MIN_MEMBERS && members.length <= MAX_MEMBERS;

  const add = () => {
    if (!pick || full || members.includes(pick)) return;
    setMembers((ms) => [...ms, pick]);
    setPick('');
  };
  const move = (i: number, by: -1 | 1) =>
    setMembers((ms) => {
      const out = [...ms];
      [out[i], out[i + by]] = [out[i + by], out[i]];
      return out;
    });
  const remove = (id: string) => setMembers((ms) => ms.filter((x) => x !== id));

  const body = (): DestinationGroupInput => {
    const full: DestinationGroupInput = { name: name.trim(), description: description.trim(), member_ids: members };
    if (!group) return full;
    const out: DestinationGroupInput = {};
    if (full.name !== group.name) out.name = full.name;
    if (full.description !== (group.description ?? '')) out.description = full.description;
    if (members.join() !== group.members.map((m) => m.id).join()) out.member_ids = members;
    return out;
  };

  const doSave = async () => {
    if (!valid) return;
    const b = body();
    if (group && Object.keys(b).length === 0) {
      onClose();
      return;
    }
    const r = await save.run(() => (group ? api.patch<DestinationGroup>(`/destination-groups/${group.id}`, b) : api.post<DestinationGroup>('/destination-groups', b)));
    if (!r) return;
    void qc.invalidateQueries({ queryKey: ['destination-groups'] });
    void qc.invalidateQueries({ queryKey: ['destinations'] });
    toast(group ? `Saved group ${r.name}.` : `Created group ${r.name}.`);
    onClose();
  };

  return (
    <Modal
      open
      onClose={onClose}
      size="wide"
      eyebrow={editing ? 'Edit group' : 'New group'}
      title={editing ? <span className="mono">{group!.name}</span> : 'New destination group'}
      description={editing ? 'Jobs that use this group write to every destination below.' : 'Pick two to four destinations. You can reorder them later.'}
    >
      <form
        className="stack"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          void doSave();
        }}
      >
        <div className="grid-2">
          <Field label="Name" htmlFor="g-name" error={fe('name')}>
            <input className="in mono" {...aria('g-name', fe('name'))} value={name} onChange={(e) => setName(e.target.value)} placeholder="eu-offsite" maxLength={80} spellCheck={false} autoComplete="off" data-autofocus />
          </Field>
          <Field label="Description" htmlFor="g-desc" error={fe('description')}>
            <input className="in" {...aria('g-desc', fe('description'))} value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional" maxLength={500} autoComplete="off" />
          </Field>
        </div>

        <div>
          <div className="spread" style={{ marginBottom: 6 }}>
            <span className="lbl" style={{ margin: 0 }} id="g-members">
              Destinations, in order
            </span>
            <span className="muted small">
              {members.length} of {MAX_MEMBERS}
            </span>
          </div>
          {members.length > 0 && (
            <ol className="members" aria-labelledby="g-members" aria-describedby={membersErr ? 'g-members-err' : 'g-members-hint'}>
              {members.map((id, i) => {
                const d = known.get(id);
                const label = d?.name ?? id;
                return (
                  <li key={id} className={`gm${editing && !original.has(id) ? ' new' : ''}`}>
                    <span className="pos" aria-hidden="true">
                      {i + 1}
                    </span>
                    <span className="nm">
                      <span className="mono">{label}</span> {d && <KindBadge kind={d.kind} />}
                      {editing && !original.has(id) && (
                        <>
                          {' '}
                          <Badge tone="warn">New</Badge>
                        </>
                      )}
                    </span>
                    <div className="ctl">
                      <button type="button" className="btn sm ic" aria-label={`Move ${label} up`} disabled={i === 0} onClick={() => move(i, -1)}>
                        <IconArrowUp />
                      </button>
                      <button type="button" className="btn sm ic" aria-label={`Move ${label} down`} disabled={i === members.length - 1} onClick={() => move(i, 1)}>
                        <IconArrowDown />
                      </button>
                      <button type="button" className="btn sm ic" aria-label={`Remove ${label}`} onClick={() => remove(id)}>
                        <IconClose />
                      </button>
                    </div>
                  </li>
                );
              })}
            </ol>
          )}
          <div className="inline" style={{ marginTop: members.length ? 10 : 0 }}>
            <div style={{ flex: '1 1 220px', minWidth: 0 }}>
              <Select
                aria-label="Add destination"
                mono
                value={pick}
                onChange={setPick}
                placeholder={destQ.isPending ? 'Loading destinations…' : full ? 'A group has at most four destinations' : available.length ? 'Add a destination…' : 'No other destinations'}
                options={available.map((d) => ({ value: d.id, label: d.name, hint: KIND_LABEL[d.kind], text: d.name }))}
                disabled={full || available.length === 0}
              />
            </div>
            <button type="button" className="btn" onClick={add} disabled={!pick || full}>
              Add
            </button>
          </div>
          {destQ.isError && <FormError error={destQ.error} />}
          {membersErr ? (
            <div className="field-error" id="g-members-err" role="alert">
              {membersErr}
            </div>
          ) : (
            <div className="field-hint" id="g-members-hint">
              Two to four destinations, any kind. The first one is the default copy to restore from.
            </div>
          )}
        </div>

        {editing && <div className="note">Existing backups are not copied to a destination you add; only new runs write to it.</div>}
        {editing && group!.jobs > 0 && <div className="note warn">This change affects {plural(group!.jobs, 'backup job')}.</div>}
        <FormError error={save.error} />

        <div className="end">
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn pri" disabled={!valid || save.pending}>
            {save.pending ? 'Saving…' : editing ? 'Save group' : 'Create group'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
