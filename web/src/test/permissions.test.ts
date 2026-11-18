import { describe, expect, it } from 'vitest';
import type { ChangeRequest, Me, Permissions } from '../api/types';
import { approveControl, can, isSelf, primaryRole, rejectControl } from '../auth/permissions';

const TENANT = 't-1';
function me(perms: Partial<Permissions>, oid = 'me-oid', roles: Me['roles'] = ['viewer']): Me {
  return {
    principal: { id: 'p', tenant_id: TENANT, object_id: oid, upn: 'me@contoso.com', display_name: 'Me', user_type: 'Member', account_enabled: true },
    is_guest: false,
    roles,
    grants: [],
    permissions: { read: true, operate: false, operate_global: false, vault_make: false, vault_approve: false, admin: false, admin_global: false, ...perms },
    dev_mode: false,
  };
}
function cr(makerOid: string, p: Partial<ChangeRequest> = {}): ChangeRequest {
  return {
    id: 'cr1',
    vault: { id: 'v', name: 'vault', cluster_name: 'c', provider: 'hashicorp' },
    maker: { id: 'x', tenant_id: TENANT, object_id: makerOid, upn: '', display_name: '', user_type: '', account_enabled: true },
    checker: null,
    justification: '',
    status: 'pending',
    created_at: '',
    expires_at: '',
    decided_at: null,
    decision_comment: '',
    applied_at: null,
    failure: '',
    can_approve: true,
    approve_disabled_reason: '',
    can_cancel: false,
    items: [],
    events: [],
    ...p,
  };
}

describe('permission gating', () => {
  it('can() is false for unknown users and missing permissions', () => {
    expect(can(null, 'admin')).toBe(false);
    expect(can(undefined, 'read')).toBe(false);
    expect(can(me({}), 'operate')).toBe(false);
    expect(can(me({ operate: true }), 'operate')).toBe(true);
  });

  it('primaryRole picks the highest role', () => {
    expect(primaryRole(me({}, 'x', ['viewer', 'operator']))).toBe('operator');
    expect(primaryRole(me({}, 'x', ['vault-maker', 'admin']))).toBe('admin');
    expect(primaryRole(null)).toBe('no role');
  });

  it('isSelf compares tenant + object ID, case-insensitively', () => {
    expect(isSelf(me({}, 'ABC'), { tenant_id: TENANT, object_id: 'abc' })).toBe(true);
    expect(isSelf(me({}, 'abc'), { tenant_id: 'other', object_id: 'abc' })).toBe(false);
  });

  it('Approve is hidden for users without vault-approver', () => {
    expect(approveControl(me({ vault_make: true }), cr('someone-else'))).toEqual({ visible: false });
    expect(rejectControl(me({ vault_make: true }), cr('someone-else'))).toBe(false);
  });

  it('Approve is enabled for an approver on someone else’s request', () => {
    expect(approveControl(me({ vault_approve: true }), cr('someone-else'))).toEqual({ visible: true, enabled: true });
    expect(rejectControl(me({ vault_approve: true }), cr('someone-else'))).toBe(true);
  });

  it('Approve on one’s own request is shown DISABLED with the reason — even for admins', () => {
    const own = cr('me-oid', { can_approve: false, approve_disabled_reason: 'You opened this request' });
    const admin = me({ vault_approve: true, admin: true, admin_global: true }, 'me-oid', ['admin', 'vault-approver']);
    expect(approveControl(admin, own)).toEqual({ visible: true, enabled: false, reason: 'You opened this request' });
    expect(rejectControl(admin, own)).toBe(false);
    // even if the server wrongly says can_approve, the UI never enables it for the maker
    expect(approveControl(admin, { ...own, can_approve: true })).toMatchObject({ visible: true, enabled: false });
  });

  it('Approve is hidden once the request is decided', () => {
    expect(approveControl(me({ vault_approve: true }), cr('x', { status: 'applied' }))).toEqual({ visible: false });
  });

  it('server-side refusal with a reason is shown disabled', () => {
    expect(approveControl(me({ vault_approve: true }), cr('x', { can_approve: false, approve_disabled_reason: 'Out of your scope' }))).toEqual({
      visible: true,
      enabled: false,
      reason: 'Out of your scope',
    });
  });
});
