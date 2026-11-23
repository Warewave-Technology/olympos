import type { ChangeRequest, Me, Permission, Role } from '../api/types';

/** True when the signed-in user has the permission anywhere in scope. Unknown → false (hide). */
export function can(me: Me | null | undefined, perm: Permission): boolean {
  return Boolean(me?.permissions?.[perm]);
}

const ORDER: Role[] = ['admin', 'operator', 'vault-maker', 'vault-approver', 'viewer'];

/**
 * The roles for the sidebar footer ("admin · Entra ID", "operator, vault-approver · Entra ID"). Roles are not
 * ordered (operator and vault-approver allow different things), so every role is shown; admin includes all
 * the others and viewer is implied by any of them, so those are left out.
 */
export function primaryRole(me: Me | null | undefined): string {
  const roles = me?.roles ?? [];
  if (roles.includes('admin')) return 'admin';
  const shown = ORDER.filter((r) => roles.includes(r) && r !== 'viewer');
  if (shown.length > 0) return shown.join(', ');
  return roles.includes('viewer') ? 'viewer' : 'no role';
}

export function isSelf(me: Me | null | undefined, p: { tenant_id?: string; object_id?: string } | null | undefined): boolean {
  if (!me || !p) return false;
  const tenantOk = !p.tenant_id || !me.principal.tenant_id || p.tenant_id.toLowerCase() === me.principal.tenant_id.toLowerCase();
  return tenantOk && !!p.object_id && p.object_id.toLowerCase() === me.principal.object_id.toLowerCase();
}

export type ControlState = { visible: false } | { visible: true; enabled: true } | { visible: true; enabled: false; reason: string };

/**
 * Approve/Reject on a change request. Controls a role does not allow are hidden,
 * EXCEPT Approve on one's own request: shown disabled with the reason (SPEC §15).
 * The server decides `can_approve`; the UI never enables what the server refuses.
 */
export function approveControl(me: Me | null | undefined, cr: ChangeRequest): ControlState {
  if (cr.status !== 'pending') return { visible: false };
  if (isSelf(me, cr.maker)) {
    return { visible: true, enabled: false, reason: cr.approve_disabled_reason || 'You opened this request. Another approver must decide.' };
  }
  if (!can(me, 'vault_approve')) return { visible: false };
  if (cr.can_approve) return { visible: true, enabled: true };
  if (cr.approve_disabled_reason) return { visible: true, enabled: false, reason: cr.approve_disabled_reason };
  return { visible: false };
}

/** Reject follows the same rule as approve, but is never shown on one's own request (use Cancel). */
export function rejectControl(me: Me | null | undefined, cr: ChangeRequest): boolean {
  if (cr.status !== 'pending' || isSelf(me, cr.maker)) return false;
  return can(me, 'vault_approve') && cr.can_approve;
}

/** Roles a guest account may never hold (SPEC §3.2; openapi: vault-approver/admin refused for guests). */
export const GUEST_FORBIDDEN_ROLES: Role[] = ['vault-approver', 'admin'];
