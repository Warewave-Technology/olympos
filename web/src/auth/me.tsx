import { createContext, useContext, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { Me, Permission } from '../api/types';
import { can } from './permissions';

const MeCtx = createContext<Me | null>(null);

export const meQueryKey = ['me'] as const;

export function useMeQuery() {
  return useQuery({ queryKey: meQueryKey, queryFn: () => api.get<Me>('/me'), staleTime: 60_000, retry: false });
}

export function MeProvider({ me, children }: { me: Me; children: ReactNode }) {
  return <MeCtx.Provider value={me}>{children}</MeCtx.Provider>;
}

/** The signed-in user. Only valid inside the authenticated app layout. */
export function useMe(): Me {
  const me = useContext(MeCtx);
  if (!me) throw new Error('useMe outside MeProvider');
  return me;
}

export function useCan(perm: Permission): boolean {
  return can(useContext(MeCtx), perm);
}

/** Renders children only when the permission is held: controls a role does not allow are hidden. */
export function Can({ perm, children }: { perm: Permission; children: ReactNode }) {
  return useCan(perm) ? <>{children}</> : null;
}
