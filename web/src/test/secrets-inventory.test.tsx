import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen, within } from '@testing-library/react';
import { renderApp } from './renderApp';
import * as db from '../mocks/db';

afterEach(cleanup);
const T = { timeout: 5000 };

describe('Security › Kubernetes secrets', () => {
  it('lists names and key names on a cluster with the inventory on', async () => {
    const c = db.clusters.find((x) => x.name === 'prod-aks-weu-01')!;
    renderApp(`/security?cluster=${c.id}&tab=secrets`);
    const card = await screen.findByRole('region', { name: 'Kubernetes secrets' }, T);
    const table = await within(card).findByRole('table', {}, T);
    expect(within(table).getByText('stripe-legacy')).toBeTruthy();
    expect(within(table).getByText('api_key')).toBeTruthy();
    expect(within(table).getByText('Legacy SA token')).toBeTruthy();
    expect(within(card).getByText(/Olympos does not delete Secrets/)).toBeTruthy();
  });

  it('explains how to enable it, and the risk, on a cluster without it', async () => {
    const c = db.clusters.find((x) => x.name === 'eks-fra-data')!;
    renderApp(`/security?cluster=${c.id}&tab=secrets`);
    const card = await screen.findByRole('region', { name: 'Kubernetes secrets' }, T);
    expect(await within(card).findByText(/secretsInventory.enabled=true/, {}, T)).toBeTruthy();
    expect(within(card).getByText(/stolen agent token could read values/)).toBeTruthy();
    expect(within(card).queryByRole('table')).toBeNull();
  });
});
