import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen, within } from '@testing-library/react';
import { renderApp } from './renderApp';

afterEach(cleanup);
const T = { timeout: 5000 };

// F10: no empty cells: last pull / last delivery show a result or "Not yet".
describe('last results', () => {
  it('registries show the last pull, or Not yet', async () => {
    renderApp('/settings/registries');
    const acr = (await screen.findByText('acr.contoso.io', {}, T)).closest('tr')!;
    expect(within(acr).getByText('OK')).toBeTruthy();
    const quay = screen.getByText('quay.io/legacy/*').closest('tr')!;
    expect(within(quay).getByText('Not yet')).toBeTruthy();
  });
  it('channels show the last delivery, or Not yet', async () => {
    renderApp('/settings/notifications');
    const ok = (await screen.findByText('#infra-backups', {}, T)).closest('tr')!;
    expect(within(ok).getByText('Delivered')).toBeTruthy();
    const bad = screen.getByText('#vault-approvals').closest('tr')!;
    expect(within(bad).getByText('Failed')).toBeTruthy();
    expect(within(bad).getByText('slack: not_in_channel')).toBeTruthy();
    expect(within(screen.getByText('#infra-audit').closest('tr')!).getByText('Not yet')).toBeTruthy();
  });
});
