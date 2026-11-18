import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen, within } from '@testing-library/react';
import { renderApp } from './renderApp';

afterEach(cleanup);
const T = { timeout: 5000 };

describe('Security › Sensitive data', () => {
  it('lists ConfigMap keys with the rule and the fix, never a value', async () => {
    renderApp('/security?cluster=all&tab=sensitive');
    const card = await screen.findByRole('region', { name: 'Sensitive data in ConfigMaps' }, T);
    const table = await within(card).findByRole('table', {}, T);
    expect(within(table).getByText('AWS_ACCESS_KEY_ID')).toBeTruthy();
    expect(within(table).getByText('DB_PASSWORD')).toBeTruthy();
    expect(within(table).getAllByText('High · pattern').length).toBeGreaterThan(0);
    expect(within(table).getByText('Medium · key name')).toBeTruthy();
    expect(within(card).getByText(/move this value to a Secret or Vault/i)).toBeTruthy();
    expect(screen.getByRole('tab', { name: /Sensitive data/ })).toBeTruthy();
  });
});
