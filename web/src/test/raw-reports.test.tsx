import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import * as db from '../mocks/db';
import { renderApp } from './renderApp';

afterEach(() => {
  cleanup();
  localStorage.removeItem('olympos.mock.role');
  db.auditSettings.raw_destination = null;
});
const T = { timeout: 5000 };

describe('raw audit reports destination', () => {
  // It was a settings key you could only set with SQL; Audit › Raw reports sets it.
  it('a global admin chooses and clears it', async () => {
    const user = userEvent.setup();
    renderApp('/audit');
    const card = await screen.findByRole('region', { name: 'Raw reports' }, T);
    expect(within(card).getByText('Not stored')).toBeTruthy();
    await user.click(within(card).getByRole('button', { name: 'Choose a destination' }));
    const picker = within(card).getByRole('combobox', { name: 'Raw reports destination' });
    await waitFor(() => expect((picker as HTMLButtonElement).disabled).toBe(false), T);
    await user.click(picker);
    await user.click((await screen.findAllByRole('option', {}, T))[0]);
    await user.click(within(card).getByRole('button', { name: 'Save' }));
    expect(await within(card).findByText(/^Stored on/, {}, T)).toBeTruthy();
    const chosen = db.destinations.find((d) => d.id === db.auditSettings.raw_destination?.id);
    expect(chosen && within(card).getByText(chosen.name)).toBeTruthy();

    await user.click(within(card).getByRole('button', { name: 'Change' }));
    await user.click(within(card).getByRole('button', { name: 'Stop storing' }));
    expect(await within(card).findByText('Not stored', {}, T)).toBeTruthy();
    expect(db.auditSettings.raw_destination).toBeNull();
  });

  it('a viewer sees where reports go but cannot change it', async () => {
    db.auditSettings.raw_destination = { id: db.destinations[0].id, name: db.destinations[0].name, kind: db.destinations[0].kind };
    localStorage.setItem('olympos.mock.role', 'viewer');
    renderApp('/audit');
    const card = await screen.findByRole('region', { name: 'Raw reports' }, T);
    expect(await within(card).findByText(/^Stored on/, {}, T)).toBeTruthy();
    expect(within(card).getByText(db.destinations[0].name)).toBeTruthy();
    expect(within(card).queryByRole('button')).toBeNull();
  });
});
