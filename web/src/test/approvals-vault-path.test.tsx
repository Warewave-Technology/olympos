import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen } from '@testing-library/react';
import * as db from '../mocks/db';
import { renderApp } from './renderApp';

afterEach(cleanup);
const T = { timeout: 5000 };

describe('approvals vault path', () => {
  // The API names a change request's vault "namespace/service"; the path must
  // read cluster / namespace / service, not cluster / namespace / namespace/service.
  it('shows the namespace once', async () => {
    const v = db.vaults[0].target;
    expect(db.changeRequests[0].vault.name).toBe(`${v.namespace}/${v.service}`);
    renderApp('/approvals');
    await screen.findAllByText(new RegExp(`${v.cluster_name} / ${v.namespace} / ${v.service}`), {}, T);
    expect(screen.queryByText(new RegExp(`${v.namespace}/${v.service}`))).toBeNull();
  });
});
