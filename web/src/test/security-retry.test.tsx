import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { Image } from '../api/types';
import * as db from '../mocks/db';
import { ScanStatusCell } from '../pages/Security';
import { renderApp } from './renderApp';

afterEach(() => {
  cleanup();
  localStorage.removeItem('olympos.mock.role');
});
const T = { timeout: 5000 };

const base: Image = { digest: 'sha256:aa', repo: 'docker.io/x/y', tags: ['1'], clusters: 1, workloads: 1, critical: 0, high: 0, medium: 0, low: 0, scan_status: 'failed', last_scanned_at: null };

describe('scan status cell', () => {
  it('says why a scan failed and when it is retried', () => {
    const at = new Date();
    at.setHours(14, 5, 0, 0);
    render(<ScanStatusCell i={{ ...base, scan_attempts: 2, next_retry_at: at.toISOString(), scan_error: 'registry answered 503 Service Unavailable' }} now={new Date(at.getTime() - 60_000)} />);
    expect(screen.getByText('Scan failed · retry 2/5 at 14:05')).toBeInTheDocument();
    expect(screen.getByText('registry answered 503 Service Unavailable')).toHaveAttribute('title', 'registry answered 503 Service Unavailable');
  });
  it('explains unavailable and missing credential', () => {
    render(
      <>
        <ScanStatusCell i={{ ...base, scan_status: 'unavailable' }} />
      </>,
    );
    expect(screen.getByText('Not in registry')).toHaveAttribute('title', expect.stringMatching(/locally or retagged.*kind/));
    expect(screen.getByText('Locally built or retagged image')).toBeInTheDocument();
  });
});

describe('Security › images', () => {
  it('keeps Kyverno/NetworkPolicy summaries out of the Images tab', async () => {
    await renderApp('/security');
    await screen.findByRole('table', { name: 'Images' }, T);
    expect(screen.queryByText('Top Kyverno violations')).toBeNull();
    expect(screen.queryByText('Namespaces without default-deny')).toBeNull();
  });

  it('offers Retry for failed/unavailable/missing-credential images and posts a rescan', async () => {
    const user = userEvent.setup();
    await renderApp('/security');
    // spy on top of the mock API (installed by renderApp)
    const posts: string[] = [];
    const orig = window.fetch;
    window.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if ((init?.method ?? 'GET') === 'POST') posts.push(url);
      return orig(input, init);
    }) as typeof fetch;
    const table = await screen.findByRole('table', { name: 'Images' }, T);
    await user.click(screen.getByRole('combobox', { name: 'Scan status' }));
    await user.click(screen.getByRole('option', { name: /Not scanned/ }));
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBeGreaterThan(1));
    // every row in this view is retryable
    const retry = within(table).getAllByRole('button', { name: /^Retry scan of / });
    expect(retry.length).toBe(within(table).getAllByRole('row').length - 1);
    expect(within(table).queryByRole('button', { name: /^Scan docker/ })).toBeNull();

    const failed = db.images.find((i) => i.scan_status === 'failed')!;
    const name = failed.tags.length ? `${failed.repo}:${failed.tags[0]}` : failed.repo;
    // find it through the search hook-in
    await user.type(screen.getByLabelText('Search images'), failed.digest);
    const btn = await within(table).findByRole('button', { name: `Retry scan of ${name}` }, T);
    await user.click(btn);
    await waitFor(() => expect(posts.some((u) => u.endsWith(`/images/${encodeURIComponent(failed.digest)}/scan`))).toBe(true), T);
    expect(await screen.findByText(`Retry queued for ${name}.`, {}, T)).toBeInTheDocument();
    window.fetch = orig;
  });

  it('hides Retry and Scan now for viewers', async () => {
    localStorage.setItem('olympos.mock.role', 'viewer');
    await renderApp('/security');
    const table = await screen.findByRole('table', { name: 'Images' }, T);
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBeGreaterThan(1));
    expect(within(table).queryByRole('button', { name: /^(Retry scan of|Scan) / })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Scan now' })).toBeNull();
  });
});
