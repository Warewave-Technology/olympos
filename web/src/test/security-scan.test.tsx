import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

afterEach(() => {
  cleanup();
  localStorage.removeItem('olympos.mock.noImages');
});

describe('Security › Scan now', () => {
  it('shows the 409 "nothing to scan" message as a warning, then disables the button with the reason', async () => {
    const { installMocks } = await import('../mocks/install');
    installMocks('1');
    window.history.pushState({}, '', '/security?cluster=all');
    const { router } = await import('../router');
    const { RouterProvider } = await import('@tanstack/react-router');
    const { ToastProvider } = await import('../ui/kit');
    const user = userEvent.setup();
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <ToastProvider>
          <RouterProvider router={router} />
        </ToastProvider>
      </QueryClientProvider>,
    );
    const button = await screen.findByRole('button', { name: 'Scan now' }, { timeout: 5000 });
    await waitFor(() => expect(screen.getAllByText(/payments-api|harbor|ghcr|acr/).length).toBeGreaterThan(0), { timeout: 5000 });
    expect(button).toBeEnabled();

    // The clusters went away between page load and the click: the server answers 409.
    localStorage.setItem('olympos.mock.noImages', '1');
    await user.click(button);
    const alert = await screen.findByText(/Nothing was scanned\./, {}, { timeout: 5000 });
    expect(alert.closest('[role="alert"]')).toHaveTextContent('No running images to scan yet. Add a cluster first');
    expect(screen.queryByText('Scan queued for all running images.')).toBeNull();

    // The image list is refetched (empty): disabled + reason, independent of permissions.
    await waitFor(() => expect(screen.getByRole('button', { name: 'Scan now' })).toBeDisabled(), { timeout: 5000 });
    expect(screen.getByRole('button', { name: 'Scan now' })).toHaveAccessibleDescription('No running images yet · add a cluster first');
  });
});
