import { render } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

let installed = false;
/** The query client of the last renderApp call (tests that check what the caches hold). */
export let lastQueryClient: QueryClient | null = null;

/** Renders the whole SPA against the mock API at `path`, with a fresh router per call. */
export async function renderApp(path: string) {
  if (!installed) {
    const { installMocks } = await import('../mocks/install');
    installMocks('1');
    installed = true;
  }
  window.history.pushState({}, '', path);
  const { routeTree } = await import('../router');
  const { RouterProvider, createRouter, createBrowserHistory } = await import('@tanstack/react-router');
  const { ToastProvider } = await import('../ui/kit');
  const router = createRouter({ routeTree, history: createBrowserHistory() });
  lastQueryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={lastQueryClient}>
      <ToastProvider>
        <RouterProvider router={router} />
      </ToastProvider>
    </QueryClientProvider>,
  );
}
