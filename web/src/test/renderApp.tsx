import { render } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

let installed = false;

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
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <ToastProvider>
        <RouterProvider router={router} />
      </ToastProvider>
    </QueryClientProvider>,
  );
}
