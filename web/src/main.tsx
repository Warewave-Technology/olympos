import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import '@fontsource/inter/400.css';
import '@fontsource/inter/500.css';
import '@fontsource/inter/600.css';
import '@fontsource/inter/700.css';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import '@fontsource/space-grotesk/700.css';
import './styles/tokens.css';
import './styles/app.css';
import { ApiError } from './api/client';
import { router } from './router';
import { ToastProvider } from './ui/kit';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      refetchOnWindowFocus: true,
      retry: (count, err) => {
        if (err instanceof ApiError && err.status >= 400 && err.status < 500) return false;
        return count < 2;
      },
    },
    mutations: { retry: false },
  },
});

async function start() {
  // Dev-only fixtures. `import.meta.env.VITE_MOCK` is replaced at build time, so in a
  // production build this branch (and the mocks chunk) is removed entirely.
  if (import.meta.env.VITE_MOCK) {
    const { installMocks } = await import('./mocks/install');
    installMocks(import.meta.env.VITE_MOCK);
  }
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <RouterProvider router={router} />
        </ToastProvider>
      </QueryClientProvider>
    </StrictMode>,
  );
}

void start();
