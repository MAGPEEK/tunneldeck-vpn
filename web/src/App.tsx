import { QueryClientProvider, type QueryClient } from '@tanstack/react-query';
import { I18nextProvider } from 'react-i18next';
import { BrowserRouter } from 'react-router';
import { i18n } from './i18n';
import { SessionGate } from './session/SessionGate';

export interface AppProps {
  queryClient: QueryClient;
}

export function App({ queryClient }: AppProps) {
  return (
    <I18nextProvider i18n={i18n}>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <SessionGate />
        </BrowserRouter>
      </QueryClientProvider>
    </I18nextProvider>
  );
}
