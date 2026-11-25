import { render } from '@testing-library/react';
import { App } from '../App';
import { createQueryClient } from '../session/queryClient';
import { mockFetch, type MockRoutes } from './fetchMock';

export const SIGNED_IN = { setupRequired: false, authenticated: true, username: 'admin' };
export const SIGNED_OUT = { setupRequired: false, authenticated: false, username: '' };
export const NEEDS_SETUP = { setupRequired: true, authenticated: false, username: '' };

export function renderApp(routes: MockRoutes, path = '/') {
  window.history.replaceState(null, '', path);
  const fetchMock = mockFetch(routes);
  const queryClient = createQueryClient();
  render(<App queryClient={queryClient} />);
  return { fetchMock, queryClient };
}
