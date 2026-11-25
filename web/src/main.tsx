import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { createQueryClient } from './session/queryClient';
import { applyTheme, readStoredTheme } from './theme/theme';
import './styles/tokens.css';
import './styles/base.css';

applyTheme(readStoredTheme());

const root = document.getElementById('root');
if (!root) {
  throw new Error('root element missing');
}

createRoot(root).render(
  <StrictMode>
    <App queryClient={createQueryClient()} />
  </StrictMode>,
);
