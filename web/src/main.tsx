import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@xyflow/react/dist/style.css';
import './app.css';
import './components.css';
import { App } from './App';

const target = document.getElementById('app');
if (target) {
  createRoot(target).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
