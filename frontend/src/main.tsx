import { createRoot } from 'react-dom/client';
import App from './App';
import { startTheme } from './app/theme';
import './index.css';

startTheme();
createRoot(document.getElementById('root')!).render(<App />);
