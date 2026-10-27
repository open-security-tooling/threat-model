import { Store } from './store';
import { getPref, setPref } from './storage';

export type ThemeChoice = 'system' | 'light' | 'dark';

const media = typeof matchMedia === 'function' ? matchMedia('(prefers-color-scheme: dark)') : null;

function parse(v: string | null): ThemeChoice {
  return v === 'light' || v === 'dark' ? v : 'system';
}

class Theme extends Store {
  choice: ThemeChoice = parse(getPref('theme'));
  private systemDark = media?.matches ?? false;

  constructor() {
    super();
    media?.addEventListener('change', (e) => {
      this.systemDark = e.matches;
      this.emit();
    });
    this.apply();
  }

  get resolved(): 'light' | 'dark' {
    if (this.choice === 'system') return this.systemDark ? 'dark' : 'light';
    return this.choice;
  }

  set(choice: ThemeChoice) {
    this.choice = choice;
    setPref('theme', choice === 'system' ? null : choice);
    this.apply();
    this.emit();
  }

  private apply() {
    const root = document.documentElement;
    if (this.choice === 'system') delete root.dataset.theme;
    else root.dataset.theme = this.choice;
  }
}

export const theme = new Theme();
