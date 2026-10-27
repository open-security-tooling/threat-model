import { Store } from './store';

class Palette extends Store {
  isOpen = false;
  private returnFocus: HTMLElement | null = null;

  open() {
    if (this.isOpen) return;
    this.returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    this.isOpen = true;
    this.emit();
  }

  close() {
    if (!this.isOpen) return;
    this.isOpen = false;
    this.emit();
    const el = this.returnFocus;
    this.returnFocus = null;
    // A command may move focus itself (e.g. open a form); only restore if it didn't.
    setTimeout(() => {
      if (el?.isConnected && (document.activeElement === document.body || !document.activeElement)) el.focus();
    }, 0);
  }

  toggle() {
    if (this.isOpen) this.close();
    else this.open();
  }
}

export const palette = new Palette();
