import { Store } from './store';
import type { FormSection } from './forms';

export interface FormRequest {
  section: FormSection;
  /** Edit this item; omitted to create a new one. */
  id?: string;
  /** Initial values for a new item, in file form. */
  preset?: Record<string, unknown>;
  /** A new fix is also added to this threat's list of fixes. */
  linkToThreat?: string;
}

class Dialogs extends Store {
  form: FormRequest | null = null;
  /** Where focus goes back to when the dialog closes. */
  private returnFocus: HTMLElement | null = null;

  openForm(req: FormRequest) {
    this.returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    this.form = req;
    this.emit();
  }

  closeForm() {
    this.form = null;
    this.emit();
    const el = this.returnFocus;
    this.returnFocus = null;
    if (el?.isConnected) setTimeout(() => el.focus(), 0);
  }
}

export const dialogs = new Dialogs();
