// The reviewer lens: extra detail for security teams. A per-browser
// preference, never written to the model file.
import { Store } from './store';
import { getPref, setPref } from './storage';

class Lens extends Store {
  reviewer = getPref('reviewer') === 'on';

  setReviewer(on: boolean) {
    this.reviewer = on;
    setPref('reviewer', on ? 'on' : null);
    this.emit();
  }
}

export const lens = new Lens();
