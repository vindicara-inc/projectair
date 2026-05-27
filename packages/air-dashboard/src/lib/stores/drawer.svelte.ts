/**
 * Drawer store — controls the detail drawer visibility and content.
 *
 * The drawer opens when a user selects a finding for deep inspection,
 * displaying the translated incident text, Layer 1 narrative, and actions.
 */

import type { Finding, AgDRRecord } from '../agdr/types.ts';
import type { FindingTemplate } from '../templates/types.ts';

export interface DrawerContent {
  finding: Finding;
  record: AgDRRecord;
  template: FindingTemplate | undefined;
  layer1Text: string;
  slotValues: Record<string, string>;
  entailmentPassed: boolean;
}

class DrawerStore {
  isOpen = $state(false);
  content = $state<DrawerContent | null>(null);

  open(data: DrawerContent): void {
    this.content = data;
    this.isOpen = true;
  }

  close(): void {
    this.isOpen = false;
    this.content = null;
  }
}

export const drawerStore = new DrawerStore();
