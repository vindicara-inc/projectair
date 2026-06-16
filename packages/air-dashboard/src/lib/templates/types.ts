import type { Finding, AgDRRecord, Severity } from '../agdr/types.ts';

export interface SlotDefinition {
  name: string;
  source: string;
}

export interface ActionDefinition {
  label: string;
  action: string;
  requires_step_up?: boolean;
}

export interface Layer2Entry {
  framework: string;
  reference: string;
  description: string;
}

export interface FindingTemplate {
  template_id: string;
  version: string;
  detector_id: string;
  finding_type: string;
  layer1: string;
  layer2: Layer2Entry[];
  layer3: {
    primary: ActionDefinition;
    secondary: ActionDefinition[];
  };
  slots: SlotDefinition[];
}

export type IncidentStatus = 'new' | 'acknowledged' | 'investigating' | 'resolved';

export interface TranslatedIncident {
  id: string;
  finding: Finding;
  record: AgDRRecord;
  template: FindingTemplate;
  layer1Text: string;
  layer2Entries: Layer2Entry[];
  layer3: FindingTemplate['layer3'];
  status: IncidentStatus;
  agentName: string;
  toolName: string;
  timestamp: string;
  entailmentPassed: boolean;
  slotValues: Record<string, string>;
}

// Re-export for consumers that want to import Severity from this module.
export type { Severity };
