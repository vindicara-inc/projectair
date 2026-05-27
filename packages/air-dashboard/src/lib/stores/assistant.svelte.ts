/**
 * Assistant store — manages the forensic assistant chat panel state.
 *
 * The assistant can be opened with optional finding context so it can
 * surface relevant evidence and citations from the active chain.
 */

export interface AssistantMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  citations: number[];
  timestamp: string;
}

class AssistantStore {
  isOpen = $state(false);
  messages = $state<AssistantMessage[]>([]);
  isLoading = $state(false);
  contextFindingId = $state<string | null>(null);

  toggle(): void {
    this.isOpen = !this.isOpen;
  }

  open(findingStepId?: string): void {
    this.isOpen = true;
    if (findingStepId) {
      this.contextFindingId = findingStepId;
    }
  }

  close(): void {
    this.isOpen = false;
  }

  addUserMessage(content: string): void {
    this.messages = [
      ...this.messages,
      {
        id: `msg-${Date.now()}`,
        role: 'user',
        content,
        citations: [],
        timestamp: new Date().toISOString()
      }
    ];
  }

  addAssistantMessage(content: string, citations: number[]): void {
    this.messages = [
      ...this.messages,
      {
        id: `msg-${Date.now()}`,
        role: 'assistant',
        content,
        citations,
        timestamp: new Date().toISOString()
      }
    ];
  }

  clearMessages(): void {
    this.messages = [];
    this.contextFindingId = null;
  }
}

export const assistantStore = new AssistantStore();
