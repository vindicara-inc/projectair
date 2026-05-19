/**
 * Global filter store — filters apply across all panels.
 */

class FilterStore {
	agent = $state<string | null>(null);
	detectorId = $state<string | null>(null);
	severity = $state<string | null>(null);
	chainId = $state<string | null>(null);

	get isActive(): boolean {
		return this.agent !== null || this.detectorId !== null || this.severity !== null || this.chainId !== null;
	}

	setAgent(id: string | null): void { this.agent = id; }
	setDetector(id: string | null): void { this.detectorId = id; }
	setSeverity(s: string | null): void { this.severity = s; }
	setChain(id: string | null): void { this.chainId = id; }

	clear(): void {
		this.agent = null;
		this.detectorId = null;
		this.severity = null;
		this.chainId = null;
	}
}

export const filterStore = new FilterStore();
