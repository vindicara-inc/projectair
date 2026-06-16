import type { FindingTemplate } from './types.ts';

export class TemplateRegistry {
  private readonly _map = new Map<string, FindingTemplate>();

  register(template: FindingTemplate): void {
    this._map.set(template.detector_id, template);
  }

  get(detectorId: string): FindingTemplate | undefined {
    return this._map.get(detectorId);
  }

  detectorIds(): string[] {
    return [...this._map.keys()];
  }

  all(): FindingTemplate[] {
    return [...this._map.values()];
  }
}

let _defaultRegistry: TemplateRegistry | null = null;

export async function loadTemplateRegistry(
  fetchImpl: typeof fetch = fetch
): Promise<TemplateRegistry> {
  if (_defaultRegistry) return _defaultRegistry;
  const registry = new TemplateRegistry();
  const ids = [
    'ASI01', 'ASI02', 'ASI03', 'ASI04', 'ASI05',
    'ASI06', 'ASI07', 'ASI08', 'ASI09', 'ASI10',
    'AIR-01', 'AIR-02', 'AIR-03', 'AIR-04', 'AIR-05', 'AIR-06'
  ];
  await Promise.allSettled(
    ids.map(async (id) => {
      const resp = await fetchImpl(`/templates/${id}.json`);
      if (!resp.ok) return;
      const template = (await resp.json()) as FindingTemplate;
      registry.register(template);
    })
  );
  _defaultRegistry = registry;
  return registry;
}

export function resetRegistryCache(): void {
  _defaultRegistry = null;
}
