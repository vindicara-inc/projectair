/**
 * Unit tests for the dashboard's AIR Cloud HTTP client.
 *
 * Drives the client through a hand-rolled stub `fetch` so the tests run
 * fast and offline; the matching server is integration-tested in
 * `tests/integration/cloud/test_air_cloud_app.py`.
 */

import { describe, expect, it } from 'vitest';

import {
	AirCloudClient,
	AirCloudHttpError,
	DEFAULT_BASE_URL,
	loadCloudChain
} from '../../src/lib/transport/air_cloud_client.ts';

interface CapturedRequest {
	url: string;
	method: string;
	headers: Record<string, string>;
}

function stubFetch(responses: Map<string, { status: number; body: unknown }>): {
	fetch: typeof fetch;
	calls: CapturedRequest[];
} {
	const calls: CapturedRequest[] = [];
	const impl: typeof fetch = async (input, init) => {
		const url = typeof input === 'string' ? input : (input as Request).url;
		const headers: Record<string, string> = {};
		const rawHeaders = init?.headers as Record<string, string> | undefined;
		if (rawHeaders) for (const [k, v] of Object.entries(rawHeaders)) headers[k.toLowerCase()] = v;
		calls.push({ url, method: init?.method ?? 'GET', headers });
		const match = responses.get(url);
		if (!match) throw new Error(`stubFetch: no response configured for ${url}`);
		const body = typeof match.body === 'string' ? match.body : JSON.stringify(match.body);
		return new Response(body, {
			status: match.status,
			headers: { 'Content-Type': 'application/json' }
		});
	};
	return { fetch: impl, calls };
}

describe('AirCloudClient', () => {
	it('rejects construction without an api key', () => {
		expect(() => new AirCloudClient({ apiKey: '' })).toThrow(/required/);
	});

	it('whoami sends GET /v1/workspaces/me with the api key header', async () => {
		const { fetch: fetchImpl, calls } = stubFetch(
			new Map([
				[
					`${DEFAULT_BASE_URL}/v1/workspaces/me`,
					{
						status: 200,
						body: {
							workspace_id: 'acme',
							name: 'Acme',
							owner_email: 'ops@acme.io',
							created_at: '2026-05-08T00:00:00Z'
						}
					}
				]
			])
		);
		const client = new AirCloudClient({ apiKey: 'air_test', fetchImpl });
		const ws = await client.whoami();
		expect(ws.workspace_id).toBe('acme');
		expect(calls).toHaveLength(1);
		expect(calls[0]!.method).toBe('GET');
		expect(calls[0]!.headers['x-api-key']).toBe('air_test');
	});

	it('listCapsules returns the page and applies pagination params', async () => {
		const { fetch: fetchImpl, calls } = stubFetch(
			new Map([
				[
					`${DEFAULT_BASE_URL}/v1/capsules?limit=50&offset=10`,
					{ status: 200, body: { workspace_id: 'acme', count: 200, records: [] } }
				]
			])
		);
		const client = new AirCloudClient({ apiKey: 'air_test', fetchImpl });
		const page = await client.listCapsules({ limit: 50, offset: 10 });
		expect(page.count).toBe(200);
		expect(calls[0]!.url).toBe(`${DEFAULT_BASE_URL}/v1/capsules?limit=50&offset=10`);
	});

	it('respects a custom base URL and trims trailing slashes', async () => {
		const { fetch: fetchImpl, calls } = stubFetch(
			new Map([
				[
					'https://eu.cloud.vindicara.io/v1/workspaces/me',
					{
						status: 200,
						body: { workspace_id: 'eu', name: 'EU', owner_email: 'a@b', created_at: '' }
					}
				]
			])
		);
		const client = new AirCloudClient({
			apiKey: 'air_test',
			baseUrl: 'https://eu.cloud.vindicara.io///',
			fetchImpl
		});
		await client.whoami();
		expect(calls[0]!.url).toBe('https://eu.cloud.vindicara.io/v1/workspaces/me');
	});

	it('non-2xx responses raise AirCloudHttpError with status + body', async () => {
		const { fetch: fetchImpl } = stubFetch(
			new Map([[`${DEFAULT_BASE_URL}/v1/workspaces/me`, { status: 401, body: 'invalid api key' }]])
		);
		const client = new AirCloudClient({ apiKey: 'air_test', fetchImpl });
		await expect(client.whoami()).rejects.toBeInstanceOf(AirCloudHttpError);
		await expect(client.whoami()).rejects.toMatchObject({ status: 401 });
	});

	it('loadCloudChain returns the records array from listCapsules', async () => {
		const records = [
			{ step_id: 'a' },
			{ step_id: 'b' }
		];
		const { fetch: fetchImpl } = stubFetch(
			new Map([
				[
					`${DEFAULT_BASE_URL}/v1/capsules?limit=1000`,
					{ status: 200, body: { workspace_id: 'acme', count: 2, records } }
				]
			])
		);
		const client = new AirCloudClient({ apiKey: 'air_test', fetchImpl });
		const chain = await loadCloudChain(client);
		expect(chain).toHaveLength(2);
		expect(chain[0]).toMatchObject({ step_id: 'a' });
	});
});
