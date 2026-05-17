<script lang="ts">
	import { onMount, onDestroy } from 'svelte';

	let canvas: HTMLCanvasElement | undefined = $state();
	let raf = 0;
	let resizeObs: ResizeObserver | null = null;

	const GLYPHS =
		'01アァイィウヴエカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
	const FONT_SIZE = 14;
	const TRAIL_FADE = 'rgba(10, 10, 12, 0.10)';

	// Circuit-trace forks: bright cyan lines that walk on a grid, turning at
	// right angles, occasionally branching. Inspired by the user's first
	// reference image (architectural glowing traces, not Matrix rain alone).
	const TRACE_GRID = 22;
	const TRACE_HEAD_LIMIT = 22; // max simultaneous live heads
	const TRACE_STEP_FRAMES = 3; // advance every N frames
	const SEGMENT_TTL = 220; // frames a segment stays before fading
	const TURN_PROB = 0.18;
	const BRANCH_PROB = 0.08;
	const SPAWN_PROB = 0.04;

	type Dir = 0 | 1 | 2 | 3; // right, down, left, up
	const DX: Record<Dir, number> = { 0: 1, 1: 0, 2: -1, 3: 0 };
	const DY: Record<Dir, number> = { 0: 0, 1: 1, 2: 0, 3: -1 };

	interface Head {
		gx: number;
		gy: number;
		dir: Dir;
	}
	interface Segment {
		x: number;
		y: number;
		dir: Dir;
		age: number;
	}

	function turnLeft(d: Dir): Dir {
		return ((d + 3) % 4) as Dir;
	}
	function turnRight(d: Dir): Dir {
		return ((d + 1) % 4) as Dir;
	}

	onMount(() => {
		if (!canvas) return;
		const ctx = canvas.getContext('2d');
		if (!ctx) return;

		let columns = 0;
		let rainDrops: number[] = [];
		let cols = 0;
		let rows = 0;
		let heads: Head[] = [];
		let segments: Segment[] = [];
		let frame = 0;

		const resize = (): void => {
			if (!canvas) return;
			const dpr = Math.min(window.devicePixelRatio, 2);
			const w = canvas.clientWidth;
			const h = canvas.clientHeight;
			canvas.width = w * dpr;
			canvas.height = h * dpr;
			ctx.setTransform(1, 0, 0, 1, 0, 0);
			ctx.scale(dpr, dpr);
			ctx.font = `${FONT_SIZE}px 'JetBrains Mono', monospace`;
			columns = Math.ceil(w / FONT_SIZE);
			rainDrops = new Array(columns).fill(0).map(() => Math.floor(Math.random() * (h / FONT_SIZE)));
			cols = Math.ceil(w / TRACE_GRID);
			rows = Math.ceil(h / TRACE_GRID);
			heads = [];
			segments = [];
			for (let i = 0; i < 6; i++) spawnHead();
		};

		const spawnHead = (): void => {
			if (heads.length >= TRACE_HEAD_LIMIT) return;
			const edge = Math.floor(Math.random() * 4) as Dir;
			let gx = 0;
			let gy = 0;
			if (edge === 0) {
				gx = 0;
				gy = Math.floor(Math.random() * rows);
			} else if (edge === 1) {
				gx = Math.floor(Math.random() * cols);
				gy = 0;
			} else if (edge === 2) {
				gx = cols - 1;
				gy = Math.floor(Math.random() * rows);
			} else {
				gx = Math.floor(Math.random() * cols);
				gy = rows - 1;
			}
			heads.push({ gx, gy, dir: edge });
		};

		const stepHead = (head: Head): Head | null => {
			let dir: Dir = head.dir;
			if (Math.random() < TURN_PROB) {
				dir = Math.random() < 0.5 ? turnLeft(dir) : turnRight(dir);
			}
			const ngx = head.gx + DX[dir];
			const ngy = head.gy + DY[dir];
			if (ngx < 0 || ngy < 0 || ngx >= cols || ngy >= rows) return null;
			segments.push({
				x: ngx * TRACE_GRID,
				y: ngy * TRACE_GRID,
				dir,
				age: 0
			});
			if (Math.random() < BRANCH_PROB && heads.length < TRACE_HEAD_LIMIT) {
				const branchDir = Math.random() < 0.5 ? turnLeft(dir) : turnRight(dir);
				heads.push({ gx: ngx, gy: ngy, dir: branchDir });
			}
			return { gx: ngx, gy: ngy, dir };
		};

		const drawRain = (w: number, h: number): void => {
			ctx.fillStyle = TRAIL_FADE;
			ctx.fillRect(0, 0, w, h);
			for (let i = 0; i < columns; i++) {
				const ch = GLYPHS.charAt(Math.floor(Math.random() * GLYPHS.length));
				const x = i * FONT_SIZE;
				const y = rainDrops[i]! * FONT_SIZE;
				ctx.fillStyle =
					rainDrops[i]! % 19 === 0 ? 'rgba(180, 250, 230, 0.75)' : 'rgba(34, 211, 238, 0.30)';
				ctx.fillText(ch, x, y);
				if (y > h && Math.random() > 0.975) {
					rainDrops[i] = 0;
				} else {
					rainDrops[i]!++;
				}
			}
		};

		const drawTraces = (): void => {
			for (const seg of segments) {
				const fade = 1 - seg.age / SEGMENT_TTL;
				if (fade <= 0) continue;
				const nx = seg.x - DX[seg.dir] * TRACE_GRID;
				const ny = seg.y - DY[seg.dir] * TRACE_GRID;
				ctx.lineCap = 'round';
				// Outer glow
				ctx.strokeStyle = `rgba(34, 211, 238, ${0.18 * fade})`;
				ctx.lineWidth = 5;
				ctx.beginPath();
				ctx.moveTo(nx, ny);
				ctx.lineTo(seg.x, seg.y);
				ctx.stroke();
				// Bright core
				ctx.strokeStyle = `rgba(180, 250, 230, ${0.95 * fade})`;
				ctx.lineWidth = 1.4;
				ctx.beginPath();
				ctx.moveTo(nx, ny);
				ctx.lineTo(seg.x, seg.y);
				ctx.stroke();
			}
			// Heads
			for (const head of heads) {
				const x = head.gx * TRACE_GRID;
				const y = head.gy * TRACE_GRID;
				ctx.fillStyle = 'rgba(180, 250, 230, 0.95)';
				ctx.beginPath();
				ctx.arc(x, y, 2.2, 0, Math.PI * 2);
				ctx.fill();
				ctx.fillStyle = 'rgba(34, 211, 238, 0.4)';
				ctx.beginPath();
				ctx.arc(x, y, 5, 0, Math.PI * 2);
				ctx.fill();
			}
		};

		const draw = (): void => {
			if (!canvas) return;
			frame++;
			const w = canvas.clientWidth;
			const h = canvas.clientHeight;

			drawRain(w, h);

			if (frame % TRACE_STEP_FRAMES === 0) {
				const next: Head[] = [];
				for (const head of heads) {
					const out = stepHead(head);
					if (out) next.push(out);
				}
				heads = next;
				if (Math.random() < SPAWN_PROB || heads.length < 4) spawnHead();
			}
			for (const seg of segments) seg.age++;
			segments = segments.filter((s) => s.age < SEGMENT_TTL);

			drawTraces();
			raf = requestAnimationFrame(draw);
		};

		resize();
		resizeObs = new ResizeObserver(resize);
		resizeObs.observe(canvas);
		raf = requestAnimationFrame(draw);
	});

	onDestroy(() => {
		if (raf) cancelAnimationFrame(raf);
		resizeObs?.disconnect();
	});
</script>

<canvas
	bind:this={canvas}
	class="fixed inset-0 w-full h-full pointer-events-none"
	style="z-index: 0; opacity: 0.55;"
	aria-hidden="true"
></canvas>
