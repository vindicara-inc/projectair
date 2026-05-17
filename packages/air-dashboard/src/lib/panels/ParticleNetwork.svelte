<script lang="ts">
	import { onMount, onDestroy } from 'svelte';

	let canvas: HTMLCanvasElement;
	let ctx: CanvasRenderingContext2D;
	let animId = 0;
	let w = 0;
	let h = 0;
	let mx = -1000;
	let my = -1000;

	const CONN = 140;
	const REPEL_SQ = 22500;

	interface Pt {
		x: number; y: number;
		sx: number; sy: number;
		sz: number; a: number;
	}
	let pts: Pt[] = [];

	function init(): void {
		w = canvas.width = window.innerWidth;
		h = canvas.height = window.innerHeight;
		const count = Math.floor((w * h) / 9000);
		pts = [];
		for (let i = 0; i < count; i++) {
			pts.push({
				x: Math.random() * w,
				y: Math.random() * h,
				sx: Math.random() * 0.6 - 0.3,
				sy: Math.random() * 0.6 - 0.3,
				sz: Math.random() * 1.5 + 0.5,
				a: Math.random() * Math.PI * 2,
			});
		}
	}

	function animate(): void {
		ctx.clearRect(0, 0, w, h);
		for (let i = 0; i < pts.length; i++) {
			const p = pts[i]!;
			p.x += p.sx;
			p.y += p.sy;
			p.a += 0.01;
			p.y += Math.sin(p.a) * 0.3;
			if (p.x > w || p.x < 0) p.sx *= -1;
			if (p.y > h || p.y < 0) p.sy *= -1;
			const dx = mx - p.x;
			const dy = my - p.y;
			if (dx * dx + dy * dy < REPEL_SQ) {
				p.x -= dx * 0.02;
				p.y -= dy * 0.02;
			}
			ctx.beginPath();
			ctx.arc(p.x, p.y, p.sz, 0, Math.PI * 2);
			ctx.fillStyle = 'rgba(255,255,255,0.8)';
			ctx.fill();
			for (let j = i + 1; j < pts.length; j++) {
				const q = pts[j]!;
				const cx = p.x - q.x;
				const cy = p.y - q.y;
				const dist = Math.sqrt(cx * cx + cy * cy);
				if (dist < CONN) {
					const r = Math.floor((p.x / w) * 200 + 55);
					const g = Math.floor((p.y / h) * 30);
					const b = Math.floor(255 - (p.x / w) * 100);
					ctx.beginPath();
					ctx.moveTo(p.x, p.y);
					ctx.lineTo(q.x, q.y);
					ctx.strokeStyle = `rgba(${r},${g},${b},${(1 - dist / CONN) * 0.5})`;
					ctx.lineWidth = 0.8;
					ctx.stroke();
				}
			}
		}
		animId = requestAnimationFrame(animate);
	}

	function onMove(e: MouseEvent): void { mx = e.clientX; my = e.clientY; }
	function onResize(): void { init(); }

	onMount(() => {
		ctx = canvas.getContext('2d')!;
		init();
		animate();
		window.addEventListener('mousemove', onMove);
		window.addEventListener('resize', onResize);
	});

	onDestroy(() => {
		cancelAnimationFrame(animId);
		window.removeEventListener('mousemove', onMove);
		window.removeEventListener('resize', onResize);
	});
</script>

<canvas bind:this={canvas} class="fixed inset-0 z-0 pointer-events-none"></canvas>
