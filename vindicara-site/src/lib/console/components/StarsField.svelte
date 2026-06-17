<script lang="ts">
  interface Star {
    x: number;
    y: number;
    size: number;
    peak: number;
    floor: number;
    dur: number;
    delay: number;
    cool: boolean;
  }

  function buildStars(count: number): Star[] {
    let seed = 41823;
    const rnd = () => {
      seed = (seed * 16807) % 2147483647;
      return (seed - 1) / 2147483646;
    };
    return Array.from({ length: count }, () => ({
      x: rnd() * 100,
      y: rnd() * 100,
      size: rnd() < 0.1 ? 2 : 1,
      peak: 0.16 + rnd() * 0.28,
      floor: 0.03 + rnd() * 0.09,
      dur: 3.2 + rnd() * 8.5,
      delay: rnd() * 10,
      cool: rnd() < 0.38
    }));
  }

  const stars = buildStars(160);
</script>

<div class="fd-stars" aria-hidden="true">
  {#each stars as s}
    <span
      class="fd-star"
      class:cool={s.cool}
      style:left="{s.x}%"
      style:top="{s.y}%"
      style:--peak={s.peak}
      style:--floor={s.floor}
      style:--dur="{s.dur}s"
      style:--delay="{s.delay}s"
      style:width="{s.size}px"
      style:height="{s.size}px"
    ></span>
  {/each}
</div>

<style>
  .fd-stars {
    position: fixed;
    inset: 0;
    pointer-events: none;
    z-index: 0;
    overflow: hidden;
  }

  .fd-star {
    position: absolute;
    border-radius: 50%;
    background: #f8fafc;
    opacity: var(--floor);
    box-shadow: 0 0 2px rgba(255, 255, 255, 0.12);
    animation: fd-twinkle var(--dur) ease-in-out var(--delay) infinite;
  }

  .fd-star.cool {
    background: #c7d7ff;
    box-shadow: 0 0 3px rgba(167, 196, 255, 0.14);
  }

  @keyframes fd-twinkle {
    0%,
    100% {
      opacity: var(--floor);
      transform: scale(1);
    }
    48% {
      opacity: var(--peak);
      transform: scale(1.15);
    }
    62% {
      opacity: calc(var(--peak) * 0.72);
      transform: scale(0.95);
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .fd-star {
      animation: none;
      opacity: var(--floor);
    }
  }
</style>