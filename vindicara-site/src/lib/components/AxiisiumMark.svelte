<script>
  // @ts-nocheck
  // AXIISIUM wordmark. Phosphate-style condensed face (Anton stand-in), accent on
  // the A and the enlarged third I (--ax), neutral letters in currentColor so it
  // works on dark and light. size = cap height in px.
  let { size = 40 } = $props();
</script>

<span class="axmark" style="--axs:{size}px" aria-label="AXIISIUM"
  ><span class="ac">A</span>XIIS<span class="ac tall">I</span>UM</span>

<style>
  .axmark{
    font-family:'Anton','Arial Narrow','Inter',sans-serif;
    display:inline-flex;align-items:baseline;white-space:nowrap;
    font-size:var(--axs);line-height:.85;letter-spacing:.012em;
    color:currentColor;-webkit-font-smoothing:antialiased;
  }
  .axmark .ac{color:var(--ax,#F47B20)}
  .axmark .tall{font-size:calc(var(--axs) * 1.42);line-height:.6;margin:0 -.015em}
</style>
