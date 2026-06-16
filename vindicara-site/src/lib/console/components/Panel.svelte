<script lang="ts">
  let { reveal = false, delay = 0, klass = '', children } = $props();
</script>

<div class="panel glass hud {klass} {reveal ? 'reveal' : ''}" style={reveal ? `animation-delay:${delay}s` : ''}>
  {@render children?.()}
</div>
