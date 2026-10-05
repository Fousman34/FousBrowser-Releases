<script lang="ts">
  /**
   * Подсказка вместо системного всплывающего окна: строка печатается
   * посимвольно рядом с элементом, к которому относится.
   */
  import TerminalText from './TerminalText.svelte';

  interface Props {
    hint: string;
    active: boolean;
  }

  let { hint, active }: Props = $props();
</script>

{#if active}
  <span class="hint" aria-hidden="true">
    <TerminalText text={hint} speed={13} cursor={true} />
  </span>
{/if}

<style>
  .hint {
    margin-left: 10px;
    color: var(--fg-faint);
    font-size: 0.92em;
    white-space: nowrap;
  }
</style>
