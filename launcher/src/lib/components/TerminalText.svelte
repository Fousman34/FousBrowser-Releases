<script lang="ts">
  /**
   * Текст, который печатается посимвольно, как будто его вводят в терминале.
   *
   * Реализация: `requestAnimationFrame` с накопителем времени. Это даёт
   * равномерную скорость независимо от частоты кадров и не нагружает
   * поток перерисовками — обновляется только содержимое одного узла.
   *
   * Разбивка идёт по графемам через `Intl.Segmenter`, чтобы не разрывать
   * эмодзи и составные символы.
   */
  import { untrack } from 'svelte';

  interface Props {
    text: string;
    /** Миллисекунд на символ. */
    speed?: number;
    /** Задержка перед началом печати. */
    delay?: number;
    /** Показывать мигающий курсор. */
    cursor?: boolean;
    class?: string;
    onDone?: () => void;
  }

  let {
    text,
    speed = 20,
    delay = 0,
    cursor = true,
    class: className = '',
    onDone
  }: Props = $props();

  let shown = $state('');

  function segment(value: string): string[] {
    try {
      const segmenter = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
      return Array.from(segmenter.segment(value), (part) => part.segment);
    } catch {
      // Старые движки без Intl.Segmenter — печатаем по кодпоинтам.
      return Array.from(value);
    }
  }

  $effect(() => {
    const source = text;
    const parts = segment(source);
    const stepMs = Math.max(4, speed);

    // Колбэк читаем вне отслеживания: иначе инлайновая стрелка из родителя
    // меняла бы идентичность на каждом рендере и печать начиналась бы заново.
    const done = untrack(() => onDone);

    shown = '';

    const reduceMotion =
      typeof window !== 'undefined' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (reduceMotion) {
      shown = source;
      done?.();
      return;
    }

    let index = 0;
    let frame = 0;
    let origin = 0;

    const step = (now: number) => {
      if (origin === 0) origin = now;
      const target = Math.min(parts.length, Math.floor((now - origin) / stepMs));

      if (target !== index) {
        index = target;
        shown = parts.slice(0, index).join('');
      }

      if (index >= parts.length) {
        done?.();
        return;
      }

      frame = requestAnimationFrame(step);
    };

    const timer = setTimeout(() => {
      frame = requestAnimationFrame(step);
    }, delay);

    return () => {
      clearTimeout(timer);
      cancelAnimationFrame(frame);
    };
  });
</script>

<span class={className}>{shown}{#if cursor}<span class="caret" aria-hidden="true">_</span>{/if}<span
    class="sr-only">{text}</span
  ></span>
