<script lang="ts">
  /**
   * Панель обновлений: два независимых канала, прогресс и терминальный журнал.
   *
   * Прогресс и строки журнала приходят событиями из ядра, поэтому загрузка
   * не блокирует окно: видно проценты, скорость по байтам и каждый шаг
   * проверки — подпись, контрольная сумма, распаковка.
   */
  import { onMount } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import TerminalText from './TerminalText.svelte';
  import * as api from '$lib/api';

  interface Props {
    onclose: () => void;
  }

  let { onclose }: Props = $props();

  let rows = $state<api.UpdateStateRow[]>([]);
  let checking = $state<api.UpdateChannel | ''>('');
  let installing = $state<api.UpdateChannel | ''>('');
  let errorText = $state('');
  let log = $state<string[]>([]);
  let progress = $state<{ percent: number | null; received: number; total: number | null } | null>(
    null
  );
  /** Завершённое обновление: показываем экран «Обновление завершено». */
  let finished = $state<{ channel: api.UpdateChannel; version: string } | null>(null);
  let unlisten: Array<() => void> = [];

  const MAX_LOG_LINES = 14;

  function pushLine(line: string) {
    log = [...log, line].slice(-MAX_LOG_LINES);
  }

  function rowOf(channel: api.UpdateChannel): api.UpdateStateRow | undefined {
    return rows.find((row) => row.channel === channel);
  }

  onMount(() => {
    void load();

    void listen<api.UpdateLogEvent>('update://log', (event) => {
      pushLine(event.payload.line);
    }).then((off) => unlisten.push(off));

    void listen<api.UpdateProgressEvent>('update://progress', (event) => {
      progress = {
        percent: event.payload.percent,
        received: event.payload.received,
        total: event.payload.total
      };
    }).then((off) => unlisten.push(off));

    void listen<api.UpdateDoneEvent>('update://done', (event) => {
      finished = { channel: event.payload.channel, version: event.payload.version };
      installing = '';
      progress = null;
      pushLine(`готово: версия ${event.payload.version}`);
      void load();
    }).then((off) => unlisten.push(off));

    void listen<api.UpdateErrorEvent>('update://error', (event) => {
      errorText = event.payload.message;
      installing = '';
      progress = null;
    }).then((off) => unlisten.push(off));

    return () => {
      for (const off of unlisten) off();
    };
  });

  async function load() {
    try {
      const state = await api.updateState();
      // Найденные ранее обновления сохраняем: перезагрузка состояния их не теряет.
      rows = state.map((row) => ({
        ...row,
        candidate: rowOf(row.channel)?.candidate ?? row.candidate
      }));
    } catch (error) {
      errorText = api.describeError(api.toCommandError(error));
    }
  }

  async function check(channel: api.UpdateChannel) {
    if (checking !== '' || installing !== '') return;
    checking = channel;
    errorText = '';
    progress = null;

    try {
      const candidate = await api.updateCheck(channel);
      rows = rows.map((row) => (row.channel === channel ? { ...row, candidate } : row));
      pushLine(
        candidate
          ? `доступна версия ${candidate.version}`
          : `канал ${channel}: обновлений нет`
      );
    } catch (error) {
      errorText = api.describeError(api.toCommandError(error));
    } finally {
      checking = '';
    }
  }

  async function install(channel: api.UpdateChannel, version: string) {
    if (checking !== '' || installing !== '') return;
    installing = channel;
    errorText = '';
    finished = null;
    log = [];
    progress = { percent: null, received: 0, total: null };
    pushLine(`начато обновление ${channel} до ${version}`);

    try {
      await api.updateInstall(channel, version);
    } catch (error) {
      errorText = api.describeError(api.toCommandError(error));
      installing = '';
      progress = null;
    }
  }

  async function restart() {
    try {
      await api.appRestart();
    } catch (error) {
      errorText = api.describeError(api.toCommandError(error));
    }
  }

  /** Строка прогресса в терминальном виде: [####------] 42 %. */
  const bar = $derived.by(() => {
    if (!progress) return null;
    const percent = progress.percent;
    if (percent === null) return '##########';
    const filled = Math.round((percent / 100) * 20);
    return `${'#'.repeat(filled)}${'-'.repeat(20 - filled)}`;
  });
</script>

<section class="screen updates">
  {#if finished}
    <h2><TerminalText text="ОБНОВЛЕНИЕ ЗАВЕРШЕНО" speed={14} cursor={false} /></h2>
    <p class="dim lead">
      <TerminalText
        text={`Движок ${finished.channel} обновлён до версии ${finished.version}. Профили запускаются на новой версии.`}
        speed={9}
      />
    </p>
    <div class="actions">
      <button class="primary" onclick={restart}>перезапустить лаунчер</button>
      <button class="ghost" onclick={onclose}>закрыть</button>
    </div>
  {:else}
    <h2><TerminalText text="ОБНОВЛЕНИЯ ДВИЖКОВ" speed={14} cursor={false} /></h2>
    <p class="faint small">
      Каналы независимы: у них разные источники, разные проверки и разные манифесты.
      Движок Antidetect ставится только с подтверждённой GPG-подписью.
    </p>

    <ul class="channels">
      {#each rows as row (row.channel)}
        <li>
          <div class="line">
            <span class="name">{row.label}</span>
            <span class="faint small">
              установлено: {row.installed ?? 'нет'}
            </span>
            <span class="spacer"></span>
            {#if row.candidate}
              <span class="ok small">доступна {row.candidate.version}</span>
            {/if}
          </div>
          <div class="faint tiny hint">{api.UPDATE_CHANNEL_HINTS[row.channel]}</div>

          <div class="actions">
            <button
              class="ghost"
              onclick={() => check(row.channel)}
              disabled={checking !== '' || installing !== ''}
            >
              {checking === row.channel ? 'проверка…' : 'проверить обновления'}
            </button>
            {#if row.candidate}
              <button
                class="primary"
                onclick={() => install(row.channel, row.candidate!.version)}
                disabled={checking !== '' || installing !== ''}
              >
                {installing === row.channel ? 'установка…' : `обновить до ${row.candidate.version}`}
              </button>
            {/if}
          </div>
        </li>
      {/each}
    </ul>

    {#if installing !== ''}
      <div class="progress">
        <div class="bar">
          <span class="accent">[{bar}]</span>
          <span class="faint small">
            {progress?.percent !== null && progress?.percent !== undefined
              ? `${progress.percent.toFixed(0)} %`
              : 'получение размера…'}
          </span>
          <span class="spacer"></span>
          <span class="faint small">
            {api.formatBytes(progress?.received ?? 0)}{progress?.total
              ? ` / ${api.formatBytes(progress.total)}`
              : ''}
          </span>
        </div>
        <div class="track"><div class="fill" style={`width: ${progress?.percent ?? 4}%`}></div></div>
      </div>
    {/if}

    {#if log.length > 0}
      <div class="terminal" aria-live="polite">
        {#each log as line, index (index)}
          <div class="log-line">
            <span class="faint">&gt;</span>
            <span class="dim">{line}</span>
          </div>
        {/each}
        {#if installing !== ''}
          <div class="log-line"><span class="caret">_</span></div>
        {/if}
      </div>
    {/if}

    {#if errorText}
      <p class="danger small">[x] {errorText}</p>
    {/if}

    <div class="actions">
      <button class="ghost" onclick={onclose} disabled={installing !== ''}>назад</button>
    </div>
  {/if}

  <!-- Журнал остаётся на экране и после завершения: видно, что именно
       проверялось — подпись, контрольная сумма, распаковка. -->
  {#if finished && log.length > 0}
    <div class="terminal" aria-live="polite">
      {#each log as line, index (index)}
        <div class="log-line">
          <span class="faint">&gt;</span>
          <span class="dim">{line}</span>
        </div>
      {/each}
    </div>
  {/if}
</section>

<style>
  .updates {
    border: 1px solid var(--line);
    background: var(--bg-panel);
    padding: 22px 24px;
  }

  h2 {
    font-size: 1em;
    letter-spacing: 0.04em;
  }

  .lead {
    margin-top: 12px;
    font-size: 0.95em;
  }

  .channels {
    margin: 18px 0 0;
    padding: 0;
    list-style: none;
  }

  .channels li {
    padding: 14px 0;
    border-bottom: 1px solid var(--line-soft);
  }

  .line {
    display: flex;
    align-items: baseline;
    gap: 12px;
  }

  .name {
    letter-spacing: 0.04em;
  }

  .hint {
    margin-top: 4px;
  }

  .spacer {
    flex: 1;
  }

  .actions {
    display: flex;
    gap: 10px;
    margin-top: 14px;
  }

  .progress {
    margin-top: 18px;
  }

  .bar {
    display: flex;
    align-items: baseline;
    gap: 10px;
  }

  .track {
    margin-top: 6px;
    height: 4px;
    background: var(--line);
  }

  .fill {
    height: 100%;
    background: var(--accent);
    transition: width var(--dur) linear;
  }

  .terminal {
    margin-top: 16px;
    padding: 12px 14px;
    border: 1px solid var(--line);
    background: var(--bg-inset);
    font-size: 0.9em;
    max-height: 220px;
    overflow-y: auto;
  }

  .log-line {
    display: flex;
    gap: 8px;
    white-space: pre-wrap;
    word-break: break-all;
  }

  .small {
    font-size: 0.9em;
  }
</style>
