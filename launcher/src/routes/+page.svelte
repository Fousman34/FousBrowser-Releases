<script lang="ts">
  import { onMount } from 'svelte';
  import TerminalText from '$lib/components/TerminalText.svelte';
  import TypedHint from '$lib/components/TypedHint.svelte';
  import * as api from '$lib/api';

  type Phase = 'boot' | 'welcome' | 'unlock' | 'ready';

  let phase = $state<Phase>('boot');
  let status = $state<api.VaultStatus | null>(null);
  let outcome = $state<api.UnlockOutcome | null>(null);

  let busy = $state(false);
  let errorText = $state('');
  let hintFor = $state('');

  let password = $state('');
  let confirmation = $state('');
  let report = $state<api.PasswordReport | null>(null);

  let cooldown = $state(0);
  let cooldownHandle: ReturnType<typeof setInterval> | undefined;
  let reportHandle: ReturnType<typeof setTimeout> | undefined;

  let passwordInput = $state<HTMLInputElement | undefined>();

  const MIN = api.MIN_PASSWORD_LENGTH;

  onMount(() => {
    void refresh();
    return () => {
      if (cooldownHandle) clearInterval(cooldownHandle);
      if (reportHandle) clearTimeout(reportHandle);
    };
  });

  // Поле пароля получает фокус, как только экран появился.
  $effect(() => {
    if (phase === 'welcome' || phase === 'unlock') {
      passwordInput?.focus();
    }
  });

  async function refresh() {
    try {
      status = await api.vaultStatus();
      phase = status.exists ? 'unlock' : 'welcome';
      if (status.backoff_seconds > 0) startCooldown(status.backoff_seconds);
    } catch (error) {
      errorText = api.describeError(api.toCommandError(error));
      phase = 'welcome';
    }
  }

  async function refreshStatus() {
    try {
      status = await api.vaultStatus();
    } catch {
      // Состояние счётчика не критично: оставляем предыдущее значение.
    }
  }

  function startCooldown(seconds: number) {
    cooldown = Math.max(0, Math.floor(seconds));
    if (cooldownHandle) clearInterval(cooldownHandle);
    if (cooldown <= 0) return;

    cooldownHandle = setInterval(() => {
      cooldown -= 1;
      if (cooldown <= 0) {
        cooldown = 0;
        if (cooldownHandle) clearInterval(cooldownHandle);
      }
    }, 1000);
  }

  function scheduleReport(value: string) {
    if (reportHandle) clearTimeout(reportHandle);
    reportHandle = setTimeout(async () => {
      try {
        report = await api.passwordReport(value);
      } catch {
        report = null;
      }
    }, 120);
  }

  async function createVault() {
    if (busy) return;
    errorText = '';

    if (!report?.acceptable) {
      errorText = `мастер-пароль должен быть не короче ${MIN} символов`;
      return;
    }
    if (password !== confirmation) {
      errorText = 'пароли не совпадают';
      return;
    }

    busy = true;
    try {
      outcome = await api.vaultCreate(password);
      password = '';
      confirmation = '';
      report = null;
      phase = 'ready';
    } catch (error) {
      errorText = api.describeError(api.toCommandError(error));
    } finally {
      busy = false;
    }
  }

  async function unlockVault() {
    if (busy || cooldown > 0 || password.length === 0) return;
    errorText = '';
    busy = true;

    try {
      outcome = await api.vaultUnlock(password);
      password = '';
      phase = 'ready';
    } catch (error) {
      const commandError = api.toCommandError(error);
      errorText = api.describeError(commandError);
      password = '';

      if (commandError.kind === 'backoff' && commandError.seconds) {
        startCooldown(commandError.seconds);
      }
      await refreshStatus();
    } finally {
      busy = false;
    }
  }

  async function confirmContinue() {
    errorText = '';
    try {
      status = await api.vaultConfirmContinue();
    } catch (error) {
      errorText = api.describeError(api.toCommandError(error));
    }
  }

  async function lockVault() {
    try {
      await api.vaultLock();
    } catch {
      // Блокировка локальна: даже при ошибке канала ключ будет затёрт при выходе.
    }
    outcome = null;
    password = '';
    confirmation = '';
    report = null;
    errorText = '';
    hintFor = '';
    await refresh();
  }

  function shorten(value: string): string {
    return value.length <= 46 ? value : `…${value.slice(-45)}`;
  }
</script>

<div class="shell">
  <header class="bar">
    <span class="accent">FousBrowser</span>
    <span class="faint">launcher</span>
    <span class="spacer"></span>
    {#if status}
      <span class="faint" title={status.vault_path}>{shorten(status.vault_path)}</span>
    {/if}
  </header>

  <main>
    {#if phase === 'boot'}
      <section class="screen">
        <p class="dim"><TerminalText text="чтение хранилища…" speed={14} /></p>
      </section>
    {:else if phase === 'welcome'}
      <section class="screen panel">
        <h1><TerminalText text="ИНИЦИАЛИЗАЦИЯ ХРАНИЛИЩА" speed={16} cursor={false} /></h1>

        <p class="dim lead">
          <TerminalText
            text="Предустановленных профилей нет. Всё, что вы создадите, будет зашифровано мастер-паролем."
            speed={8}
          />
        </p>

        <div class="notice">
          <div class="warn">[!] восстановления пароля не существует</div>
          <p class="dim small">
            Ключ выводится из пароля и нигде не хранится. Забытый пароль означает безвозвратную
            потерю данных. Сохраните его в менеджере паролей.
          </p>
        </div>

        <div class="field">
          <div class="label-row">
            <label for="master">мастер-пароль</label>
            <TypedHint
              hint="буквы, цифры и спецсимволы заметно надёжнее"
              active={hintFor === 'password'}
            />
          </div>
          <input
            id="master"
            type="password"
            autocomplete="new-password"
            spellcheck="false"
            bind:this={passwordInput}
            bind:value={password}
            disabled={busy}
            placeholder="минимум 12 символов"
            oninput={(event) => scheduleReport((event.target as HTMLInputElement).value)}
            onfocus={() => (hintFor = 'password')}
            onblur={() => (hintFor = '')}
            onmouseenter={() => (hintFor = 'password')}
            onmouseleave={() => (hintFor = '')}
          />
        </div>

        <div class="strength">
          <span class="faint small">сложность</span>
          <div class="segments">
            {#each [0, 1, 2, 3] as index (index)}
              <span class="segment" class:filled={(report?.score ?? 0) > index}></span>
            {/each}
          </div>
          <span class="faint small">{report?.length ?? 0} симв.</span>
        </div>

        {#if report && report.recommendations.length > 0}
          <ul class="tips">
            {#each report.recommendations.slice(0, 3) as tip (tip)}
              <li class="faint small">— {tip}</li>
            {/each}
          </ul>
        {/if}

        <div class="field">
          <label for="confirm">повторите пароль</label>
          <input
            id="confirm"
            type="password"
            autocomplete="new-password"
            spellcheck="false"
            bind:value={confirmation}
            disabled={busy}
            onkeydown={(event) => {
              if (event.key === 'Enter') void createVault();
            }}
          />
        </div>

        {#if errorText}
          <p class="danger small">[x] {errorText}</p>
        {/if}

        <div class="actions">
          <button class="primary" onclick={createVault} disabled={busy}>
            {busy ? 'создание…' : 'создать хранилище'}
          </button>
        </div>
      </section>
    {:else if phase === 'unlock'}
      <section class="screen panel">
        <h1><TerminalText text="ХРАНИЛИЩЕ ЗАБЛОКИРОВАНО" speed={16} cursor={false} /></h1>

        <p class="dim lead">
          <TerminalText text="Введите мастер-пароль. Без него данные не расшифровываются." speed={12} />
        </p>

        <div class="field">
          <div class="label-row">
            <label for="master">мастер-пароль</label>
            <TypedHint
              hint="раскладка и Caps Lock — самая частая причина ошибки"
              active={hintFor === 'password'}
            />
          </div>
          <input
            id="master"
            type="password"
            autocomplete="current-password"
            spellcheck="false"
            bind:this={passwordInput}
            bind:value={password}
            disabled={busy || cooldown > 0}
            placeholder={cooldown > 0 ? 'ввод временно недоступен' : 'введите пароль'}
            onfocus={() => (hintFor = 'password')}
            onblur={() => (hintFor = '')}
            onmouseenter={() => (hintFor = 'password')}
            onmouseleave={() => (hintFor = '')}
            onkeydown={(event) => {
              if (event.key === 'Enter') void unlockVault();
            }}
          />
        </div>

        {#if cooldown > 0}
          <p class="warn small">
            [~] следующая попытка через {api.formatDuration(cooldown)}
          </p>
        {/if}

        {#if status && status.failed_attempts > 0}
          <p class:faint={!status.warn_attempts} class:warn={status.warn_attempts} class="small">
            [!] неудачных попыток подряд: {status.failed_attempts}
            {#if status.warn_attempts}— проверьте раскладку клавиатуры{/if}
          </p>
        {/if}

        {#if status?.confirm_required}
          <div class="notice">
            <div class="warn">[!] достигнут порог попыток</div>
            <p class="dim small">
              Данные не удалены. Чтобы продолжить ввод, подтвердите намерение.
            </p>
            <div class="actions">
              <button onclick={confirmContinue}>продолжить попытки</button>
            </div>
          </div>
        {/if}

        {#if errorText}
          <p class="danger small">[x] {errorText}</p>
        {:else}
          <p class="faint small">
            «никакие данные не доступны без мастер-пароля» — включая список профилей
          </p>
        {/if}

        <div class="actions">
          <button class="primary" onclick={unlockVault} disabled={busy || cooldown > 0}>
            {busy ? 'проверка…' : 'разблокировать'}
          </button>
        </div>
      </section>
    {:else if phase === 'ready'}
      <section class="screen panel">
        <h1><TerminalText text="ДОСТУП РАЗРЕШЁН" speed={16} cursor={false} /></h1>

        <dl class="kv">
          <dt class="faint">идентификатор</dt>
          <dd>{outcome?.vault_id.slice(0, 8) ?? '—'}</dd>
          <dt class="faint">профилей</dt>
          <dd>{outcome?.profiles ?? 0}</dd>
          <dt class="faint">каталог</dt>
          <dd class="dim">{status?.vault_path ?? '—'}</dd>
        </dl>

        {#if outcome && outcome.warnings.length > 0}
          <div class="notice">
            {#each outcome.warnings as warning (warning)}
              <p class="warn small">[!] {warning}</p>
            {/each}
          </div>
        {/if}

        <p class="dim small">
          Шифрование работает: ключ выведен из пароля через Argon2id и находится только
          в памяти процесса. Управление профилями появится на следующем этапе.
        </p>

        <div class="actions">
          <button onclick={lockVault}>заблокировать</button>
        </div>
      </section>
    {/if}
  </main>

  <footer class="bar bottom">
    <span class="faint small">PolyForm Noncommercial 1.0.0</span>
    <span class="spacer"></span>
    <span class="faint small">
      {#if phase === 'ready'}сессия разблокирована{:else}сессия закрыта{/if}
    </span>
  </footer>
</div>

<style>
  .shell {
    display: grid;
    grid-template-rows: auto 1fr auto;
    height: 100vh;
  }

  .bar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 16px;
    border-bottom: 1px solid var(--line-soft);
    font-size: 0.92em;
  }

  .bar.bottom {
    border-bottom: none;
    border-top: 1px solid var(--line-soft);
  }

  .spacer {
    flex: 1;
  }

  main {
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: auto;
    padding: 28px 16px;
  }

  .panel {
    width: 100%;
    max-width: 620px;
    border: 1px solid var(--line);
    background: var(--bg-panel);
    padding: 26px 28px;
  }

  h1 {
    font-size: 1.05em;
    color: var(--fg);
  }

  .lead {
    margin-top: 12px;
    font-size: 0.95em;
  }

  .notice {
    margin-top: 16px;
    padding: 12px 14px;
    border: 1px solid var(--line);
    border-left: 2px solid var(--warn);
    background: var(--bg-inset);
  }

  .field {
    margin-top: 18px;
  }

  label {
    display: block;
    margin-bottom: 6px;
    color: var(--fg-dim);
    font-size: 0.9em;
    letter-spacing: 0.04em;
  }

  .label-row {
    display: flex;
    align-items: baseline;
    margin-bottom: 6px;
    overflow: hidden;
  }

  .label-row label {
    margin-bottom: 0;
    white-space: nowrap;
  }

  .strength {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 10px;
  }

  .segments {
    display: flex;
    gap: 4px;
  }

  .segment {
    width: 26px;
    height: 6px;
    background: var(--line);
  }

  .segment.filled {
    background: var(--accent);
  }

  .tips {
    margin: 10px 0 0;
    padding: 0;
    list-style: none;
  }

  .actions {
    display: flex;
    gap: 10px;
    margin-top: 20px;
  }

  .kv {
    display: grid;
    grid-template-columns: 130px 1fr;
    gap: 6px 14px;
    margin: 16px 0 0;
  }

  .kv dt {
    font-size: 0.9em;
  }

  .kv dd {
    margin: 0;
    overflow-wrap: anywhere;
  }

  .small {
    font-size: 0.9em;
  }
</style>
