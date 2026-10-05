<script lang="ts">
  import { onMount } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import TerminalText from '$lib/components/TerminalText.svelte';
  import TypedHint from '$lib/components/TypedHint.svelte';
  import ProfileForm from '$lib/components/ProfileForm.svelte';
  import UpdatePanel from '$lib/components/UpdatePanel.svelte';
  import * as api from '$lib/api';

  type Phase = 'boot' | 'welcome' | 'unlock' | 'ready';
  /** Какая панель раскрыта под списком профилей. */
  type Panel = 'none' | 'create' | 'edit';

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

  // --- профили ---
  let profiles = $state<api.ProfileView[]>([]);
  let panel = $state<Panel>('none');
  let editing = $state<api.ProfileView | null>(null);
  /** Профиль, удаление которого ждёт подтверждения. */
  let deleting = $state<api.ProfileView | null>(null);
  /** Идентификатор профиля, с которым сейчас идёт работа. */
  let working = $state('');
  /** Строка состояния: что только что произошло. */
  let notice = $state('');
  let transfer = $state<{ profileId: string | null } | null>(null);
  let transferPassword = $state('');

  async function transferProfile() {
    if (!transfer || working) return;
    working = 'transfer';
    errorText = '';
    const secret = transferPassword;
    transferPassword = '';
    try {
      const message = await api.profileTransfer(transfer.profileId, secret);
      if (message) { notice = message; await loadProfiles(); await loadRuntimes(); }
      transfer = null;
    } catch (error) { errorText = api.describeError(api.toCommandError(error)); }
    finally { working = ''; }
  }

  async function checkProxy(profile: api.ProfileView) {
    working = profile.id;
    errorText = '';
    try { await api.profileCheckProxy(profile.id); notice = 'Прокси: соединение с example.com:443 установлено'; }
    catch (error) { errorText = api.describeError(api.toCommandError(error)); }
    finally { working = ''; }
  }

  // --- запуск движков ---
  /** Состояние запуска и данных каждого профиля. */
  let runtimes = $state<api.RuntimeView[]>([]);
  /** Какие движки установлены. */
  let engines = $state<api.EngineStatus | null>(null);
  /** Профиль, с которым сейчас работают (запуск или остановка). */
  let engineBusy = $state('');
  let stopAllBusy = $state(false);
  /** Отчёт последней остановки всех профилей. */
  let stopReport = $state<api.StopAllReport | null>(null);
  /** Открыта ли панель обновлений. */
  let showUpdates = $state(false);
  let unlisten: (() => void) | undefined;

  const MIN = api.MIN_PASSWORD_LENGTH;

  onMount(() => {
    void refresh();
    void loadEngines();

    // Ядро сообщает о смене состояния профиля: браузер закрылся сам,
    // данные зашифрованы, произошла ошибка. Ждать опроса интерфейсом
    // для этого не нужно.
    void listen<api.ProfileStateEvent>('profile://state', (event) => {
      applyState(event.payload);
    }).then((off) => {
      unlisten = off;
    });

    return () => {
      if (cooldownHandle) clearInterval(cooldownHandle);
      if (reportHandle) clearTimeout(reportHandle);
      unlisten?.();
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
      await loadProfiles();
      await loadRuntimes();
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
      await loadProfiles();
      await loadRuntimes();
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
    // Список профилей живёт только в памяти разблокированной сессии.
    profiles = [];
    panel = 'none';
    editing = null;
    deleting = null;
    working = '';
    notice = '';
    runtimes = [];
    stopReport = null;
    engineBusy = '';
    stopAllBusy = false;
    await refresh();
  }

  // --- профили -------------------------------------------------------------

  async function loadProfiles() {
    try {
      profiles = await api.profileList();
    } catch (error) {
      errorText = api.describeError(api.toCommandError(error));
    }
  }

  function openCreate() {
    editing = null;
    deleting = null;
    notice = '';
    errorText = '';
    panel = 'create';
  }

  function openEdit(profile: api.ProfileView) {
    editing = profile;
    deleting = null;
    notice = '';
    errorText = '';
    panel = 'edit';
  }

  function closePanel() {
    panel = 'none';
    editing = null;
  }

  async function submitProfile(draft: api.ProfileDraft) {
    working = editing?.id ?? 'new';
    errorText = '';

    try {
      if (editing) {
        // Правка идёт двумя шагами: поля профиля и отдельно прокси,
        // потому что пароль прокси ядро хранит само.
        await api.profileUpdate(editing.id, draft);
        const withProxy = await api.profileSetProxy(editing.id, draft.proxy);
        notice = `профиль «${withProxy.name}» обновлён`;
      } else {
        const created = await api.profileCreate(draft);
        notice = `профиль «${created.name}» создан`;
      }
      closePanel();
      await loadProfiles();
      outcome = outcome ? { ...outcome, profiles: profiles.length } : outcome;
    } catch (error) {
      errorText = api.describeError(api.toCommandError(error));
    } finally {
      working = '';
    }
  }

  async function cloneProfile(profile: api.ProfileView) {
    working = profile.id;
    errorText = '';
    notice = '';
    try {
      const clone = await api.profileClone(profile.id);
      notice = `создана копия «${clone.name}» с новым зерном отпечатка`;
      await loadProfiles();
      outcome = outcome ? { ...outcome, profiles: profiles.length } : outcome;
    } catch (error) {
      errorText = api.describeError(api.toCommandError(error));
    } finally {
      working = '';
    }
  }

  function askDelete(profile: api.ProfileView) {
    deleting = profile;
    notice = '';
    errorText = '';
  }

  async function confirmDelete() {
    if (!deleting) return;
    const target = deleting;
    working = target.id;
    errorText = '';

    try {
      await api.profileDelete(target.id);
      deleting = null;
      notice = `профиль «${target.name}» удалён, данные стёрты`;
      await loadProfiles();
      outcome = outcome ? { ...outcome, profiles: profiles.length } : outcome;
    } catch (error) {
      errorText = api.describeError(api.toCommandError(error));
    } finally {
      working = '';
    }
  }

  // --- движки ---------------------------------------------------------------

  async function loadEngines() {
    try {
      engines = await api.engineStatus();
    } catch {
      engines = null;
    }
  }

  async function loadRuntimes() {
    try {
      runtimes = await api.profileRuntimeList();
    } catch {
      runtimes = [];
    }
  }

  /**
   * Применяет событие ядра к состоянию профилей.
   *
   * Важно, что событие приходит и тогда, когда браузер закрыл сам
   * пользователь: лаунчер обязан отразить это без перезапроса списка.
   */
  function applyState(payload: api.ProfileStateEvent) {
    runtimes = runtimes.map((item) =>
      item.profile_id === payload.profile_id
        ? {
            ...item,
            running: payload.state === 'running' || payload.state === 'stopping',
            pid: payload.pid ?? item.pid,
            plaintext: payload.state === 'stopped' ? false : item.plaintext
          }
        : item
    );

    switch (payload.state) {
      case 'running':
        notice = `профиль запущен · pid ${payload.pid ?? '?'}`;
        errorText = '';
        break;
      case 'stopping':
        notice = 'останавливаю движок…';
        break;
      case 'stopped':
        notice = 'профиль остановлен, данные зашифрованы';
        void loadRuntimes();
        break;
      default:
        errorText = payload.message ?? 'движок завершился с ошибкой';
    }
  }

  function runtimeOf(profileId: string): api.RuntimeView | undefined {
    return runtimes.find((item) => item.profile_id === profileId);
  }

  function engineInstalled(kind: api.ProfileKind): boolean {
    if (!engines) return true;
    return kind === 'antidetect' ? engines.antidetect_installed : engines.normal_installed;
  }

  const runningCount = $derived(runtimes.filter((item) => item.running).length);

  /** Типы профилей, для которых нужен движок, но он не установлен. */
  const missingEngines = $derived(
    engines === null
      ? []
      : (['normal', 'antidetect'] as api.ProfileKind[]).filter(
          (kind) =>
            profiles.some((profile) => profile.kind === kind) && !engineInstalled(kind)
        )
  );

  async function launchProfile(profile: api.ProfileView) {
    if (engineBusy !== '' || stopAllBusy) return;
    engineBusy = profile.id;
    errorText = '';
    notice = '';
    stopReport = null;

    try {
      const runtime = await api.profileLaunch(profile.id);
      notice = `профиль «${profile.name}» запущен · pid ${runtime.pid ?? '?'}`;
      await loadRuntimes();
    } catch (error) {
      const commandError = api.toCommandError(error);
      errorText =
        commandError.kind === 'engine_missing'
          ? `движок для этого профиля не установлен — ${commandError.message}`
          : api.describeError(commandError);
      await loadEngines();
    } finally {
      engineBusy = '';
    }
  }

  async function stopProfile(profile: api.ProfileView) {
    if (engineBusy !== '' || stopAllBusy) return;
    engineBusy = profile.id;
    errorText = '';
    notice = '';

    try {
      await api.profileStop(profile.id);
      notice = `профиль «${profile.name}» остановлен, данные зашифрованы`;
      await loadRuntimes();
    } catch (error) {
      errorText = api.describeError(api.toCommandError(error));
    } finally {
      engineBusy = '';
    }
  }

  async function stopAllProfiles() {
    if (stopAllBusy || engineBusy !== '') return;
    stopAllBusy = true;
    errorText = '';
    notice = '';

    try {
      stopReport = await api.profileStopAll();
      notice =
        stopReport.stopped.length > 0
          ? `остановлено профилей: ${stopReport.stopped.length}`
          : 'запущенных профилей не было';
      await loadRuntimes();
    } catch (error) {
      errorText = api.describeError(api.toCommandError(error));
    } finally {
      stopAllBusy = false;
    }
  }

  function shorten(value: string): string {
    return value.length <= 46 ? value : `…${value.slice(-45)}`;
  }
</script>

<div class="shell">
  <header class="bar">
    <img class="logo" src="/fousbrowser.svg" alt="" aria-hidden="true" />
    <span class="accent">FousBrowser</span>
    <span class="faint">launcher</span>
    <span class="spacer"></span>
    {#if status}
      <span class="faint" title={status.vault_path}>{shorten(status.vault_path)}</span>
    {/if}
  </header>

  <main class:wide={phase === 'ready'}>
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
      <section class="screen workspace">
        <header class="head">
          <h1><TerminalText text="ПРОФИЛИ" speed={14} cursor={false} /></h1>
          <span class="faint small">{profiles.length} шт.</span>
          <span class="spacer"></span>
          {#if runningCount > 0}
            <button
              class="danger"
              onclick={stopAllProfiles}
              disabled={stopAllBusy || engineBusy !== ''}
            >
              {stopAllBusy ? 'останавливаю все…' : `остановить все профили (${runningCount})`}
            </button>
          {/if}
          {#if panel === 'none'}
            <button class="ghost" onclick={() => { transferPassword = ''; transfer = { profileId: null }; }} disabled={working !== ''}>
              импорт профиля
            </button>
            <button class="primary" onclick={openCreate} disabled={working !== ''}>
              создать профиль
            </button>
          {/if}
        </header>

        {#if notice}
          <p class="ok small notice-line"><TerminalText text={notice} speed={12} /></p>
        {/if}

        {#if errorText}
          <p class="danger small">[x] {errorText}</p>
        {/if}

        {#if missingEngines.length > 0}
          <p class="warn small">
            [!] не установлен движок: {missingEngines
              .map((kind) => api.PROFILE_KIND_LABELS[kind])
              .join(', ')} — профили этого типа запустить нельзя, пока движок не установлен
          </p>
        {/if}

        {#if stopReport && stopReport.failed.length > 0}
          <div class="confirm">
            <p class="danger small">
              [x] не удалось остановить профилей: {stopReport.failed.length}
            </p>
            {#each stopReport.failed as failure (failure.profile_id)}
              <p class="faint small">— {failure.profile_id.slice(0, 8)}: {failure.message}</p>
            {/each}
          </div>
        {/if}

        {#if profiles.length === 0}
          <p class="dim empty">
            <TerminalText
              text="Хранилище пусто: предустановленных профилей нет. Создайте первый."
              speed={9}
            />
          </p>
        {:else}
          <ul class="profiles">
            {#each profiles as profile (profile.id)}
              <li class:pending={working === profile.id}>
                <div class="line">
                  <span class="name">{profile.name}</span>
                  <span class="kind" class:anti={profile.kind === 'antidetect'}>
                    {api.PROFILE_KIND_LABELS[profile.kind]}
                  </span>
                  <span class="faint small">
                    {profile.proxy
                      ? `${api.PROXY_SCHEME_LABELS[profile.proxy.scheme]} ${profile.proxy.host}:${profile.proxy.port}`
                      : 'без прокси'}
                  </span>
                  {#if runtimeOf(profile.id)?.running}
                    <span class="badge running">работает · pid {runtimeOf(profile.id)?.pid}</span>
                  {/if}
                  <span class="spacer"></span>
                  <span class="faint tiny">зерно {profile.seed.toString(16).padStart(8, '0')}</span>
                </div>

                {#if profile.note}
                  <div class="faint small note">{profile.note}</div>
                {/if}

                {#if runtimeOf(profile.id)?.plaintext}
                  <div class="data-state">
                    <span class="warn small">
                      данные расшифрованы: {runtimeOf(profile.id)?.plaintext_entries} файлов,
                      {api.formatBytes(runtimeOf(profile.id)?.plaintext_bytes ?? 0)}
                    </span>
                    <button
                      class="ghost"
                      onclick={() => stopProfile(profile)}
                      disabled={engineBusy !== '' || stopAllBusy}
                    >
                      зашифровать обратно
                    </button>
                  </div>
                {/if}

                <div class="actions">
                  {#if runtimeOf(profile.id)?.running}
                    <button
                      class="primary"
                      onclick={() => stopProfile(profile)}
                      disabled={engineBusy !== '' || stopAllBusy}
                    >
                      {engineBusy === profile.id ? 'останавливаю…' : 'остановить'}
                    </button>
                  {:else}
                    <button
                      class="primary"
                      onclick={() => launchProfile(profile)}
                      disabled={engineBusy !== '' || stopAllBusy || !engineInstalled(profile.kind)}
                    >
                      {engineBusy === profile.id ? 'запуск…' : 'запустить'}
                    </button>
                  {/if}
                  <button class="ghost" onclick={() => openEdit(profile)} disabled={working !== ''}>
                    изменить
                  </button>
                  <button class="ghost" onclick={() => { transferPassword = ''; transfer = { profileId: profile.id }; }} disabled={working !== '' || runtimeOf(profile.id)?.running || runtimeOf(profile.id)?.plaintext}>
                    экспорт
                  </button>
                  {#if profile.proxy}
                    <button class="ghost" onclick={() => checkProxy(profile)} disabled={working !== ''}>
                      {working === profile.id ? 'проверка…' : 'проверить прокси'}
                    </button>
                  {/if}
                  <button
                    class="ghost"
                    onclick={() => cloneProfile(profile)}
                    disabled={working !== ''}
                  >
                    клонировать
                  </button>
                  <button
                    class="ghost danger"
                    onclick={() => askDelete(profile)}
                    disabled={working !== '' || runtimeOf(profile.id)?.running}
                  >
                    удалить
                  </button>
                </div>

                {#if deleting?.id === profile.id}
                  <div class="confirm">
                    <p class="warn small">
                      <TerminalText
                        text="данные профиля будут стёрты безвозвратно. восстановить их нельзя"
                        speed={10}
                      />
                    </p>
                    <div class="actions">
                      <button class="danger" onclick={confirmDelete} disabled={working !== ''}>
                        {working === profile.id ? 'стирание…' : 'стереть безвозвратно'}
                      </button>
                      <button class="ghost" onclick={() => (deleting = null)} disabled={working !== ''}>
                        отмена
                      </button>
                    </div>
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}

        {#if transfer}
          <section class="confirm">
            <h2>{transfer.profileId ? 'Экспорт профиля' : 'Импорт профиля'}</h2>
            <p class="dim small">Введите мастер-пароль текущего хранилища. Для импорта пароли обоих хранилищ должны совпадать. Переносятся настройки и данные профиля; сохранённые браузером пароли и сеансы могут быть привязаны к Windows исходного компьютера.</p>
            <label for="transfer-password">мастер-пароль</label>
            <input id="transfer-password" type="password" autocomplete="current-password" bind:value={transferPassword} disabled={working !== ''} />
            <div class="actions">
              <button class="primary" onclick={transferProfile} disabled={working !== '' || !transferPassword}>{working === 'transfer' ? 'обработка…' : 'выбрать файл'}</button>
              <button class="ghost" onclick={() => { transfer = null; transferPassword = ''; }} disabled={working !== ''}>отмена</button>
            </div>
          </section>
        {/if}
        {#if panel !== 'none'}
          <div class="panel-slot">
            <ProfileForm
              mode={panel === 'edit' ? 'edit' : 'create'}
              profile={editing}
              busy={working !== ''}
              onsubmit={submitProfile}
              oncancel={closePanel}
            />
          </div>
        {/if}

        <footer class="actions tail">
          <button onclick={lockVault}>заблокировать хранилище</button>
          <button class="ghost" onclick={() => (showUpdates = !showUpdates)} disabled={working !== ''}>
            {showUpdates ? 'скрыть обновления' : 'обновления движков'}
          </button>
          <span class="spacer"></span>
          <span class="faint tiny">{outcome?.vault_id.slice(0, 8) ?? ''}</span>
        </footer>

        {#if showUpdates}
          <div class="panel-slot">
            <UpdatePanel onclose={() => (showUpdates = false)} oninstalled={() => void loadEngines()} />
          </div>
        {/if}

        {#if outcome && outcome.warnings.length > 0}
          <div class="warn-block">
            {#each outcome.warnings as warning (warning)}
              <p class="warn small">[!] {warning}</p>
            {/each}
          </div>
        {/if}
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

  /* Значок проекта в шапке: векторный, поэтому резкий на любом экране.
     Тот же знак, что у окна и на панели задач. */
  .logo {
    width: 20px;
    height: 20px;
    display: block;
    flex: none;
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

  /* Список профилей растёт вниз: центрировать его по вертикали не нужно. */
  main.wide {
    align-items: flex-start;
  }

  .workspace {
    width: 100%;
    max-width: 820px;
  }

  .head {
    display: flex;
    align-items: baseline;
    gap: 12px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--line);
  }

  .head h1 {
    font-size: 1.05em;
  }

  .notice-line {
    margin-top: 12px;
  }

  .empty {
    margin-top: 18px;
    font-size: 0.95em;
  }

  .profiles {
    margin: 16px 0 0;
    padding: 0;
    list-style: none;
  }

  .profiles li {
    padding: 14px 0;
    border-bottom: 1px solid var(--line-soft);
  }

  .profiles li.pending {
    opacity: 0.55;
  }

  .line {
    display: flex;
    align-items: baseline;
    gap: 12px;
  }

  .name {
    color: var(--fg);
    letter-spacing: 0.02em;
  }

  .kind {
    padding: 1px 7px;
    border: 1px solid var(--line);
    color: var(--fg-dim);
    font-size: 0.82em;
    letter-spacing: 0.08em;
  }

  .kind.anti {
    border-color: var(--accent-soft);
    color: var(--accent);
  }

  .note {
    margin-top: 6px;
  }

  /* Метка работы движка: не «пузырёк», а строка в терминальном стиле. */
  .badge {
    padding: 1px 7px;
    border: 1px solid var(--line);
    font-size: 0.82em;
    letter-spacing: 0.06em;
    color: var(--fg-dim);
  }

  .badge.running {
    border-color: var(--ok);
    color: var(--ok);
  }

  .data-state {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-top: 8px;
  }

  button.danger {
    border-color: var(--danger);
    color: var(--danger);
  }

  button.danger:hover:not(:disabled) {
    background: rgba(248, 113, 113, 0.08);
    border-color: var(--danger);
    color: var(--danger);
  }

  .confirm {
    margin-top: 12px;
    padding: 12px 14px;
    border: 1px solid var(--line);
    border-left: 2px solid var(--danger);
    background: var(--bg-inset);
  }

  .panel-slot {
    margin-top: 22px;
  }

  .tail {
    margin-top: 26px;
    padding-top: 14px;
    border-top: 1px solid var(--line-soft);
  }

  .warn-block {
    margin-top: 16px;
    padding: 12px 14px;
    border: 1px solid var(--line);
    border-left: 2px solid var(--warn);
    background: var(--bg-inset);
  }

  .tiny {
    font-size: 0.85em;
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

  .small {
    font-size: 0.9em;
  }
</style>
