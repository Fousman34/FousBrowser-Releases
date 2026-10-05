<script lang="ts">
  /**
   * Форма профиля: создание и правка.
   *
   * Одна форма на оба случая: поля и правила проверки совпадают, а разное
   * поведение сводится к тексту кнопки и к тому, что в режиме правки пароль
   * прокси не переспрашивается.
   */
  import TerminalText from './TerminalText.svelte';
  import TypedHint from './TypedHint.svelte';
  import * as api from '$lib/api';
  import { untrack } from 'svelte';

  interface Props {
    mode: 'create' | 'edit';
    profile?: api.ProfileView | null;
    busy?: boolean;
    onsubmit: (draft: api.ProfileDraft) => void;
    oncancel: () => void;
  }

  let { mode, profile = null, busy = false, onsubmit, oncancel }: Props = $props();

  // Форма заполняется значениями профиля один раз, при появлении.
  // Дальше это самостоятельные поля: реактивная привязка к prop затирала бы
  // то, что человек уже ввёл. untrack делает намерение явным и для
  // компилятора, и для читателя.
  const initial = untrack(() => profile);

  let name = $state(initial?.name ?? '');
  let kind = $state<api.ProfileKind>(initial?.kind ?? 'normal');
  let note = $state(initial?.note ?? '');
  let restoreTabs = $state(initial?.restore_tabs ?? true);

  let useProxy = $state(Boolean(initial?.proxy));
  let scheme = $state<api.ProxyScheme>(initial?.proxy?.scheme ?? 'socks5');
  let host = $state(initial?.proxy?.host ?? '');
  let port = $state(String(initial?.proxy?.port ?? api.PROXY_DEFAULT_PORTS.socks5));
  let username = $state(initial?.proxy?.username ?? '');
  let password = $state('');

  let localError = $state('');
  let hintFor = $state('');

  const KINDS: api.ProfileKind[] = ['normal', 'antidetect'];
  const SCHEMES: api.ProxyScheme[] = ['socks5', 'http', 'https'];

  /** Пароль уже лежит в зашифрованных метаданных. */
  const storedPassword = initial?.proxy?.has_password ?? false;

  /** Смена схемы подставляет её порт по умолчанию, но не затирает свой. */
  function changeScheme(next: api.ProxyScheme) {
    const previousDefault = api.PROXY_DEFAULT_PORTS[scheme];
    if (port === '' || Number(port) === previousDefault) {
      port = String(api.PROXY_DEFAULT_PORTS[next]);
    }
    scheme = next;
  }

  function submit() {
    localError = '';

    const trimmed = name.trim();
    if (trimmed.length === 0) {
      localError = 'имя профиля не может быть пустым';
      return;
    }
    if (trimmed.length > 64) {
      localError = 'имя профиля длиннее 64 символов';
      return;
    }

    let proxy: api.ProxyInput | null = null;
    if (useProxy) {
      const trimmedHost = host.trim();
      if (trimmedHost.length === 0) {
        localError = 'адрес прокси не может быть пустым';
        return;
      }
      const portNumber = Number(port);
      if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
        localError = 'порт прокси должен быть числом от 1 до 65535';
        return;
      }
      proxy = {
        scheme,
        host: trimmedHost,
        port: portNumber,
        username: username.trim() || null,
        // Пустое поле — «не менять сохранённый пароль»; убрать его можно,
        // очистив имя пользователя.
        password: password === '' ? null : password,
      };
    }

    onsubmit({ name: trimmed, kind, proxy, note: note.trim() || null, restore_tabs: restoreTabs });
  }
</script>

<section class="screen form">
  <h2>
    <TerminalText
      text={mode === 'create' ? 'НОВЫЙ ПРОФИЛЬ' : 'ПРАВКА ПРОФИЛЯ'}
      speed={14}
      cursor={false}
    />
  </h2>

  <div class="field">
    <div class="label-row">
      <label for="profile-name">имя</label>
      <TypedHint
        hint="имя видно только внутри лаунчера: в метаданных оно зашифровано"
        active={hintFor === 'name'}
      />
    </div>
    <input
      id="profile-name"
      bind:value={name}
      disabled={busy}
      spellcheck="false"
      placeholder="например, Основной"
      onfocus={() => (hintFor = 'name')}
      onblur={() => (hintFor = '')}
      onmouseenter={() => (hintFor = 'name')}
      onmouseleave={() => (hintFor = '')}
    />
  </div>

  <div class="field">
    <div class="label-row">
      <span class="label">тип</span>
      <TypedHint
        hint={api.PROFILE_KIND_HINTS[kind]}
        active={hintFor === 'kind'}
      />
    </div>
    <div
      class="row"
      role="group"
      aria-label="тип профиля"
      onmouseenter={() => (hintFor = 'kind')}
      onmouseleave={() => (hintFor = '')}
    >
      {#each KINDS as option (option)}
        <button
          type="button"
          class:selected={kind === option}
          disabled={busy}
          onclick={() => (kind = option)}
        >
          {api.PROFILE_KIND_LABELS[option]}
        </button>
      {/each}
    </div>
  </div>

  <div class="field">
    <label class="toggle">
      <input type="checkbox" bind:checked={restoreTabs} disabled={busy} />
      <span>продолжать с открытых вкладок</span>
    </label>
    <p class="faint">Включено: вкладки и окна восстанавливаются при запуске профиля. Выключено: используются настройки запуска самого браузера. Новая вкладка — страница FousBrowser.</p>
  </div>

  <div class="field">
    <div class="label-row">
      <label class="toggle">
        <input type="checkbox" bind:checked={useProxy} disabled={busy} />
        <span>прокси для этого профиля</span>
      </label>
      <TypedHint
        hint="логин и пароль хранятся зашифрованными и не попадают в командную строку"
        active={hintFor === 'proxy'}
      />
    </div>

    {#if useProxy}
      <div
        class="proxy"
        role="group"
        aria-label="настройки прокси"
        onmouseenter={() => (hintFor = 'proxy')}
        onmouseleave={() => (hintFor = '')}
      >
        <div class="row">
          {#each SCHEMES as option (option)}
            <button
              type="button"
              class:selected={scheme === option}
              disabled={busy}
              onclick={() => changeScheme(option)}
            >
              {api.PROXY_SCHEME_LABELS[option]}
            </button>
          {/each}
        </div>

        <div class="pair">
          <div>
            <label for="proxy-host">адрес</label>
            <input id="proxy-host" bind:value={host} disabled={busy} spellcheck="false" placeholder="127.0.0.1" />
          </div>
          <div class="port">
            <label for="proxy-port">порт</label>
            <input id="proxy-port" bind:value={port} disabled={busy} inputmode="numeric" />
          </div>
        </div>

        <div class="pair">
          <div>
            <label for="proxy-user">логин</label>
            <input id="proxy-user" bind:value={username} disabled={busy} spellcheck="false" />
          </div>
          <div>
            <label for="proxy-pass">пароль</label>
            <input
              id="proxy-pass"
              type="password"
              bind:value={password}
              disabled={busy}
              autocomplete="off"
              placeholder={storedPassword ? 'сохранён — оставьте пустым' : 'не задан'}
            />
          </div>
        </div>
      </div>
    {/if}
  </div>

  <div class="field">
    <label for="profile-note">заметка (необязательно)</label>
    <input id="profile-note" bind:value={note} disabled={busy} placeholder="для чего этот профиль" />
  </div>

  {#if localError}
    <p class="danger small">[x] {localError}</p>
  {/if}

  <div class="actions">
    <button class="primary" onclick={submit} disabled={busy}>
      {busy ? 'запись…' : mode === 'create' ? 'создать профиль' : 'сохранить'}
    </button>
    <button class="ghost" onclick={oncancel} disabled={busy}>отмена</button>
  </div>
</section>

<style>
  .form {
    border: 1px solid var(--line);
    background: var(--bg-panel);
    padding: 22px 24px;
  }

  h2 {
    font-size: 1em;
    letter-spacing: 0.04em;
  }

  .field {
    margin-top: 18px;
  }

  label,
  .label {
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

  .label-row label,
  .label-row .label {
    margin-bottom: 0;
    white-space: nowrap;
  }

  .toggle {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 0;
    cursor: pointer;
    white-space: nowrap;
  }

  .toggle input {
    width: auto;
    margin: 0;
  }

  .row {
    display: flex;
    gap: 8px;
  }

  .row button.selected {
    border-color: var(--accent);
    color: var(--accent);
    background: rgba(183, 154, 255, 0.08);
  }

  .proxy {
    margin-top: 12px;
    padding: 14px;
    border: 1px solid var(--line);
    border-left: 2px solid var(--accent-soft);
    background: var(--bg-inset);
  }

  .pair {
    display: grid;
    grid-template-columns: 1fr 110px;
    gap: 10px;
    margin-top: 12px;
  }

  .pair > div > label {
    margin-bottom: 6px;
  }

  .small {
    font-size: 0.9em;
  }
</style>
