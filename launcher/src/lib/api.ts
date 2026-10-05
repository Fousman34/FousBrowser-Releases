/**
 * Типизированный слой IPC: единственное место, где фронтенд знает
 * о командах Rust. Все имена команд должны совпадать с `invoke_handler`
 * в `src-tauri/src/lib.rs`.
 */
import { invoke } from '@tauri-apps/api/core';

export interface PasswordReport {
  length: number;
  min_length: number;
  acceptable: boolean;
  has_lowercase: boolean;
  has_uppercase: boolean;
  has_digit: boolean;
  has_symbol: boolean;
  /** 0..=4 — для индикатора сложности. */
  score: number;
  recommendations: string[];
}

export interface VaultStatus {
  exists: boolean;
  unlocked: boolean;
  vault_path: string;
  password_min_length: number;
  failed_attempts: number;
  warn_attempts: boolean;
  confirm_required: boolean;
  backoff_seconds: number;
}

export interface UnlockOutcome {
  vault_id: string;
  profiles: number;
  warnings: string[];
}

export interface AttemptsState {
  vault_id: string;
  failed: number;
  last_failed_unix: number;
  confirm_required: boolean;
}

/** Ошибка команды Rust в том виде, в каком её сериализует `CommandError`. */
export interface CommandError {
  kind:
    | 'not_found'
    | 'already_exists'
    | 'wrong_password'
    | 'weak_password'
    | 'invalid'
    | 'corrupted'
    | 'locked'
    | 'backoff'
    | 'confirmation_required'
    | 'io'
    | 'json'
    | 'crypto'
    | 'engine_missing'
    | 'engine_failed'
    | 'already_running'
    | 'not_running'
    | 'proxy_bridge_required'
    | 'unknown';
  message: string;
  seconds?: number | null;
  attempts?: number | null;
}

export type ProfileKind = 'normal' | 'antidetect';

export type ProxyScheme = 'socks5' | 'http' | 'https';

/** Настройки прокси в том виде, в каком их отдаёт ядро: без пароля. */
export interface ProxyView {
  scheme: ProxyScheme;
  host: string;
  port: number;
  username: string | null;
  /** Задан ли пароль. Сам пароль остаётся в зашифрованных метаданных. */
  has_password: boolean;
}

/** Профиль для интерфейса. */
export interface ProfileView {
  id: string;
  name: string;
  kind: ProfileKind;
  /** Зерно отпечатка: у каждого профиля своё. */
  seed: number;
  created_unix: number;
  engine_version: string | null;
  note: string | null;
  proxy: ProxyView | null;
}

/** Настройки прокси, отправляемые в ядро. */
export interface ProxyInput {
  scheme: ProxyScheme;
  host: string;
  port: number;
  username?: string | null;
  /** `null` — сохранить прежний пароль, пустая строка — убрать его. */
  password?: string | null;
}

export interface ProfileDraft {
  name: string;
  kind: ProfileKind;
  proxy: ProxyInput | null;
  note: string | null;
}

export const PROFILE_KIND_LABELS: Record<ProfileKind, string> = {
  normal: 'Normal',
  antidetect: 'Antidetect',
};

export const PROFILE_KIND_HINTS: Record<ProfileKind, string> = {
  normal: 'стоковый Chromium без патчей — повседневный сёрфинг',
  antidetect: 'Chromium с подменой отпечатка — там, где важна анонимность',
};

export const PROXY_SCHEME_LABELS: Record<ProxyScheme, string> = {
  socks5: 'SOCKS5',
  http: 'HTTP',
  https: 'HTTPS',
};

export const PROXY_DEFAULT_PORTS: Record<ProxyScheme, number> = {
  socks5: 1080,
  http: 8080,
  https: 8080,
};

export const MIN_PASSWORD_LENGTH = 12;

export function vaultStatus(): Promise<VaultStatus> {
  return invoke('vault_status');
}

export function passwordReport(password: string): Promise<PasswordReport> {
  return invoke('password_report', { password });
}

export function vaultCreate(password: string): Promise<UnlockOutcome> {
  return invoke('vault_create', { password });
}

export function vaultUnlock(password: string): Promise<UnlockOutcome> {
  return invoke('vault_unlock', { password });
}

export function vaultLock(): Promise<void> {
  return invoke('vault_lock');
}

export function vaultConfirmContinue(): Promise<VaultStatus> {
  return invoke('vault_confirm_continue');
}

export function vaultAttempts(): Promise<AttemptsState> {
  return invoke('vault_attempts');
}

// --- профили ---------------------------------------------------------------

export function profileList(): Promise<ProfileView[]> {
  return invoke('profile_list');
}

export function profileCreate(draft: ProfileDraft): Promise<ProfileView> {
  return invoke('profile_create', {
    name: draft.name,
    kind: draft.kind,
    proxy: draft.proxy,
    note: draft.note,
  });
}

/** Клонирование: те же настройки, новое зерно отпечатка. */
export function profileClone(profileId: string, name?: string | null): Promise<ProfileView> {
  return invoke('profile_clone', { profileId, name: name ?? null });
}

export function profileUpdate(
  profileId: string,
  draft: Pick<ProfileDraft, 'name' | 'kind' | 'note'>
): Promise<ProfileView> {
  return invoke('profile_update', {
    profileId,
    name: draft.name,
    kind: draft.kind,
    note: draft.note,
  });
}

/** `null` снимает привязку прокси. */
export function profileSetProxy(
  profileId: string,
  proxy: ProxyInput | null
): Promise<ProfileView> {
  return invoke('profile_set_proxy', { profileId, proxy });
}

/** Удаляет профиль и безвозвратно стирает его данные. Возвращает число оставшихся. */
export function profileDelete(profileId: string): Promise<number> {
  return invoke('profile_delete', { profileId });
}

// --- движки и запуск профилей ----------------------------------------------

/** Какие движки установлены на этом устройстве. */
export interface EngineStatus {
  normal_installed: boolean;
  normal_version: string | null;
  antidetect_installed: boolean;
  antidetect_version: string | null;
}

/** Что известно о запуске профиля и состоянии его данных на диске. */
export interface RuntimeView {
  profile_id: string;
  running: boolean;
  pid: number | null;
  engine_version: string | null;
  started_unix: number | null;
  /** Есть ли расшифрованная копия данных на диске. */
  plaintext: boolean;
  plaintext_entries: number;
  plaintext_bytes: number;
}

/** Смена состояния профиля, приходящая из ядра событием `profile://state`. */
export interface ProfileStateEvent {
  profile_id: string;
  state: 'running' | 'stopping' | 'stopped' | 'error';
  pid: number | null;
  message: string | null;
}

export interface StopFailure {
  profile_id: string;
  message: string;
}

export interface StopAllReport {
  stopped: string[];
  failed: StopFailure[];
}

export function engineStatus(): Promise<EngineStatus> {
  return invoke('engine_status');
}

export function profileRuntimeList(): Promise<RuntimeView[]> {
  return invoke('profile_runtime_list');
}

/** Расшифровывает данные профиля и запускает движок. */
export function profileLaunch(profileId: string): Promise<RuntimeView> {
  return invoke('profile_launch', { profileId });
}

/** Закрывает движок и шифрует данные профиля обратно. */
export function profileStop(profileId: string): Promise<RuntimeView> {
  return invoke('profile_stop', { profileId });
}

/** Одна кнопка: закрыть все движки и зашифровать все данные. */
export function profileStopAll(): Promise<StopAllReport> {
  return invoke('profile_stop_all');
}

/** Человекочитаемый размер: 1536 → «1,5 КиБ». */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} Б`;
  const units = ['КиБ', 'МиБ', 'ГиБ'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0).replace('.', ',')} ${units[unit]}`;
}

// --- обновления движков ------------------------------------------------------

export type UpdateChannel = 'normal' | 'antidetect';

/** Найденное обновление. */
export interface Release {
  channel: UpdateChannel;
  version: string;
  notes: string;
  asset_name: string;
  asset_url: string;
  size: number | null;
  sha256: string | null;
  sums_url: string | null;
  signature_url: string | null;
  page_url: string;
}

/** Состояние одного канала. */
export interface UpdateStateRow {
  channel: UpdateChannel;
  label: string;
  installed: string | null;
  candidate: Release | null;
}

export interface UpdateProgressEvent {
  channel: UpdateChannel;
  version: string;
  received: number;
  total: number | null;
  percent: number | null;
}

export interface UpdateLogEvent {
  channel: UpdateChannel;
  line: string;
}

export interface UpdateDoneEvent {
  channel: UpdateChannel;
  version: string;
  executable: string;
}

export interface UpdateErrorEvent {
  channel: UpdateChannel;
  message: string;
}

export function updateState(): Promise<UpdateStateRow[]> {
  return invoke('update_state');
}

/** Проверяет обновление в канале. Возвращает `null`, если обновления нет. */
export function updateCheck(channel: UpdateChannel): Promise<Release | null> {
  return invoke('update_check', { channel });
}

/** Ставит обновление. Прогресс и журнал приходят событиями. */
export function updateInstall(channel: UpdateChannel, version: string): Promise<void> {
  return invoke('update_install', { channel, version });
}

/** Перезапускает лаунчер. */
export function appRestart(): Promise<void> {
  return invoke('app_restart');
}

export const UPDATE_CHANNEL_HINTS: Record<UpdateChannel, string> = {
  normal: 'стоковый Chromium из официального канала',
  antidetect: 'наш форк с подменой отпечатка: релизы GitHub с обязательной GPG-подписью'
};

/**
 * Приводит любое исключение к `CommandError`.
 *
 * Tauri отклоняет промис сериализованной ошибкой команды, но при сбое
 * самого канала связи приходит строка — её тоже нужно показать человеку.
 */
export function toCommandError(error: unknown): CommandError {
  if (typeof error === 'object' && error !== null && 'message' in error) {
    const candidate = error as Partial<CommandError>;
    return {
      kind: candidate.kind ?? 'unknown',
      message: String(candidate.message),
      seconds: candidate.seconds ?? null,
      attempts: candidate.attempts ?? null,
    };
  }
  return { kind: 'unknown', message: String(error), seconds: null, attempts: null };
}

/** Текст предупреждения для показа в терминальной строке. */
export function describeError(error: CommandError): string {
  switch (error.kind) {
    case 'wrong_password':
      return 'неверный мастер-пароль';
    case 'weak_password':
      return `пароль не принят: ${error.message}`;
    case 'already_exists':
      return 'хранилище уже существует';
    case 'not_found':
      // Ядро само называет объект: «профиль …», «хранилище не найдено: …».
      return error.message;
    case 'backoff':
      return `слишком много попыток: подождите ${formatDuration(error.seconds ?? 0)}`;
    case 'confirmation_required':
      return `после ${error.attempts ?? 100} неудачных попыток нужно подтверждение. Данные не удалены`;
    case 'corrupted':
      return `хранилище повреждено: ${error.message}`;
    case 'locked':
      return 'хранилище заблокировано';
    case 'engine_missing':
      return `движок не установлен: ${error.message}`;
    case 'engine_failed':
      return `движок не запустился: ${error.message}`;
    case 'already_running':
      return 'этот профиль уже запущен';
    case 'not_running':
      return 'этот профиль не запущен';
    case 'proxy_bridge_required':
      return error.message;
    case 'invalid':
      return error.message;
    default:
      return error.message;
  }
}

/** Человекочитаемая длительность: 95 → «1 мин 35 с». */
export function formatDuration(totalSeconds: number): string {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  if (seconds < 60) return `${seconds} с`;

  const minutes = Math.floor(seconds / 60);
  const restSeconds = seconds % 60;
  if (minutes < 60) {
    return restSeconds === 0 ? `${minutes} мин` : `${minutes} мин ${restSeconds} с`;
  }

  const hours = Math.floor(minutes / 60);
  const restMinutes = minutes % 60;
  return restMinutes === 0 ? `${hours} ч` : `${hours} ч ${restMinutes} мин`;
}
/** Native dialogs keep archive bytes out of the webview. */
export function profileTransfer(profileId: string | null, password: string): Promise<string | null> {
  return invoke('profile_transfer', { profileId, password });
}

export function profileCheckProxy(profileId: string): Promise<void> {
  return invoke('profile_check_proxy', { profileId });
}
