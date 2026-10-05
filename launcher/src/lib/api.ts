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
    | 'corrupted'
    | 'locked'
    | 'backoff'
    | 'confirmation_required'
    | 'io'
    | 'json'
    | 'crypto'
    | 'unknown';
  message: string;
  seconds?: number | null;
  attempts?: number | null;
}

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
      return 'хранилище не найдено';
    case 'backoff':
      return `слишком много попыток: подождите ${formatDuration(error.seconds ?? 0)}`;
    case 'confirmation_required':
      return `после ${error.attempts ?? 100} неудачных попыток нужно подтверждение. Данные не удалены`;
    case 'corrupted':
      return `хранилище повреждено: ${error.message}`;
    case 'locked':
      return 'хранилище заблокировано';
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
