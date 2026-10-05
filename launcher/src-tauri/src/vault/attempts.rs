//! Счётчик неудачных попыток входа.
//!
//! # Это НЕ граница безопасности
//!
//! Файл `attempts.json` лежит в открытом виде: до ввода пароля ключа ещё нет,
//! и подписывать счётчик нечем. Тот, кто может писать в файлы пользователя,
//! может сбросить счётчик и снять задержки.
//!
//! Реальная защита от перебора — Argon2id (256 МиБ, 3 итерации): перебор
//! экономически бессмыслен. Счётчик нужен, чтобы:
//!
//! 1. замедлить тупой перебор «в лоб» с чужого скрипта;
//! 2. подсказать пользователю, что он, вероятно, ошибается раскладкой.
//!
//! # Чего здесь принципиально НЕТ
//!
//! Автоудаления данных по числу неудачных попыток. Такого кода нет и не
//! должно появиться: он не защищал данные (перебор невозможен из-за Argon2id),
//! зато давал любому процессу под учётной записью пользователя способ
//! уничтожить хранилище за пару минут.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::error::Result;
use crate::paths;

/// После стольких неудач подряд требуется явное подтверждение продолжения.
/// Данные при этом остаются на месте.
pub const MAX_ATTEMPTS_BEFORE_CONFIRMATION: u32 = 100;

/// С этого числа неудач интерфейс показывает предупреждение.
pub const WARN_AT_ATTEMPTS: u32 = 90;

/// Имя файла счётчика внутри каталога хранилища.
pub const FILE_NAME: &str = "attempts.json";

/// Состояние счётчика неудачных попыток.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AttemptsState {
    pub vault_id: String,
    /// Число неудачных попыток подряд.
    pub failed: u32,
    /// Время последней неудачной попытки (Unix, секунды).
    pub last_failed_unix: u64,
    /// Требуется явное подтверждение продолжения (порог достигнут).
    pub confirm_required: bool,
}

impl AttemptsState {
    pub fn new(vault_id: &str) -> Self {
        Self {
            vault_id: vault_id.to_string(),
            failed: 0,
            last_failed_unix: 0,
            confirm_required: false,
        }
    }

    /// Путь к файлу счётчика внутри указанного каталога хранилища.
    pub fn path_in(vault_dir: &Path) -> PathBuf {
        vault_dir.join(FILE_NAME)
    }

    /// Читает счётчик из каталога хранилища.
    ///
    /// Отсутствующий, повреждённый или относящийся к другому хранилищу файл
    /// трактуется как «попыток не было» — в пользу пользователя, потому что
    /// ошибиться в сторону ужесточения здесь означало бы запереть владельца.
    pub fn load(vault_dir: &Path, vault_id: &str) -> Self {
        let path = Self::path_in(vault_dir);
        let Ok(bytes) = std::fs::read(&path) else {
            return Self::new(vault_id);
        };
        match serde_json::from_slice::<Self>(&bytes) {
            Ok(state) if state.vault_id == vault_id => state,
            _ => Self::new(vault_id),
        }
    }

    /// Записывает счётчик атомарно.
    pub fn store(&self, vault_dir: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        paths::write_atomic(&Self::path_in(vault_dir), &bytes)?;
        Ok(())
    }

    /// Задержка перед следующей попыткой: после каждых 5 неудач растёт.
    ///
    /// 0 → 0 с, 5 → 5 с, 10 → 30 с, 15 → 2 мин, 20 → 10 мин, 25+ → 1 ч.
    pub fn backoff_secs(&self) -> u64 {
        match self.failed / 5 {
            0 => 0,
            1 => 5,
            2 => 30,
            3 => 120,
            4 => 600,
            _ => 3600,
        }
    }

    /// Сколько секунд ещё нужно подождать на момент `now`.
    pub fn remaining_backoff(&self, now: u64) -> u64 {
        let ready_at = self.last_failed_unix.saturating_add(self.backoff_secs());
        ready_at.saturating_sub(now)
    }

    /// Пора показать предупреждение о большом числе неудач.
    pub fn should_warn(&self) -> bool {
        self.failed >= WARN_AT_ATTEMPTS
    }

    /// Регистрирует неудачную попытку.
    ///
    /// Вызывается ДО проверки пароля, чтобы счётчик не зависел от того,
    /// успел ли процесс упасть во время вывода ключа.
    pub fn register_failure(&mut self, now: u64) {
        self.failed = self.failed.saturating_add(1);
        self.last_failed_unix = now;
        if self.failed >= MAX_ATTEMPTS_BEFORE_CONFIRMATION {
            self.confirm_required = true;
        }
    }

    /// Сбрасывает счётчик после успешного входа.
    pub fn reset(&mut self) {
        self.failed = 0;
        self.last_failed_unix = 0;
        self.confirm_required = false;
    }

    /// Пользователь подтвердил продолжение попыток.
    ///
    /// Счётчик неудач НЕ обнуляется — иначе подтверждение было бы способом
    /// бесконечно обходить порог.
    pub fn confirm_continue(&mut self) {
        self.confirm_required = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn backoff_grows_in_steps() {
        let mut state = AttemptsState::new(VAULT);
        let expected = [(0u32, 0u64), (4, 0), (5, 5), (9, 5), (10, 30), (14, 30), (15, 120), (19, 120), (20, 600), (24, 600), (25, 3600), (500, 3600)];
        for (failed, secs) in expected {
            state.failed = failed;
            assert_eq!(state.backoff_secs(), secs, "для {failed} неудач");
        }
    }

    #[test]
    fn remaining_backoff_counts_down() {
        let mut state = AttemptsState::new(VAULT);
        state.failed = 5;
        state.last_failed_unix = 1_000;
        assert_eq!(state.remaining_backoff(1_000), 5);
        assert_eq!(state.remaining_backoff(1_003), 2);
        assert_eq!(state.remaining_backoff(1_005), 0);
        assert_eq!(state.remaining_backoff(2_000), 0);
    }

    #[test]
    fn confirmation_is_required_at_threshold_and_never_deletes() {
        let mut state = AttemptsState::new(VAULT);
        for _ in 0..MAX_ATTEMPTS_BEFORE_CONFIRMATION - 1 {
            state.register_failure(0);
        }
        assert_eq!(state.failed, MAX_ATTEMPTS_BEFORE_CONFIRMATION - 1);
        assert!(!state.confirm_required);

        state.register_failure(0);
        assert_eq!(state.failed, MAX_ATTEMPTS_BEFORE_CONFIRMATION);
        assert!(state.confirm_required);

        // счётчик продолжает расти, но ни одно поле не означает удаление
        state.register_failure(0);
        assert_eq!(state.failed, MAX_ATTEMPTS_BEFORE_CONFIRMATION + 1);
    }

    #[test]
    fn confirm_continue_keeps_the_counter() {
        let mut state = AttemptsState::new(VAULT);
        state.failed = MAX_ATTEMPTS_BEFORE_CONFIRMATION;
        state.confirm_required = true;
        state.confirm_continue();
        assert!(!state.confirm_required);
        assert_eq!(
            state.failed, MAX_ATTEMPTS_BEFORE_CONFIRMATION,
            "подтверждение не должно обнулять счётчик"
        );
    }

    #[test]
    fn warning_threshold() {
        let mut state = AttemptsState::new(VAULT);
        state.failed = WARN_AT_ATTEMPTS - 1;
        assert!(!state.should_warn());
        state.failed = WARN_AT_ATTEMPTS;
        assert!(state.should_warn());
    }

    #[test]
    fn success_resets_everything() {
        let mut state = AttemptsState::new(VAULT);
        for _ in 0..30 {
            state.register_failure(5);
        }
        state.reset();
        assert_eq!(state, AttemptsState::new(VAULT));
    }

    #[test]
    fn store_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = AttemptsState::new(VAULT);
        for _ in 0..7 {
            state.register_failure(123);
        }
        state.store(dir.path()).unwrap();

        let loaded = AttemptsState::load(dir.path(), VAULT);
        assert_eq!(loaded, state);
    }

    #[test]
    fn state_from_another_vault_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let mut other = AttemptsState::new("другое-хранилище");
        other.failed = 50;
        other.store(dir.path()).unwrap();

        let loaded = AttemptsState::load(dir.path(), VAULT);
        assert_eq!(loaded.failed, 0, "чужой счётчик не должен влиять на это хранилище");
    }

    #[test]
    fn corrupted_file_does_not_lock_the_owner_out() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(AttemptsState::path_in(dir.path()), b"{ definitely not json").unwrap();
        let loaded = AttemptsState::load(dir.path(), VAULT);
        assert_eq!(loaded.failed, 0);
    }
}
