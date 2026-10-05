//! Сравнение версий движков.
//!
//! Версии Chromium — числовые с точками (`121.0.6167.85`), версии наших
//! релизов движка — тоже (`antidetect-v121.0.6167.85`). Сравнение идёт по
//! числовым отрезкам: строка вида `1.10` обязана быть новее `1.9`, а не
//! «меньше по алфавиту» — именно на этом ломаются наивные сравнения строк.

/// Разбирает версию в последовательность чисел.
///
/// Всё, что не является цифрой, служит разделителем: `v121.0.6167.85`,
/// `antidetect-v121.0.6167.85` и `121.0.6167.85` дают одно и то же.
pub fn segments(version: &str) -> Vec<u64> {
    let mut result = Vec::new();
    let mut current = String::new();

    for character in version.chars() {
        if character.is_ascii_digit() {
            current.push(character);
        } else if !current.is_empty() {
            // Слишком длинный отрезок не должен ломать разбор: берём то,
            // что помещается, а остальное игнорируем.
            if let Ok(number) = current.parse::<u64>() {
                result.push(number);
            }
            current.clear();
        }
    }
    if !current.is_empty() {
        if let Ok(number) = current.parse::<u64>() {
            result.push(number);
        }
    }
    result
}

/// Новее ли `candidate`, чем `current`.
///
/// Если версии совпадают по всем отрезкам, результат — `false`:
/// обновляться на ту же версию незачем. Пустая или непонятная строка
/// «новее» не считается.
pub fn is_newer(candidate: &str, current: Option<&str>) -> bool {
    let candidate = segments(candidate);
    if candidate.is_empty() {
        return false;
    }
    let Some(current) = current else {
        return true;
    };
    let current = segments(current);
    if current.is_empty() {
        return true;
    }

    let length = candidate.len().max(current.len());
    for index in 0..length {
        let left = candidate.get(index).copied().unwrap_or(0);
        let right = current.get(index).copied().unwrap_or(0);
        if left != right {
            return left > right;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_ignore_prefixes_and_separators() {
        assert_eq!(segments("121.0.6167.85"), vec![121, 0, 6167, 85]);
        assert_eq!(segments("v121.0.6167.85"), vec![121, 0, 6167, 85]);
        assert_eq!(segments("antidetect-v121.0.6167.85"), vec![121, 0, 6167, 85]);
        assert_eq!(segments(""), Vec::<u64>::new());
        assert_eq!(segments("нет цифр"), Vec::<u64>::new());
    }

    #[test]
    fn numeric_comparison_is_not_lexicographic() {
        assert!(is_newer("1.10", Some("1.9")), "1.10 новее 1.9");
        assert!(!is_newer("1.9", Some("1.10")));
        assert!(is_newer("121.0.6167.85", Some("121.0.6167.84")));
        assert!(is_newer("122.0.0.0", Some("121.9999.9999.9999")));
    }

    #[test]
    fn equal_versions_are_not_an_update() {
        assert!(!is_newer("121.0.6167.85", Some("121.0.6167.85")));
        assert!(!is_newer("1.2.0", Some("1.2")));
        assert!(!is_newer("1.2", Some("1.2.0")));
    }

    #[test]
    fn anything_is_newer_than_nothing() {
        assert!(is_newer("1.0.0", None));
        assert!(!is_newer("", None));
        assert!(!is_newer("мусор", Some("1.0")));
        assert!(is_newer("1.0", Some("мусор")));
    }

    #[test]
    fn longer_version_with_equal_prefix_is_newer() {
        assert!(is_newer("121.0.6167.85.1", Some("121.0.6167.85")));
        assert!(!is_newer("121.0.6167", Some("121.0.6167.85")));
    }
}
