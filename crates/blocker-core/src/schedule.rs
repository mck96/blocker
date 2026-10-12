//! Time-window scheduling. The core stays time-source agnostic: the daemon
//! passes in the current weekday and minute-of-day (derived from the system
//! clock) and this module decides whether a schedule is active.

use serde::{Deserialize, Serialize};

/// A recurring window during which blocking is enforced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Window {
    /// Days the window applies to. 0 = Monday … 6 = Sunday.
    pub days: Vec<u8>,
    /// Inclusive start, minutes since midnight (0..=1439).
    pub start_min: u16,
    /// Exclusive end, minutes since midnight (1..=1440). May be <= start_min
    /// to express a window that wraps past midnight.
    pub end_min: u16,
}

impl Window {
    pub fn contains(&self, weekday_mon0: u8, minute_of_day: u16) -> bool {
        if self.start_min <= self.end_min {
            // Same-day window.
            self.days.contains(&weekday_mon0)
                && minute_of_day >= self.start_min
                && minute_of_day < self.end_min
        } else {
            // Wraps past midnight: e.g. 22:00 -> 06:00.
            let in_evening =
                self.days.contains(&weekday_mon0) && minute_of_day >= self.start_min;
            let prev_day = (weekday_mon0 + 6) % 7;
            let in_morning = self.days.contains(&prev_day) && minute_of_day < self.end_min;
            in_evening || in_morning
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schedule {
    #[serde(default)]
    pub windows: Vec<Window>,
}

impl Schedule {
    pub fn is_active(&self, weekday_mon0: u8, minute_of_day: u16) -> bool {
        self.windows
            .iter()
            .any(|w| w.contains(weekday_mon0, minute_of_day))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_day_window() {
        let w = Window {
            days: vec![0, 1, 2, 3, 4],
            start_min: 9 * 60,
            end_min: 17 * 60,
        };
        assert!(w.contains(0, 10 * 60));
        assert!(!w.contains(0, 8 * 60));
        assert!(!w.contains(5, 10 * 60)); // Saturday
    }

    #[test]
    fn wrapping_window() {
        // 22:00 Mon -> 06:00 Tue
        let w = Window {
            days: vec![0],
            start_min: 22 * 60,
            end_min: 6 * 60,
        };
        assert!(w.contains(0, 23 * 60)); // Mon 23:00
        assert!(w.contains(1, 5 * 60)); // Tue 05:00 (spillover)
        assert!(!w.contains(1, 7 * 60));
    }
}
