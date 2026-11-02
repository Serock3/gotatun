// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Finite, repeated-trial search. The loss budget must hold in every repetition.
use anyhow::{Result, ensure};
use clap::Args;
use serde::Serialize;

#[derive(Args, Serialize)]
pub struct Options {
    #[arg(long, default_value_t = 2.0)]
    pub min_gbps: f64,
    #[arg(long, default_value_t = 4.0)]
    pub max_gbps: f64,
    #[arg(long, default_value_t = 0.125)]
    pub resolution_gbps: f64,
    /// Maximum packet loss percentage, required in every repetition.
    #[arg(long, default_value_t = 0.1)]
    pub loss_budget_percent: f64,
}

impl Options {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.min_gbps.is_finite()
                && self.max_gbps.is_finite()
                && self.resolution_gbps.is_finite()
                && (0.5..=9.0).contains(&self.min_gbps)
                && (0.5..=9.0).contains(&self.max_gbps)
                && self.min_gbps < self.max_gbps
                && self.resolution_gbps >= 0.01
                && self.resolution_gbps <= self.max_gbps - self.min_gbps,
            "search needs 0.5 <= min < max <= 9 Gb/s and a resolution of at least 0.01 Gb/s"
        );
        ensure!(
            self.loss_budget_percent.is_finite() && (0.0..=5.0).contains(&self.loss_budget_percent),
            "loss budget must be 0–5 percent"
        );
        Ok(())
    }
}

#[derive(Serialize)]
pub struct Point {
    pub phase: &'static str,
    pub requested_payload_gbps: f64,
    pub first_trial_index: usize,
    pub trial_count: usize,
    pub passes: bool,
    pub max_loss_percent: f64,
}

#[derive(Serialize)]
pub struct Search {
    pub options: Options,
    pub points: Vec<Point>,
    pub passing_lower_gbps: Option<f64>,
    pub failing_upper_gbps: Option<f64>,
    pub confirmed: bool,
    pub outcome: &'static str,
}

impl Search {
    pub fn new(options: Options) -> Self {
        Self {
            options,
            points: Vec::new(),
            passing_lower_gbps: None,
            failing_upper_gbps: None,
            confirmed: false,
            outcome: "running",
        }
    }

    pub fn next(&self) -> Option<(&'static str, f64)> {
        if self.outcome != "running" {
            return None;
        }
        match self.points.len() {
            0 => Some(("lower_bound", self.options.min_gbps)),
            1 => Some(("upper_bound", self.options.max_gbps)),
            _ => {
                let lower = self.passing_lower_gbps?;
                if let Some(upper) = self.failing_upper_gbps
                    && upper - lower > self.options.resolution_gbps + 1e-9
                {
                    return Some(("bisect", (upper + lower) / 2.0));
                }
                Some(("confirmation", lower))
            }
        }
    }

    pub fn record(&mut self, point: Point) {
        if point.phase == "confirmation" {
            self.confirmed = point.passes;
            self.outcome = if !point.passes {
                "unstable_confirmation"
            } else if self.failing_upper_gbps.is_none() {
                "at_least_search_maximum"
            } else {
                "confirmed_bracket"
            };
        } else if point.passes {
            self.passing_lower_gbps = Some(point.requested_payload_gbps);
        } else {
            self.failing_upper_gbps = Some(point.requested_payload_gbps);
            if self.passing_lower_gbps.is_none() {
                self.outcome = "below_search_minimum";
            }
        }
        self.points.push(point);
    }
}

/// A slow generator or a dropping payload sink is an invalid measurement,
/// rather than evidence about the encrypted receive path's capacity.
pub fn accepts(
    requested: f64,
    offered: f64,
    loss_percent: f64,
    loss_budget_percent: f64,
    sink_drops: u64,
    duplicates: usize,
) -> Result<bool> {
    ensure!(
        offered.is_finite() && (offered / requested - 1.0).abs() <= 0.01,
        "sender did not maintain requested rate within 1%: requested={requested} actual={offered}"
    );
    ensure!(sink_drops == 0, "payload sink dropped {sink_drops} packets");
    ensure!(duplicates == 0, "payload sink received duplicate packets");
    ensure!(loss_percent.is_finite(), "non-finite packet loss");
    Ok(loss_percent <= loss_budget_percent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn search() -> Search {
        Search::new(Options {
            min_gbps: 2.0,
            max_gbps: 4.0,
            resolution_gbps: 0.125,
            loss_budget_percent: 0.1,
        })
    }

    fn record(search: &mut Search, passes: bool) {
        let (phase, requested_payload_gbps) = search.next().unwrap();
        search.record(Point {
            phase,
            requested_payload_gbps,
            first_trial_index: 0,
            trial_count: 3,
            passes,
            max_loss_percent: if passes { 0.0 } else { 1.0 },
        });
    }

    #[test]
    fn search_brackets_and_requires_a_separate_confirmation() {
        let mut search = search();
        record(&mut search, true); // 2
        record(&mut search, false); // 4
        record(&mut search, true); // 3
        record(&mut search, false); // 3.5
        record(&mut search, true); // 3.25
        record(&mut search, false); // 3.375
        assert_eq!(search.next(), Some(("confirmation", 3.25)));
        record(&mut search, false);
        assert_eq!(search.outcome, "unstable_confirmation");
        assert!(!search.confirmed);
        assert_eq!(search.next(), None);
    }

    #[test]
    fn search_reports_bounds_without_claiming_a_measured_maximum() {
        let mut low = search();
        record(&mut low, false);
        assert_eq!(low.outcome, "below_search_minimum");
        assert_eq!(low.next(), None);
        let mut high = search();
        record(&mut high, true);
        record(&mut high, true);
        record(&mut high, true);
        assert_eq!(high.outcome, "at_least_search_maximum");
        assert!(high.confirmed);
        assert_eq!(high.next(), None);
    }

    #[test]
    fn rejects_generator_and_sink_bottlenecks_instead_of_hiding_them_as_loss() {
        assert!(accepts(3.0, 3.0, 0.09, 0.1, 0, 0).unwrap());
        assert!(!accepts(3.0, 3.0, 0.11, 0.1, 0, 0).unwrap());
        assert!(accepts(3.0, 2.8, 0.0, 0.1, 0, 0).is_err());
        assert!(accepts(3.0, 3.0, 0.09, 0.1, 1, 0).is_err());
        assert!(accepts(3.0, 3.0, 0.09, 0.1, 0, 1).is_err());
    }
}
