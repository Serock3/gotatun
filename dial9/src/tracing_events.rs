// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Record ordinary tracing events as Dial9 custom events. Dial9TracingLayer records spans;
//! this layer supplies log events, including fields, span scope and source location.
//! It shares the subscriber's level filter, so packet-level trace logs stay off by default.

use std::{fmt, fmt::Write as _};

use dial9::telemetry::{Dial9Handle, clock_monotonic_ns};
use dial9_trace_format::TraceEvent;
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

const MAX_TEXT_BYTES: usize = 4 * 1024;

#[derive(Debug, TraceEvent)]
pub struct TracingEventRecord {
    #[traceevent(timestamp)]
    timestamp_ns: u64,
    level: String,
    target: String,
    name: String,
    fields: String,
    span_scope: String,
    file: String,
    line: u64,
}

#[derive(Debug, TraceEvent)]
pub struct WorkloadEvent {
    #[traceevent(timestamp)]
    timestamp_ns: u64,
    phase: String,
    detail: String,
}

#[derive(Debug, Default)]
pub struct TracingEventLayer;

impl<S> Layer<S> for TracingEventLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let Some(handle) = Dial9Handle::try_current() else {
            return;
        };
        if !handle.is_enabled() {
            return;
        }

        let metadata = event.metadata();
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        let mut span_scope = ctx
            .event_scope(event)
            .map(|scope| {
                scope
                    .from_root()
                    .map(|span| span.metadata().name())
                    .collect::<Vec<_>>()
                    .join("::")
            })
            .unwrap_or_default();
        truncate_text(&mut visitor.output);
        truncate_text(&mut span_scope);

        handle.record_event(TracingEventRecord {
            timestamp_ns: clock_monotonic_ns(),
            level: metadata.level().to_string(),
            target: metadata.target().to_owned(),
            name: metadata.name().to_owned(),
            fields: visitor.output,
            span_scope,
            file: metadata.file().unwrap_or_default().to_owned(),
            line: metadata.line().map_or(0, u64::from),
        });
    }
}

#[derive(Default)]
struct FieldVisitor {
    output: String,
}

impl FieldVisitor {
    fn record(&mut self, field: &Field, value: impl fmt::Display) {
        if !self.output.is_empty() {
            self.output.push_str(", ");
        }
        let _ = write!(self.output, "{}={value}", field.name());
    }
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record(field, format_args!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record(field, value);
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record(field, value);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record(field, value);
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record(field, value);
    }
}

pub fn record_workload_event(phase: impl Into<String>, detail: impl Into<String>) {
    let Some(handle) = Dial9Handle::try_current() else {
        return;
    };
    handle.record_event(WorkloadEvent {
        timestamp_ns: clock_monotonic_ns(),
        phase: phase.into(),
        detail: detail.into(),
    });
}

fn truncate_text(text: &mut String) {
    if text.len() <= MAX_TEXT_BYTES {
        return;
    }
    let mut boundary = MAX_TEXT_BYTES;
    while !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    text.truncate(boundary);
    text.push_str("…[truncated]");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_preserves_utf8() {
        let mut text = "å".repeat(MAX_TEXT_BYTES);
        truncate_text(&mut text);
        assert!(text.is_char_boundary(text.len()));
        assert!(text.ends_with("[truncated]"));
    }
}
