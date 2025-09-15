use color_eyre::Result;
use prometheus::{Counter, CounterVec, Encoder, Opts, TextEncoder, core::Collector};

#[derive(Debug, Clone)]
pub struct Metrics {
    pub report_counter: Counter,
    pub webhooks_counter: CounterVec,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let report_counter =
            Counter::new("wellsourced_report_counter", "Number of reports processed")?;
        let webhooks_counter = CounterVec::new(
            Opts::new(
                "wellsourced_webhooks_counter",
                "Number of webhooks processed",
            ),
            &["status_code"],
        )?;

        Ok(Metrics {
            report_counter,
            webhooks_counter,
        })
    }

    pub fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        let mut metrics = Vec::new();
        metrics.extend(self.report_counter.collect());
        metrics.extend(self.webhooks_counter.collect());
        metrics
    }

    pub fn encode(&self) -> Result<String> {
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        encoder.encode(&self.gather(), &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }

    pub fn inc_report(&self) {
        self.report_counter.inc();
    }

    pub fn inc_webhooks(&self, status_code: &str) {
        self.webhooks_counter
            .with_label_values(&[status_code])
            .inc();
    }
}
