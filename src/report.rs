use bon::Builder;
use colored::Colorize;

pub struct Report {
    smells: Vec<Issue>,
}

impl Report {
    pub fn new() -> Self {
        Self { smells: Vec::new() }
    }

    pub fn add_issue(&mut self, smell: Issue) {
        self.smells.push(smell);
    }

    pub fn reaches_severity(&self, severity: Severity) -> bool {
        self.smells.iter().any(|smell| smell.severity <= severity)
    }

    pub fn show(&self) {
        let smells = {
            let mut smells = self.smells.clone();
            smells.sort_by_key(|smell| smell.severity);
            smells
        };

        for smell in smells {
            match smell.severity {
                Severity::Critical => print!("{}: {}", "Critical".bright_red(), smell.description),
                Severity::High => print!("{}: {}", "High".red(), smell.description),
                Severity::Medium => print!("{}: {}", "Medium".yellow(), smell.description),
                Severity::Low => print!("{}: {}", "Low".white(), smell.description),
            }
            println!();
        }

        println!()
    }
}

#[derive(Builder, Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Issue {
    description: String,
    severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}
