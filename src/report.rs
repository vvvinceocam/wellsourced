use bon::Builder;
use colored::Colorize;

pub struct Report {
    issues: Vec<Issue>,
}

impl Report {
    pub fn new() -> Self {
        Self { issues: Vec::new() }
    }

    pub fn add_issue(&mut self, issue: Issue) {
        self.issues.push(issue);
    }

    pub fn reaches_severity(&self, severity: Severity) -> bool {
        self.issues.iter().any(|issue| issue.severity <= severity)
    }

    pub fn show(&self) {
        let issues = {
            let mut issues = self.issues.clone();
            issues.sort_by_key(|issue| issue.severity);
            issues
        };

        for issue in issues {
            match issue.severity {
                Severity::Critical => print!("{}: {}", "Critical".bright_red(), issue.description),
                Severity::High => print!("{}: {}", "High".red(), issue.description),
                Severity::Medium => print!("{}: {}", "Medium".yellow(), issue.description),
                Severity::Low => print!("{}: {}", "Low".white(), issue.description),
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
