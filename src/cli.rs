use clap::{ArgAction, Parser, Subcommand};

#[derive(Debug, Clone, Parser)]
pub struct Cli {
    #[arg(short, long, action = ArgAction::Count)]
    pub debug: u8,

    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    Lint {
        #[arg(short, long, default_value_t = false)]
        raw_csp: bool,

        #[arg(short, long, default_value_t = false)]
        follow_redirects: bool,

        #[arg(short = 'H', long)]
        header: Vec<String>,

        source: String,
    },
}
