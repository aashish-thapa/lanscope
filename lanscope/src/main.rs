use clap::Parser;

use lanscope::app;
use lanscope::cli::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    app::init_tracing(cli.verbose);

    if let Err(e) = app::dispatch(cli).await {
        tracing::error!(error = %e, "fatal");
        std::process::exit(1);
    }
    Ok(())
}
