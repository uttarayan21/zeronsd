use zeronsd::cli::init;
use zeronsd::errors::ErrorReport;

#[tokio::main]
async fn main() -> Result<(), ErrorReport> {
    init().await
}
