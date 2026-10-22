#[cfg(target_os = "linux")]
#[tokio::main(worker_threads = 2)]
async fn main() {
    use clap::Parser;
    let options = homeproxy_service::Options::parse();
    // Register signal handlers before taking ownership of any live runtime.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("Cannot register SIGTERM handler");
    let shutdown = async move {
        tokio::select! { _ = terminate.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
    };
    if let Err(error) = homeproxy_service::run(options, shutdown).await {
        eprintln!("homeproxyd: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("homeproxyd currently requires Linux");
    std::process::exit(1);
}
