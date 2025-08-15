use anyhow::{Context, Result};
mod handlers;
mod models;
mod periodic_rewards;
mod routes;
mod utils;
use clap::Parser;
use env_logger;
use log::info;
use models::args::Args;
use std::net::SocketAddr;
static CONTRACT_ADDRESS: &str = "D185AF24121d0D6a9A3e128fB27C3704569b5E91";

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    env_logger::init();

    let cd2n_state = models::CD2NState::new_with_runtime_info_file(
        args.dev_mode,
        args.pccs_url,
        args.ra_timeout,
        args.chain_rpc,
        args.safe_storage_path,
        CONTRACT_ADDRESS.to_string(),
    )
    .await?;

    // build our application with a route and state
    let app = routes::create_routes(cd2n_state.clone()).await;

    let contract_ref = cd2n_state.contract.clone();
    let need_handover_ref = cd2n_state.need_handover.clone();
    let periodic_rewards_task: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
        info!("Starting periodic rewards task...");
        periodic_rewards::periodic_rewards(
            args.reward_block_interval,
            cd2n_state.clone().incentive_record_storage,
            contract_ref,
            need_handover_ref,
        )
        .await
    });

    // run it
    let port = args.port;
    let app_task: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

        info!(
            "app listening on {}",
            listener
                .local_addr()
                .context("Failed to get local address")?
        );
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .context("Failed to start server")
    });

    info!("All tasks are enabled!");
    let (periodic_rewards_result, app_task_result) = tokio::join!(periodic_rewards_task, app_task);

    if let Err(periodic_rewards_err) = periodic_rewards_result {
        panic!("Periodic rewards task failed: {:?}", periodic_rewards_err);
    }
    if let Err(app_task_err) = app_task_result {
        panic!("App task failed: {:?}", app_task_err);
    }

    Ok(())
}
