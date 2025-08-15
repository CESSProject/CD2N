mod args;
use anyhow::{anyhow, Context, Result};
use args::Args;
use clap::Parser;
use handover::handover::{HandoverChallenge, HandoverChallengeResponse, HandoverSecretData};
use reqwest::{Client, StatusCode};
use serde_json::json;
use std::{
    f32::consts::E,
    fmt::format,
    path::{self, Path, PathBuf},
    process::Stdio,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader, BufWriter},
    process::{Child, ChildStdout, Command},
};
const RUNTIME_INFO_FILE: &str = "seal_data/runtime_info.seal";
const LOG_PREFIX: &str = "[🧑‍⚖️]";
const SUCCESS_RUNNING_FLAG: &str = "app listening on";
fn log(log_text: String) {
    println!("{} {}", LOG_PREFIX, log_text)
}

/// client version is 'current version' which is going to run.
/// server version is the 'backup version' which should be handover runtime_info.seal to current version.
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut client_version: u64 = 0;
    let mut server_version: u64 = 0;
    // link like :ln -s /opt/justicar/backups/2 /opt/justicar/current
    match tokio::fs::read_link(&args.client_version_path).await {
        Ok(real_path) => {
            if let Some(path_str) = real_path.to_str() {
                client_version = path_str
                    .split("/")
                    .last()
                    .ok_or(anyhow!("can't get last version number"))?
                    .parse::<u64>()
                    .context("parse current version from str to u64 failed!")?;
            } else {
                return Err(anyhow!("current version path real link can't recognize!"));
            }
        }
        Err(e) => {
            return Err(anyhow!(
                "Error reading symlink {}: {}",
                args.client_version_path,
                e
            ))
        }
    }
    log(format!("Current version is: {}", client_version));

    let mut entries = tokio::fs::read_dir(&args.server_version_path)
        .await
        .context("read backup version dir failed!")?;

    while let Some(entry) = entries.next_entry().await? {
        let backup_file = entry.path();
        if backup_file.is_dir() {
            let backup_version = backup_file
                .file_name()
                .ok_or(anyhow!(
                    "filename is invalid! the previous configuration file may be corrupted!"
                ))?
                .to_str()
                .context("read backup version to string failed!")?
                .parse::<u64>()
                .context("parse backup version from str to u64 failed!")?;

            if backup_version != client_version && backup_version > server_version {
                server_version = backup_version
            };
        }
    }
    if server_version != 0 {
        log(format!("Server version is: {}", server_version));
    }

    // step1: Check current version have runtime-info.seal or not.
    let client_runtime_info_path = Path::new(&args.client_version_path).join(RUNTIME_INFO_FILE);
    if client_runtime_info_path.exists() {
        log(format!("runtime-info.seal exists, no need to handover"));
        return Ok(());
    };

    // step2: if there is no server version,let current version init.
    let mut client_process = start_justicar(
        path::Path::new(&args.client_version_path).to_path_buf(),
        &args.client_port,
        &args.chain_rpc,
    )
    .await?;
    redirect_log(
        client_process
            .stdout
            .take()
            .ok_or(anyhow!("log output is invaid!!"))?,
        &args.client_justicar_log_path,
    )
    .await?;
    wait_for_run_successfully(&args.client_justicar_log_path, SUCCESS_RUNNING_FLAG).await?;
    if server_version == 0 {
        set_handover_status(&args.client_port).await?;
        kill_justicar_and_sgx_loader(client_version, client_process).await?;
        clear_log(&args.client_justicar_log_path).await?;
        log(format!("Current version is first justicar running on your machine, init success, handover finished!"));
        return Ok(());
    }

    // step3: backup version found, start preivous version justicar as server
    log(format!("server version '{}' found,", server_version));
    let mut server_process = start_justicar(
        path::Path::new(&args.server_version_path).join(server_version.to_string()),
        &args.server_port,
        &args.chain_rpc,
    )
    .await?;
    redirect_log(
        server_process
            .stdout
            .take()
            .ok_or(anyhow!("log output is invaid!!"))?,
        &args.server_justicar_log_path,
    )
    .await?;
    wait_for_run_successfully(&args.server_justicar_log_path, SUCCESS_RUNNING_FLAG).await?;

    handover_receive(
        handover_start(
            handover_accept_challenge(
                generate_challenge(&args.server_port).await?,
                &args.client_port,
            )
            .await?,
            &args.server_port,
        )
        .await?,
        &args.client_port,
    )
    .await?;
    kill_justicar_and_sgx_loader(client_version, client_process).await?;

    kill_justicar_and_sgx_loader(server_version, server_process).await?;

    clear_log(&args.client_justicar_log_path).await?;

    clear_log(&args.server_justicar_log_path).await?;

    Ok(())
}

pub async fn start_justicar(
    program_path: PathBuf,
    port: &String,
    chain_rpc: &String,
) -> Result<Child> {
    let extra_args: &[&str] = &vec!["--port", port, "--chain-rpc", chain_rpc];

    let mut cmd = Command::new(program_path.join("start_justicar.sh"));
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // .stderr(Stdio::piped())
        .env("RUST_LOG", "debug")
        .env("SGX", "1")
        .env("SKIP_AESMD", "1")
        .env("EXTRA_OPTS", extra_args.join(" "));

    let child = cmd.spawn()?;

    Ok(child)
}

pub async fn redirect_log(stdout: ChildStdout, log_path: &String) -> Result<()> {
    //redirect process log into new created log file
    let log_path = Path::new(log_path);
    let log_file = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(log_path)
        .await
        .context("redirect log failed")?;
    let mut log_writer = BufWriter::new(log_file);

    let mut reader = BufReader::new(stdout);

    tokio::spawn(async move {
        tokio::io::copy(&mut reader, &mut log_writer)
            .await
            .expect("Error piping stdout to log file");
    });
    Ok(())
}

pub async fn clear_log(log_path: &String) -> Result<()> {
    tokio::fs::remove_file(Path::new(&log_path))
        .await
        .map_err(|e| anyhow!("clear log file {:?} failed,reason :{}", log_path, e))?;
    Ok(())
}

pub async fn wait_for_run_successfully(log_path: &String, flag: &str) -> Result<()> {
    let sleep_for_running = 10;
    let mut sleep_times = 20; //TODO! To extract the hard code into configured parameters
    let log_file = tokio::fs::File::open(log_path)
        .await
        .context("open log file for detect running status failed!")?;
    let mut reader = BufReader::new(log_file);
    let mut line = String::new();
    loop {
        match reader.read_line(&mut line).await {
            Ok(bytes_read) if bytes_read > 0 => {
                log(format!("{}:{}", log_path, line));

                if line.contains(flag) {
                    log(format!(
                        "remain sleep time: {sleep_times}, sleep {sleep_for_running} wait for gramine running.."
                    ));
                    tokio::time::sleep(tokio::time::Duration::from_secs(sleep_for_running)).await;
                    return Ok(());
                }
                line.clear();
            }
            Ok(_) => {
                if sleep_times > 0 {
                    tokio::time::sleep(tokio::time::Duration::from_secs(sleep_for_running)).await;
                    sleep_times -= 1;
                    continue;
                }
                return Err(anyhow!("there is no any contain in log file!"));
            }
            Err(err) => return Err(anyhow!("read log file failed! error: {}", err)),
        }
    }
}

pub async fn kill_justicar_and_sgx_loader(version: u64, mut justicar_process: Child) -> Result<()> {
    //kill justicar process
    justicar_process
        .kill()
        .await
        .context("kill justicar client process failed!")?;

    //kill loader process
    let cmd = format!(
        "ps -eaf | grep \"backups/{}/cruntime/sgx/loader\" | grep -v \"grep\" | awk '{{print $2}}'",
        version
    );

    let bash_process = Command::new("bash")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn bash_process")?;

    let output = bash_process
        .wait_with_output()
        .await
        .context("Failed to read bash_process output")?;

    if output.status.success() {
        let pid_str =
            std::str::from_utf8(&output.stdout).context("Failed to parse output as UTF-8")?;
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            log(format!(
                "kill the justicar's sgx loader, version is {} pid: {}",
                version, pid
            ));
            Command::new("kill")
                .arg("-9")
                .arg(pid.to_string())
                .status()
                .await
                .map_err(|e| {
                    anyhow!(
                        "Failed to kill justicar sgx_loader process, version :{} , resaon:{}",
                        version,
                        e
                    )
                })?;
        }
    } else {
        let error_str = std::str::from_utf8(&output.stderr)
            .map_err(|e| anyhow!("failed to parse kill output as UTF-8,reason :{}", e))?;
        log(format!("{}", error_str));
        return Err(anyhow!(
            "For somehow, the bash_process is not success! reason :{:?}",
            error_str
        ));
    }

    Ok(())
}

///handover flow
pub async fn set_handover_status(port: &String) -> Result<()> {
    let client = Client::new();

    let response = client
        .put(format!("http://localhost:{}/set_handover_status", port))
        .send()
        .await?;

    if response.status() != StatusCode::OK {
        log(format!(
            "set handover status failed! status code: {}, error msg :{:?}",
            response.status(),
            response.text().await?
        ));
        return Err(anyhow!("set handover status failed!"));
    }
    Ok(())
}

pub async fn generate_challenge(port: &String) -> Result<HandoverChallenge> {
    let client = Client::new();

    let response = client
        .get(format!("http://localhost:{}/generate_challenge", port))
        .send()
        .await?;

    if response.status() != StatusCode::OK {
        log(format!(
            "generate challenge failed! status code: {}, error msg :{:?}",
            response.status(),
            response.text().await?
        ));
        return Err(anyhow!("generate challenge failed!"));
    };

    let result = response.json::<HandoverChallenge>().await?;

    Ok(result)
}

pub async fn handover_accept_challenge(
    handover_challenge: HandoverChallenge,
    port: &String,
) -> Result<HandoverChallengeResponse> {
    let client = Client::new();

    let request_body = json!(handover_challenge);

    let response = client
        .post(format!(
            "http://localhost:{}/handover_accept_challenge",
            port
        ))
        .json(&request_body)
        .send()
        .await?;

    if response.status() != StatusCode::OK {
        log(format!(
            "handover accept challenge failed! status code: {}, error msg :{:?}",
            response.status(),
            response.text().await?
        ));
        return Err(anyhow!("handover accept challenge failed!"));
    };

    let result = response.json::<HandoverChallengeResponse>().await?;

    Ok(result)
}

pub async fn handover_start(
    handover_challenge_response: HandoverChallengeResponse,
    port: &String,
) -> Result<HandoverSecretData> {
    let client = Client::new();

    let request_body = json!(handover_challenge_response);

    let response = client
        .post(format!("http://localhost:{}/handover_start", port))
        .json(&request_body)
        .send()
        .await?;

    if response.status() != StatusCode::OK {
        log(format!(
            "handover start failed! status code: {}, error msg :{:?}",
            response.status(),
            response.text().await?
        ));
        return Err(anyhow!("handover start failed!"));
    };

    let result = response.json::<HandoverSecretData>().await?;

    Ok(result)
}

pub async fn handover_receive(
    handover_secret_data: HandoverSecretData,
    port: &String,
) -> Result<()> {
    let client = Client::new();

    let request_body = json!(handover_secret_data);

    let response = client
        .post(format!("http://localhost:{}/handover_receive", port))
        .json(&request_body)
        .send()
        .await?;

    if response.status() != StatusCode::OK {
        log(format!(
            "handover receive failed! status code: {}, error msg :{:?}",
            response.status(),
            response.text().await?
        ));
        return Err(anyhow!("handover receive failed!"));
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_set_handover_status() -> Result<()> {
        set_handover_status(&"8888".to_string()).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_handover_flow() -> Result<()> {
        let port = &"8888".to_string();

        let challenge = generate_challenge(port).await?;
        let challenge_response = handover_accept_challenge(challenge, port).await?;
        let handover_secret = handover_start(challenge_response, port).await?;
        handover_receive(handover_secret, port).await?;

        Ok(())
    }
}
