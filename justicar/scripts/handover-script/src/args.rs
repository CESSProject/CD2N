use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Args {
    #[arg(
        default_value = "1308",
        long = "server-port",
        help = "Previous node as server, start with server port."
    )]
    pub server_port: String,

    #[arg(
        default_value = "1309",
        long = "client-port",
        help = "New node as client, start with client port."
    )]
    pub client_port: String,

    #[arg(
        long,
        help = "The new version program absolute path",
        default_value = "/opt/justicar/current"
    )]
    pub client_version_path: String,

    #[arg(
        long,
        help = "The previous version program absolute path",
        default_value = "/opt/justicar/backups"
    )]
    pub server_version_path: String,

    #[arg(
        long,
        help = "Server node running temporary log file.",
        default_value = "/tmp/pre_justicar.log"
    )]
    pub server_justicar_log_path: String,

    #[arg(
        long,
        help = "Client node running temporary log file.",
        default_value = "/tmp/new_justicar.log"
    )]
    pub client_justicar_log_path: String,

    #[arg(long, help = "Chain rpc url.", default_value = "ws://127.0.0.1:9944")]
    pub chain_rpc: String,
}
