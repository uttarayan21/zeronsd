use std::{net::IpAddr, path::Path, str::FromStr, sync::Once};

use ipnetwork::IpNetwork;
use reqwest::header::{HeaderMap, HeaderValue};
use tracing::warn;
use trust_dns_server::client::rr::{LowerName, Name};

use crate::errors;
use crate::traits::ToHostname;
use error_stack::*;

use zerotier_api::{central_api, service_api};

// collections of test hosts files
pub const TEST_HOSTS_DIR: &str = "../testdata/hosts-files";
pub const DEFAULT_DOMAIN_NAME: &str = "home.arpa.";
// zeronsd version calculated from Cargo.toml
pub const VERSION_STRING: &str = env!("CARGO_PKG_VERSION");
// address of Central
pub const CENTRAL_BASEURL: &str = "https://my.zerotier.com/api/v1";
// address of local zerotier instance
pub const ZEROTIER_LOCAL_URL: &str = "http://127.0.0.1:9993";

// this really needs to be replaced with lazy_static! magic
fn version() -> String {
    "zeronsd ".to_string() + VERSION_STRING
}

static LOGGER: Once = Once::new();

// initializes a logger
pub fn init_logger(level: Option<tracing::Level>) {
    LOGGER.call_once(|| {
        let loglevel = std::env::var("ZERONSD_LOG").or_else(|_| std::env::var("RUST_LOG"));

        let level = if let Ok(loglevel) = loglevel {
            crate::log::LevelFilter::from_str(&loglevel)
                .expect("invalid log level")
                .to_log()
        } else {
            level
        };

        tracing_log::log_tracer::LogTracer::init().expect("initializing logger failed");

        if let Some(level) = level {
            let subscriber = tracing_subscriber::FmtSubscriber::builder()
                // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
                // will be written to stdout.
                .with_max_level(level)
                // completes the builder.
                .finish();

            tracing::subscriber::set_global_default(subscriber)
                .expect("setting default subscriber failed");
        }
    })
}

// this provides the production configuration for talking to central through the openapi libraries.
pub fn central_client(token: String) -> Result<central_api::Client, errors::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("bearer {}", token)).change_context(errors::Error)?,
    );

    Ok(central_api::Client::new_with_client(
        &std::env::var("ZEROTIER_CENTRAL_INSTANCE").unwrap_or(CENTRAL_BASEURL.to_string()),
        reqwest::Client::builder()
            .user_agent(version())
            .https_only(true)
            .default_headers(headers)
            .build()
            .change_context(errors::Error)?,
    ))
}

// extracts the ip from the CIDR. 10.0.0.1/32 becomes 10.0.0.1
pub fn parse_ip_from_cidr(ip_with_cidr: String) -> IpAddr {
    IpNetwork::from_str(&ip_with_cidr)
        .expect("Could not parse IP from CIDR")
        .ip()
}

// load and prepare the central API token
pub fn central_token(arg: Option<&Path>) -> Result<String, errors::Error> {
    if let Some(path) = arg {
        return Ok(std::fs::read_to_string(path)
            .expect("Could not load token file")
            .trim()
            .to_string());
    }

    if let Ok(token) = std::env::var("ZEROTIER_CENTRAL_TOKEN") {
        if !token.is_empty() {
            return Ok(token);
        }
    }

    return Err(errors::Error).attach_printable("missing zerotier central token: set ZEROTIER_CENTRAL_TOKEN in environment, or pass a file containing it with -t");
}

// determine the path of the authtoken.secret
pub fn authtoken_path(arg: Option<&Path>) -> &Path {
    if let Some(arg) = arg {
        return arg;
    }

    if cfg!(target_os = "linux") {
        Path::new("/var/lib/zerotier-one/authtoken.secret")
    } else if cfg!(target_os = "windows") {
        Path::new("C:/ProgramData/ZeroTier/One/authtoken.secret")
    } else if cfg!(target_os = "macos") {
        Path::new("/Library/Application Support/ZeroTier/One/authtoken.secret")
    } else {
        panic!("authtoken.secret not found; please provide the -s option to provide a custom path")
    }
}

// use the default tld if none is supplied.
pub fn domain_or_default(tld: Option<&str>) -> Result<Name, errors::Error> {
    if let Some(tld) = tld {
        if !tld.is_empty() {
            return Ok(Name::from_str(&format!("{}.", tld)).change_context(errors::Error)?);
        } else {
            return Err(errors::Error)
                .attach_printable("Domain name must not be empty if provided.");
        }
    };

    Ok(Name::from_str(DEFAULT_DOMAIN_NAME).change_context(errors::Error)?)
}

// parse_member_name ensures member names are DNS compliant
pub fn parse_member_name(name: Option<String>, domain_name: Name) -> Option<Name> {
    if let Some(name) = name {
        let name = name.trim();
        if !name.is_empty() {
            match name.to_fqdn(domain_name) {
                Ok(record) => return Some(record),
                Err(e) => {
                    warn!("Record {} not entered into catalog: {}", name, e);
                    return None;
                }
            };
        }
    }

    None
}

pub async fn get_member_name(
    authtoken_path: &Path,
    domain_name: Name,
    local_url: String,
) -> Result<LowerName, errors::Error> {
    let client = local_client_from_file(authtoken_path, local_url).change_context(errors::Error)?;

    let status = client
        .get_status()
        .await
        .change_context(errors::Error)?
        .into_inner();
    if let Some(address) = &status.address {
        return Ok(("zt-".to_string() + address)
            .to_fqdn(domain_name)
            .change_context(errors::Error)?
            .into());
    }

    Err(errors::Error).attach_printable(
        "No member found for this instance; is zerotier connected to this network.change_context(errors::Error)?"
    )
}

fn local_client_from_file(
    authtoken_path: &Path,
    local_url: String,
) -> Result<service_api::Client, errors::Error> {
    let authtoken = std::fs::read_to_string(authtoken_path).change_context(errors::Error)?;
    local_client(authtoken, local_url)
}

pub fn local_client(
    authtoken: String,
    local_url: String,
) -> Result<service_api::Client, errors::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "X-ZT1-Auth",
        HeaderValue::from_str(&authtoken).change_context(errors::Error)?,
    );

    Ok(service_api::Client::new_with_client(
        &local_url,
        reqwest::Client::builder()
            .user_agent(version())
            .default_headers(headers)
            .build()
            .change_context(errors::Error)?,
    ))
}

// get_listen_ips returns the IPs that the network is providing to the instance running zeronsd.
// 4193 and 6plane are handled up the stack.
pub async fn get_listen_ips(
    authtoken_path: &Path,
    network_id: &str,
    local_url: String,
) -> Result<Vec<String>, errors::Error> {
    let client = local_client_from_file(authtoken_path, local_url).change_context(errors::Error)?;

    match client.get_network(network_id).await {
        Err(error) => Err(errors::Error).attach_printable_lazy(|| {
            format!(
                "Error: {}. Are you joined to {}.change_context(errors::Error)?",
                error, network_id
            )
        }),
        Ok(listen) => {
            let assigned = listen.into_inner().assigned_addresses.to_owned();
            if !assigned.is_empty() {
                Ok(assigned)
            } else {
                Err(errors::Error).attach_printable("No listen IPs available on this network")
            }
        }
    }
}

// update_central_dns pushes the search records
pub async fn update_central_dns(
    domain_name: Name,
    ips: Vec<String>,
    client: central_api::Client,
    network: String,
) -> Result<(), errors::Error> {
    let mut zt_network = client
        .get_network_by_id(&network)
        .await
        .change_context(errors::Error)?;

    let mut domain_name = domain_name;
    domain_name.set_fqdn(false);

    let dns = Some(central_api::types::Dns {
        domain: Some(domain_name.to_string()),
        servers: Some(ips),
    });

    if let Some(mut zt_network_config) = zt_network.config.to_owned() {
        zt_network_config.dns = dns;
        zt_network.config = Some(zt_network_config);
        client
            .update_network(&network, &zt_network)
            .await
            .change_context(errors::Error)?;
    }

    Ok(())
}
