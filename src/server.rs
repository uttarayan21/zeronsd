use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tracing::info;

use crate::errors;
use error_stack::{Result, ResultExt};
use openssl::{
    pkey::{PKey, Private},
    stack::Stack,
    x509::X509,
};
use tokio::net::{TcpListener, UdpSocket};

use trust_dns_server::server::ServerFuture;

use crate::authority::{init_catalog, ZTAuthority};

#[derive(Clone)]
pub struct Server(ZTAuthority);

impl Server {
    pub fn new(zt: ZTAuthority) -> Self {
        Self(zt)
    }

    // listener routine for TCP and UDP.
    pub async fn listen(
        self,
        ip: IpAddr,
        tcp_timeout: Duration,
        certs: Option<X509>,
        cert_chain: Option<Stack<X509>>,
        key: Option<PKey<Private>>,
    ) -> Result<(), errors::Error> {
        let sa = SocketAddr::new(ip, 53);
        let tcp = TcpListener::bind(sa).await.change_context(errors::Error)?;
        let udp = UdpSocket::bind(sa).await.change_context(errors::Error)?;

        let mut sf = ServerFuture::new(init_catalog(self.0).await.change_context(errors::Error)?);

        if let (Some(certs), Some(key)) = (certs.clone(), key.clone()) {
            info!("Configuring DoT Listener");
            let tls = TcpListener::bind(SocketAddr::new(ip, 853))
                .await
                .change_context(errors::Error)?;

            match sf.register_tls_listener(tls, tcp_timeout, ((certs, cert_chain), key)) {
                Ok(_) => {}
                Err(e) => tracing::error!("Cannot start DoT listener: {}", e),
            }
        }

        sf.register_socket(udp);
        sf.register_listener(tcp, tcp_timeout);
        // match sf.block_until_done().await {
        //     Ok(_) => Ok(()),
        //     Err(e) => Err(error_stack::report!()),
        // }
        sf.block_until_done().await.change_context(errors::Error)
    }
}
