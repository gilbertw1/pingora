// Copyright 2025 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use pingora_error::{Error, Result};
use pingora_error::{ErrorType::*, OrErr};

use pingora_s2n::{
    load_pem_file, ClientAuthType, Config, ConfigBuilder, IgnoreVerifyHostnameCallback,
    TlsConnector as S2NTlsConnector, DEFAULT_TLS13,
};

use crate::{
    connectors::ConnectorOptions,
    listeners::ALPN,
    protocols::{
        tls::{client::handshake, S2NConnectionBuilder, TlsStream},
        IO,
    },
    upstreams::peer::Peer,
};

#[derive(Clone)]
pub struct Connector {
    pub ctx: TlsConnector,
}

impl Connector {
    /// Create a new connector based on the optional configurations. If no
    /// configurations are provided, no customized certificates or keys will be
    /// used
    pub fn new(options: Option<ConnectorOptions>) -> Self {
        Connector {
            ctx: TlsConnector { options },
        }
    }
}

#[derive(Clone)]
pub struct TlsConnector {
    options: Option<ConnectorOptions>,
}

pub(crate) async fn connect<T, P>(
    stream: T,
    peer: &P,
    alpn_override: Option<ALPN>,
    tls_ctx: &TlsConnector,
) -> Result<TlsStream<T>>
where
    T: IO,
    P: Peer + Send + Sync,
{
    let mut builder = create_config_builder(&tls_ctx.options)?;

    if let Some(max_blinding_delay) = peer.get_max_blinding_delay() {
        builder.set_max_blinding_delay(max_blinding_delay).unwrap();
    }

    if let Some(security_policy) = peer.get_security_policy() {
        builder
            .set_security_policy(security_policy)
            .or_err(InternalError, "invalid security policy")?;
    }

    if let Some(ca) = peer.get_ca() {
        builder
            .trust_pem(&ca.raw_pem)
            .or_err(InternalError, "invalid peer ca cert")?;
    }

    if let Some(client_cert_key) = peer.get_client_cert_key() {
        builder
            .load_pem(&client_cert_key.raw_pem(), &client_cert_key.key())
            .or_err(InternalError, "invalid peer client cert or key")?;
    }

    if let Some(alpn) = alpn_override.as_ref().or(peer.get_alpn()) {
        builder
            .set_application_protocol_preference(alpn.to_wire_protocols())
            .or_err(InternalError, "failed to set peer alpn")?;
    }

    if !peer.verify_cert() {
        // Disabling x509 verification is considered unsafe
        unsafe {
            builder.disable_x509_verification().unwrap();
        }
    }

    if !peer.verify_hostname() {
        // Set verify hostname callback that always returns success
        builder
            .set_verify_host_callback(IgnoreVerifyHostnameCallback::new())
            .unwrap();
    }

    let config = builder
        .build()
        .or_err(InternalError, "failed to create s2n config")?;
    let connection_builder = S2NConnectionBuilder {
        config: config.clone(),
        psk_config: peer.get_psk().cloned(),
    };

    let domain = peer
        .alternative_cn()
        .map(|s| s.as_str())
        .unwrap_or(peer.sni());
    let connector = S2NTlsConnector::new(connection_builder);
    let connect_future = handshake(&connector, domain, stream);

    match peer.connection_timeout() {
        Some(t) => match pingora_timeout::timeout(t, connect_future).await {
            Ok(res) => res,
            Err(_) => Error::e_explain(
                ConnectTimedout,
                format!("connecting to server {}, timeout {:?}", peer, t),
            ),
        },
        None => connect_future.await,
    }
}

fn create_config_builder(options: &Option<ConnectorOptions>) -> Result<ConfigBuilder> {
    let mut builder = Config::builder();

    // Default security policy with TLS 1.3 support
    // https://aws.github.io/s2n-tls/usage-guide/ch06-security-policies.html
    builder.set_security_policy(&DEFAULT_TLS13).unwrap();

    if let Some(conf) = options.as_ref() {
        if let Some(ca_file_path) = conf.ca_file.as_ref() {
            let ca_pem = load_pem_file(&ca_file_path)?;
            builder
                .trust_pem(&ca_pem)
                .or_err(InternalError, "failed to load ca cert")?;
        }

        if let Some((cert_file, key_file)) = conf.cert_key_file.as_ref() {
            let cert = load_pem_file(cert_file)?;
            let key = load_pem_file(key_file)?;
            builder
                .load_pem(&cert, &key)
                .or_err(InternalError, "failed to load client cert")?;
            builder
                .set_client_auth_type(ClientAuthType::Required)
                .or_err(InternalError, "failed to load client key")?;
        }
    }
    Ok(builder)
}
