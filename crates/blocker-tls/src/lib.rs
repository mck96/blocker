//! A locally-generated certificate authority used to terminate TLS locally:
//! for the proxy's path-rule interception and for the daemon's HTTPS block
//! page. The CA cert is written to `/etc/blocker/ca.crt`; the user installs it
//! into their trust store (and the browser's). Leaf certificates are minted on
//! demand per SNI host and cached in memory.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::server::ClientHello;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub const CA_CERT_PATH: &str = "/etc/blocker/ca.crt";
pub const CA_KEY_PATH: &str = "/etc/blocker/ca.key";

/// Install the ring crypto provider as rustls' process default. Call once at
/// startup before building any rustls config. Idempotent.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub struct Ca {
    issuer_cert: rcgen::Certificate,
    issuer_key: KeyPair,
    ca_der: CertificateDer<'static>,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl Ca {
    /// Load the CA from disk, generating and persisting it on first run.
    pub fn load_or_create() -> Result<Ca, String> {
        if Path::new(CA_CERT_PATH).exists() && Path::new(CA_KEY_PATH).exists() {
            Self::load()
        } else {
            Self::create()
        }
    }

    fn create() -> Result<Ca, String> {
        let issuer_key = KeyPair::generate().map_err(|e| e.to_string())?;
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "Blocker Local CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Blocker");
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let cert = params.self_signed(&issuer_key).map_err(|e| e.to_string())?;

        fs::write(CA_CERT_PATH, cert.pem()).map_err(|e| e.to_string())?;
        fs::write(CA_KEY_PATH, issuer_key.serialize_pem()).map_err(|e| e.to_string())?;
        let _ = fs::set_permissions(CA_KEY_PATH, fs::Permissions::from_mode(0o600));
        let _ = fs::set_permissions(CA_CERT_PATH, fs::Permissions::from_mode(0o644));

        let ca_der = cert.der().clone();
        Ok(Ca {
            issuer_cert: cert,
            issuer_key,
            ca_der,
            cache: Mutex::new(HashMap::new()),
        })
    }

    fn load() -> Result<Ca, String> {
        let cert_pem = fs::read_to_string(CA_CERT_PATH).map_err(|e| e.to_string())?;
        let key_pem = fs::read_to_string(CA_KEY_PATH).map_err(|e| e.to_string())?;
        let issuer_key = KeyPair::from_pem(&key_pem).map_err(|e| e.to_string())?;
        let params =
            CertificateParams::from_ca_cert_pem(&cert_pem).map_err(|e| e.to_string())?;
        // Re-emit an in-memory issuer with the same key and DN so we can sign
        // leaves; the chain still presents the installed CA bytes below.
        let issuer_cert = params.self_signed(&issuer_key).map_err(|e| e.to_string())?;

        let mut rd = std::io::BufReader::new(cert_pem.as_bytes());
        let ca_der = rustls_pemfile::certs(&mut rd)
            .filter_map(|c| c.ok())
            .next()
            .ok_or_else(|| "no certificate in ca.crt".to_string())?;

        Ok(Ca {
            issuer_cert,
            issuer_key,
            ca_der,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Return (minting if needed) a cert+key chain for `host`.
    pub fn cert_for(&self, host: &str) -> Result<Arc<CertifiedKey>, String> {
        if let Some(ck) = self.cache.lock().unwrap().get(host) {
            return Ok(ck.clone());
        }
        let ck = self.mint(host)?;
        self.cache
            .lock()
            .unwrap()
            .insert(host.to_string(), ck.clone());
        Ok(ck)
    }

    fn mint(&self, host: &str) -> Result<Arc<CertifiedKey>, String> {
        let mut params =
            CertificateParams::new(vec![host.to_string()]).map_err(|e| e.to_string())?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let leaf_key = KeyPair::generate().map_err(|e| e.to_string())?;
        let leaf_cert = params
            .signed_by(&leaf_key, &self.issuer_cert, &self.issuer_key)
            .map_err(|e| e.to_string())?;

        let leaf_der = leaf_cert.der().clone();
        let key_der = leaf_key.serialize_der();
        let signing_key = any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            key_der,
        )))
        .map_err(|e| e.to_string())?;

        let ck = CertifiedKey::new(vec![leaf_der, self.ca_der.clone()], signing_key);
        Ok(Arc::new(ck))
    }
}

/// A rustls cert resolver that mints per-SNI leaves via the CA.
#[derive(Debug)]
struct SniResolver {
    ca: Arc<Ca>,
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ca")
    }
}

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name()?;
        self.ca.cert_for(name).ok()
    }
}

/// Build the interception server config (forces HTTP/1.1 via ALPN so we never
/// have to parse HTTP/2).
pub fn server_config(ca: Arc<Ca>) -> Arc<ServerConfig> {
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SniResolver { ca }));
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// Build the upstream client config used to re-originate the TLS connection to
/// the real server, validating against the system/web PKI roots.
pub fn client_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}
