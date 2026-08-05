use std::collections::BTreeMap;

use conduwuit::{Err, Result, Server, debug, err};
use serde_json::{Map as JsonObject, Value as JsonValue};
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

use conduwuit::config::IdentityProvider;

/// Runtime-resolved provider state (config + discovered endpoints).
pub type Provider = IdentityProvider;

/// Provider ID (the BTreeMap key from config).
pub type ProviderId = String;

pub struct Providers {
	server: Arc<Server>,
	cache: RwLock<BTreeMap<ProviderId, Provider>>,
}

impl Providers {
	pub(super) fn new(server: Arc<Server>) -> Self {
		Self {
			server,
			cache: RwLock::new(BTreeMap::new()),
		}
	}

	/// Get a provider by its config key ID. Runs OIDC discovery on first
	/// access (requires HTTP client), then caches.
	pub async fn get_with_client(
		&self,
		id: &str,
		http_client: &reqwest::Client,
	) -> Result<Provider> {
		if let Some(provider) = self.cache.read().await.get(id).cloned() {
			return Ok(provider);
		}

		let config = self.get_config(id)?;
		let provider = configure(id, config, http_client, &self.server).await?;

		debug!(?id, ?provider, "Provider configured");
		self.cache
			.write()
			.await
			.insert(id.to_owned(), provider.clone());

		Ok(provider)
	}

	/// Get a provider from cache only (no discovery). For use when HTTP
	/// client is not available.
	pub async fn get(&self, id: &str) -> Result<Provider> {
		self.cache
			.read()
			.await
			.get(id)
			.cloned()
			.or_else(|| self.get_config(id).ok())
			.ok_or_else(|| err!(Request(NotFound("Unrecognized Identity Provider: {id}"))))
	}

	/// Get the raw config for a provider by its config key.
	pub fn get_config(&self, id: &str) -> Result<Provider> {
		self.server
			.config
			.identity_provider
			.get(id)
			.cloned()
			.ok_or_else(|| err!(Request(NotFound("Unrecognized Identity Provider"))))
	}
}

/// Resolve a provider config by running OIDC discovery and filling in
/// missing endpoint URLs. `config_key` is the key from
/// `[global.identity_provider.<key>]` used as the stable provider ID.
async fn configure(
	config_key: &str,
	mut provider: Provider,
	http_client: &reqwest::Client,
	server: &Server,
) -> Result<Provider> {
	if provider.name.is_none() {
		provider.name = Some(provider.brand.clone());
	}

	if provider.issuer_url.is_none() {
		let url_str = match provider.brand.as_str() {
			| "github" => "https://github.com",
			| "gitlab" => "https://gitlab.com",
			| "google" => "https://accounts.google.com",
			| _ => return Err!(Config("issuer_url", "Required for this provider.")),
		};
		provider.issuer_url = Some(
			Url::parse(url_str).map_err(|e| err!(error!("Invalid default issuer URL: {e}")))?,
		);
	}

	if provider.base_path.is_empty() && provider.brand == "github" {
		provider.base_path = "login/oauth/".to_owned();
	}

	// Run OIDC discovery. Non-fatal — some providers (e.g., GitHub) are
	// OAuth2-only and don't have a discovery endpoint.
	let response = match discover(&provider, http_client).await {
		| Ok(value) => value
			.as_object()
			.cloned()
			.and_then(|obj| check_issuer(obj, &provider).ok())
			.unwrap_or_default(),
		| Err(e) => {
			debug!(?e, "OIDC discovery failed (non-fatal), using defaults");
			serde_json::Map::new()
		},
	};

	if provider.authorization_url.is_none() {
		provider.authorization_url = response
			.get("authorization_endpoint")
			.and_then(JsonValue::as_str)
			.map(Url::parse)
			.transpose()
			.map_err(|e| err!(error!("Invalid URL from discovery: {e}")))?
			.or_else(|| make_url(&provider, "authorize").ok());
	}

	if provider.token_url.is_none() {
		let path = if provider.brand == "github" {
			"access_token"
		} else {
			"token"
		};
		provider.token_url = response
			.get("token_endpoint")
			.and_then(JsonValue::as_str)
			.map(Url::parse)
			.transpose()
			.map_err(|e| err!(error!("Invalid URL from discovery: {e}")))?
			.or_else(|| make_url(&provider, path).ok());
	}

	if provider.userinfo_url.is_none() {
		provider.userinfo_url = response
			.get("userinfo_endpoint")
			.and_then(JsonValue::as_str)
			.map(Url::parse)
			.transpose()
			.map_err(|e| err!(error!("Invalid URL from discovery: {e}")))?
			.or_else(|| match provider.brand.as_str() {
				| "github" => Url::parse("https://api.github.com/user").ok(),
				| _ => make_url(&provider, "userinfo").ok(),
			});
	}

	if provider.revocation_url.is_none() {
		provider.revocation_url = response
			.get("revocation_endpoint")
			.and_then(JsonValue::as_str)
			.map(Url::parse)
			.transpose()
			.map_err(|e| err!(error!("Invalid URL from discovery: {e}")))?
			.or_else(|| make_url(&provider, "revocation").ok());
	}

	if provider.callback_url.is_none() {
		if let Some(server_url) = server.config.well_known.client.as_ref() {
			let callback_path =
				format!("_matrix/client/unstable/login/sso/callback/{config_key}");
			provider.callback_url = Some(
				server_url
					.join(&callback_path)
					.map_err(|e| err!(error!("Invalid callback URL: {e}")))?,
			);
		}
	}

	Ok(provider)
}

/// Fetch the OIDC discovery document from the provider.
async fn discover(provider: &Provider, http_client: &reqwest::Client) -> Result<JsonValue> {
	if !provider.discovery {
		return Err!(Config("discovery", "Discovery is disabled for this provider"));
	}

	let url = discovery_url(provider)?;
	http_client
		.get(url)
		.send()
		.await?
		.error_for_status()?
		.json()
		.await
		.map_err(Into::into)
}

fn discovery_url(provider: &Provider) -> Result<Url> {
	let default_url = provider
		.discovery
		.then(|| make_url(provider, ".well-known/openid-configuration"))
		.transpose()?;

	provider
		.discovery_url
		.clone()
		.filter(|_| provider.discovery)
		.or(default_url)
		.ok_or_else(|| {
			err!(Config("discovery_url", "Failed to determine discovery URL for provider"))
		})
}

fn check_issuer(
	response: JsonObject<String, JsonValue>,
	provider: &Provider,
) -> Result<JsonObject<String, JsonValue>> {
	let expected = provider
		.issuer_url
		.as_ref()
		.map(Url::as_str)
		.map(|url| url.trim_end_matches('/'));

	let responded = response
		.get("issuer")
		.and_then(JsonValue::as_str)
		.map(|url| url.trim_end_matches('/'));

	if expected != responded {
		return Err!(Request(Unauthorized(
			"Configured issuer_url {expected:?} does not match discovered {responded:?}",
		)));
	}

	Ok(response)
}

fn make_url(provider: &Provider, path: &str) -> Result<Url> {
	let mut suffix = provider.base_path.clone();
	suffix.push_str(path);

	let issuer = provider
		.issuer_url
		.as_ref()
		.ok_or_else(|| err!(Config("issuer_url", "Required field")))?;

	let issuer_path = issuer.path();
	if issuer_path.ends_with('/') {
		issuer
			.join(&suffix)
			.map_err(|e| err!(error!("Failed to build provider URL: {e}")))
	} else {
		let mut url = issuer.clone();
		url.set_path(&(issuer_path.to_owned() + "/"));
		url.join(&suffix)
			.map_err(|e| err!(error!("Failed to build provider URL: {e}")))
	}
}
