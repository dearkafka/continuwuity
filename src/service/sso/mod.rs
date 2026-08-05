pub mod providers;
pub mod sessions;
pub mod user_info;

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as b64encode};
use conduwuit::{Err, Result, err, info, utils::response::LimitReadExt};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::Serialize;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use url::Url;

/// Maximum provider response body size for token/userinfo/discovery JSON.
const RESPONSE_LIMIT: u64 = 64 * 1024;

pub use self::{
	providers::{Provider, ProviderId, Providers},
	sessions::{CODE_VERIFIER_LENGTH, SESSION_ID_LENGTH, Session, Sessions},
	user_info::UserInfo,
};
use crate::Dep;

pub struct Service {
	client: Dep<crate::client::Service>,
	pub providers: Arc<Providers>,
	pub sessions: Arc<Sessions>,
}

impl crate::Service for Service {
	fn build(args: crate::Args<'_>) -> Result<Arc<Self>> {
		let server = Arc::clone(args.server);
		let client_dep = args.depend::<crate::client::Service>("client");

		let providers = Arc::new(Providers::new(Arc::clone(&server)));
		let sessions = Arc::new(Sessions::new(args.db));

		let has_providers = !server.config.identity_provider.is_empty();

		if has_providers {
			info!(
				"SSO enabled with {} identity provider(s)",
				server.config.identity_provider.len()
			);
		}

		Ok(Arc::new(Self { client: client_dep, providers, sessions }))
	}

	fn name(&self) -> &str {
		crate::service::make_name(std::module_path!())
	}
}

impl Service {
	/// Get the HTTP client for making requests to providers.
	fn http_client(&self) -> &reqwest::Client {
		&self.client.external_resource
	}

	/// Get a provider with OIDC discovery (uses HTTP client).
	pub async fn get_provider(&self, id: &str) -> Result<Provider> {
		self.providers.get_with_client(id, self.http_client()).await
	}

	/// Exchange an authorization code for an access token from the provider.
	pub async fn request_token(
		&self,
		provider: &Provider,
		session: &Session,
		code: &str,
	) -> Result<Session> {
		#[derive(Debug, Serialize)]
		struct TokenQuery<'a> {
			client_id: &'a str,
			client_secret: &'a str,
			grant_type: &'a str,
			code: &'a str,
			code_verifier: Option<&'a str>,
			redirect_uri: Option<&'a str>,
		}

		let client_secret = get_client_secret(provider).await?;

		let query = TokenQuery {
			client_id: &provider.client_id,
			client_secret: &client_secret,
			grant_type: "authorization_code",
			code,
			code_verifier: session.code_verifier.as_deref(),
			redirect_uri: provider.callback_url.as_ref().map(Url::as_str),
		};

		let url = provider
			.token_url
			.clone()
			.ok_or_else(|| err!(Config("token_url", "Missing token URL in provider config")))?;

		self.post_form(provider, session, url, Some(query))
			.await
			.and_then(|value| serde_json::from_value(value).map_err(Into::into))
	}

	/// Fetch userinfo claims from the provider.
	pub async fn request_userinfo(
		&self,
		provider: &Provider,
		session: &Session,
	) -> Result<UserInfo> {
		let url = provider
			.userinfo_url
			.clone()
			.ok_or_else(|| err!(Config("userinfo_url", "Missing userinfo URL")))?;

		let mut request = self
			.http_client()
			.get(url)
			.header(ACCEPT, "application/json");

		// Set Host header from issuer_url so providers that validate the
		// Host header (e.g., Zitadel) accept requests routed via Docker
		// internal networking.
		if let Some(issuer) = &provider.issuer_url {
			if let Some(host) = issuer.host_str() {
				let host_val = match issuer.port() {
					| Some(port) => format!("{host}:{port}"),
					| None => host.to_owned(),
				};
				request = request.header("Host", host_val);
			}
		}

		if let Some(access_token) = session.access_token.as_deref() {
			request = request.bearer_auth(access_token);
		}

		let response = request
			.send()
			.await?
			.error_for_status()?
			.limit_read_text(RESPONSE_LIMIT)
			.await?;

		serde_json::from_str(&response).map_err(Into::into)
	}

	/// Send a form-encoded POST request to a provider endpoint.
	async fn post_form<Body>(
		&self,
		provider: &Provider,
		session: &Session,
		url: Url,
		body: Option<Body>,
	) -> Result<JsonValue>
	where
		Body: Serialize,
	{
		let mut request = self
			.http_client()
			.post(url)
			.header(ACCEPT, "application/json");

		// Set Host header from issuer_url for providers that validate it.
		if let Some(issuer) = &provider.issuer_url {
			if let Some(host) = issuer.host_str() {
				let host_val = match issuer.port() {
					| Some(port) => format!("{host}:{port}"),
					| None => host.to_owned(),
				};
				request = request.header("Host", host_val);
			}
		}

		if let Some(body) = body
			.map(serde_html_form::to_string)
			.transpose()
			.map_err(|e| err!(error!("Failed to encode form body: {e}")))?
		{
			request = request
				.header(CONTENT_TYPE, "application/x-www-form-urlencoded")
				.body(body);
		}

		if let Some(access_token) = session.access_token.as_deref() {
			request = request.bearer_auth(access_token);
		}

		let response = request
			.send()
			.await?
			.error_for_status()?
			.limit_read_text(RESPONSE_LIMIT)
			.await?;
		let response: JsonValue = serde_json::from_str(&response)?;

		if let Some(obj) = response.as_object()
			&& let Some(error) = obj.get("error").and_then(JsonValue::as_str)
		{
			let desc = obj
				.get("error_description")
				.and_then(JsonValue::as_str)
				.unwrap_or("(no description)");

			return Err!(Request(Forbidden("Provider error: {error}: {desc}")));
		}

		Ok(response)
	}
}

/// Generate a unique identity hash from the provider's issuer URL and the
/// user's subject claim.
pub fn unique_id(provider: &Provider, sub: &str) -> Result<String> {
	let iss = provider
		.issuer_url
		.as_ref()
		.map(Url::as_str)
		.ok_or_else(|| err!(Config("issuer_url", "Required for unique_id")))?;

	let mut hasher = Sha256::new();
	hasher.update(iss.as_bytes());
	hasher.update(b"\xFF");
	hasher.update(sub.as_bytes());
	let hash = hasher.finalize();

	Ok(b64encode.encode(hash))
}

/// Read the client secret from the provider config (inline or file).
async fn get_client_secret(provider: &Provider) -> Result<String> {
	if let Some(secret) = &provider.client_secret {
		return Ok(secret.clone());
	}

	if let Some(path) = &provider.client_secret_file {
		let secret = tokio::fs::read_to_string(path)
			.await
			.map_err(|e| err!(Config("client_secret_file", "Failed to read: {e}")))?;

		return Ok(secret.trim().to_owned());
	}

	Err!(Config("client_secret", "No client_secret or client_secret_file configured"))
}
