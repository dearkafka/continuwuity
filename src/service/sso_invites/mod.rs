use std::sync::Arc;

use conduwuit::{Err, Result, Server, err, utils::response::LimitReadExt};
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::{client, service::Dep};

/// Maximum provider admin-API response body size.
const RESPONSE_LIMIT: u64 = 64 * 1024;

pub struct Service {
	client: Dep<client::Service>,
	server: Arc<Server>,
}

pub struct IssuedInvite {
	pub provider_id: String,
	pub invite_url: Url,
	pub token_id: String,
	pub expires_at: Option<String>,
	pub usage_limit: u64,
	pub user_group_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignupTokenRequest<'a> {
	ttl: &'a str,
	usage_limit: u64,
	user_group_ids: &'a [String],
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignupTokenResponse {
	id: String,
	token: String,
	expires_at: Option<String>,
}

impl crate::Service for Service {
	fn build(args: crate::Args<'_>) -> Result<Arc<Self>> {
		Ok(Arc::new(Self {
			client: args.depend::<client::Service>("client"),
			server: Arc::clone(args.server),
		}))
	}

	fn name(&self) -> &str {
		crate::service::make_name(std::module_path!())
	}
}

impl Service {
	pub async fn issue_default_invite(
		&self,
		ttl: &str,
		usage_limit: u64,
	) -> Result<IssuedInvite> {
		let ttl = normalize_ttl(ttl)?;
		let (provider_id, provider) = self.default_provider()?;
		let admin_api_url = provider
			.admin_api_url
			.clone()
			.ok_or_else(|| err!(Config("admin_api_url", "Required for !admin sso-invite")))?;
		let issuer_url = provider
			.issuer_url
			.clone()
			.ok_or_else(|| err!(Config("issuer_url", "Required for !admin sso-invite")))?;
		let admin_api_key = get_admin_api_key(&provider).await?;

		let request = SignupTokenRequest {
			ttl: &ttl,
			usage_limit,
			user_group_ids: &provider.invite_user_group_ids,
		};

		let response = self
			.client
			.external_resource
			.post(join_url(&admin_api_url, "api/signup-tokens")?)
			.header("X-API-Key", admin_api_key)
			.json(&request)
			.send()
			.await?;

		let status = response.status();
		let body = response.limit_read_text(RESPONSE_LIMIT).await?;
		if !status.is_success() {
			let detail = body.trim();
			return Err!(Request(Forbidden(error!(
				"Failed to create SSO invite with provider {provider_id}: {}{}",
				status,
				if detail.is_empty() {
					String::new()
				} else {
					format!(" ({detail})")
				}
			))));
		}

		let created: SignupTokenResponse = serde_json::from_str(&body)
			.map_err(|e| err!(error!("Failed to decode SSO invite response: {e}")))?;

		let invite_url = make_signup_url(&issuer_url, &created.token)?;

		Ok(IssuedInvite {
			provider_id,
			invite_url,
			token_id: created.id,
			expires_at: created.expires_at,
			usage_limit,
			user_group_ids: provider.invite_user_group_ids,
		})
	}

	fn default_provider(&self) -> Result<(String, conduwuit::config::IdentityProvider)> {
		self.server
			.config
			.identity_provider
			.iter()
			.find(|(_, provider)| provider.default)
			.or_else(|| self.server.config.identity_provider.iter().next())
			.map(|(id, provider)| (id.clone(), provider.clone()))
			.ok_or_else(|| err!(Request(NotFound("No identity provider configured"))))
	}
}

fn normalize_ttl(ttl: &str) -> Result<String> {
	let ttl = ttl.trim();

	if ttl.is_empty() {
		return Err!(Request(InvalidParam("TTL must not be empty")));
	}

	if let Some(days) = ttl.strip_suffix('d') {
		let days = days.parse::<u64>().map_err(|_| {
			err!(Request(InvalidParam("TTL with `d` must be a whole number, e.g. `7d`")))
		})?;
		let hours = days
			.checked_mul(24)
			.ok_or_else(|| err!(Request(InvalidParam("TTL is too large"))))?;
		return Ok(format!("{hours}h"));
	}

	if let Some(weeks) = ttl.strip_suffix('w') {
		let weeks = weeks.parse::<u64>().map_err(|_| {
			err!(Request(InvalidParam("TTL with `w` must be a whole number, e.g. `1w`")))
		})?;
		let hours = weeks
			.checked_mul(24 * 7)
			.ok_or_else(|| err!(Request(InvalidParam("TTL is too large"))))?;
		return Ok(format!("{hours}h"));
	}

	Ok(ttl.to_owned())
}

async fn get_admin_api_key(provider: &conduwuit::config::IdentityProvider) -> Result<String> {
	if let Some(key) = &provider.admin_api_key {
		return Ok(key.clone());
	}

	if let Some(path) = &provider.admin_api_key_file {
		let key = tokio::fs::read_to_string(path)
			.await
			.map_err(|e| err!(Config("admin_api_key_file", "Failed to read: {e}")))?;

		return Ok(key.trim().to_owned());
	}

	Err!(Config("admin_api_key", "No admin_api_key or admin_api_key_file configured"))
}

fn join_url(base: &Url, path: &str) -> Result<Url> {
	base.join(path)
		.map_err(|e| err!(error!("Failed to build SSO invite URL: {e}")))
}

fn make_signup_url(issuer_url: &Url, token: &str) -> Result<Url> {
	let mut url = join_url(issuer_url, "signup")?;
	url.query_pairs_mut().append_pair("token", token);
	Ok(url)
}

#[cfg(test)]
mod tests {
	use url::Url;

	use super::{make_signup_url, normalize_ttl};

	#[test]
	fn signup_url_uses_public_issuer() {
		let issuer = Url::parse("https://id.fluiid.party").expect("valid URL");
		let signup = make_signup_url(&issuer, "abc123").expect("signup URL");

		assert_eq!(signup.as_str(), "https://id.fluiid.party/signup?token=abc123");
	}

	#[test]
	fn normalize_ttl_converts_days_to_hours() {
		assert_eq!(normalize_ttl("7d").unwrap(), "168h");
	}

	#[test]
	fn normalize_ttl_converts_weeks_to_hours() {
		assert_eq!(normalize_ttl("1w").unwrap(), "168h");
	}

	#[test]
	fn normalize_ttl_keeps_supported_units() {
		assert_eq!(normalize_ttl("24h").unwrap(), "24h");
		assert_eq!(normalize_ttl("30m").unwrap(), "30m");
	}
}
