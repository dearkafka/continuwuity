use std::{
	borrow::Cow,
	time::{Duration, SystemTime},
};

use axum::{
	extract::{Form, Path, Query, State},
	response::{Html, IntoResponse, Redirect},
};
use axum_client_ip::InsecureClientIp;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as b64};
use conduwuit::{Err, Result, debug_warn, err, error, info, utils, warn};
use conduwuit_service::Services;
use http::header;
use ruma::{
	OwnedMxcUri, OwnedUserId, ServerName, UserId,
	api::client::session::{
		get_login_types::v3::{IdentityProvider as RumaIdp, IdentityProviderBrand, SsoLoginType},
		sso_login, sso_login_with_provider,
	},
	events::{GlobalAccountDataEventType, room::message::RoomMessageEventContent},
	push,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use conduwuit::utils::hash;

use super::TOKEN_LENGTH;
use crate::Ruma;

static GRANT_SESSION_COOKIE: &str = "continuwuity_grant_session";

#[derive(Debug, Deserialize, Serialize)]
struct GrantCookie<'a> {
	client_id: Cow<'a, str>,
	state: Cow<'a, str>,
	nonce: Cow<'a, str>,
	redirect_uri: Cow<'a, str>,
}

#[derive(Debug, Serialize)]
struct GrantQuery<'a> {
	client_id: &'a str,
	state: &'a str,
	nonce: &'a str,
	scope: &'a str,
	response_type: &'a str,
	access_type: &'a str,
	code_challenge_method: &'a str,
	code_challenge: &'a str,
	redirect_uri: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CallbackParams {
	code: Option<String>,
	state: Option<String>,
	error: Option<String>,
	error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TokenFormParams {
	token: String,
	sess_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LinkFormParams {
	username: String,
	password: String,
	sess_id: String,
}

/// Build SSO login type for the login types response.
pub(crate) fn build_sso_login_type(services: &Services) -> Option<SsoLoginType> {
	let providers = &services.server.config.identity_provider;
	if providers.is_empty() {
		return None;
	}

	let identity_providers: Vec<RumaIdp> = providers
		.iter()
		.map(|(key, idp)| {
			let brand = match idp.brand.as_str() {
				| "google" => Some(IdentityProviderBrand::Google),
				| "github" => Some(IdentityProviderBrand::GitHub),
				| "gitlab" => Some(IdentityProviderBrand::GitLab),
				| "apple" => Some(IdentityProviderBrand::Apple),
				| "facebook" => Some(IdentityProviderBrand::Facebook),
				| "twitter" => Some(IdentityProviderBrand::Twitter),
				| _ => None,
			};

			RumaIdp {
				id: key.clone(),
				name: idp.name.clone().unwrap_or_else(|| idp.brand.clone()),
				icon: None,
				brand,
			}
		})
		.collect();

	Some(SsoLoginType {
		identity_providers,
		delegated_oidc_compatibility: false,
	})
}

/// # `GET /_matrix/client/v3/login/sso/redirect`
#[tracing::instrument(skip_all, fields(%client), name = "sso_login", level = "debug")]
pub(crate) async fn sso_login_route(
	State(services): State<crate::State>,
	InsecureClientIp(client): InsecureClientIp,
	uri: http::Uri,
	body: Ruma<sso_login::v3::Request>,
) -> Result<sso_login::v3::Response> {
	let providers = &services.server.config.identity_provider;

	let default_key = providers
		.iter()
		.find(|(_, idp)| idp.default)
		.or_else(|| providers.iter().next())
		.map(|(key, _)| key.clone())
		.ok_or_else(|| err!(Request(NotFound("No identity provider configured"))))?;

	let action = sso_action_from_uri(&uri);
	let (location, cookie) =
		handle_sso_redirect(&services, &default_key, &body.body.redirect_url, action).await?;

	Ok(sso_login::v3::Response { location, cookie })
}

/// # `GET /_matrix/client/v3/login/sso/redirect/{idpId}`
#[tracing::instrument(skip_all, fields(%client), name = "sso_login_with_provider", level = "debug")]
pub(crate) async fn sso_login_with_provider_route(
	State(services): State<crate::State>,
	InsecureClientIp(client): InsecureClientIp,
	uri: http::Uri,
	body: Ruma<sso_login_with_provider::v3::Request>,
) -> Result<sso_login_with_provider::v3::Response> {
	let action = sso_action_from_uri(&uri);
	let (location, cookie) =
		handle_sso_redirect(&services, &body.body.idp_id, &body.body.redirect_url, action).await?;

	Ok(sso_login_with_provider::v3::Response { location, cookie })
}

/// Extract MSC3824 `action` parameter from the request URI query string.
fn sso_action_from_uri(uri: &http::Uri) -> Option<String> {
	uri.query().and_then(|q| {
		url::form_urlencoded::parse(q.as_bytes())
			.find(|(k, _)| k == "action" || k == "org.matrix.msc3824.action")
			.map(|(_, v)| v.into_owned())
	})
}

/// Core SSO redirect logic.
async fn handle_sso_redirect(
	services: &Services,
	idp_id: &str,
	redirect_url: &str,
	action: Option<String>,
) -> Result<(String, Option<Cow<'static, str>>)> {
	let redirect_url: Url = Url::parse(redirect_url)
		.map_err(|e| err!(Request(InvalidParam("Invalid redirect_url: {e}"))))?;

	// Validate redirect_url origin against the well-known client URL to
	// prevent open redirects that leak the login token.
	if let Some(ref allowed) = services.server.config.well_known.client {
		if redirect_url.scheme() != allowed.scheme() || redirect_url.host() != allowed.host() {
			return Err!(Request(Forbidden(
				"redirect_url origin does not match the configured client"
			)));
		}
	}

	let provider = services.oauth.get_provider(idp_id).await?;

	let sess_id = utils::random_string(conduwuit_service::oauth::SESSION_ID_LENGTH);
	let query_nonce = utils::random_string(conduwuit_service::oauth::CODE_VERIFIER_LENGTH);
	let cookie_nonce = utils::random_string(conduwuit_service::oauth::CODE_VERIFIER_LENGTH);
	let code_verifier = utils::random_string(conduwuit_service::oauth::CODE_VERIFIER_LENGTH);
	let code_challenge = b64.encode(Sha256::digest(code_verifier.as_bytes()));

	let callback_uri = provider.callback_url.as_ref().map(Url::as_str);
	let scope = if provider.scope.is_empty() {
		"openid email profile".to_owned()
	} else {
		provider.scope.join(" ")
	};

	let query = GrantQuery {
		client_id: &provider.client_id,
		state: &sess_id,
		nonce: &query_nonce,
		access_type: "online",
		response_type: "code",
		code_challenge_method: "S256",
		code_challenge: &code_challenge,
		redirect_uri: callback_uri,
		scope: &scope,
	};

	let authorize_url = provider
		.authorization_url
		.clone()
		.ok_or_else(|| err!(Config("authorization_url", "Missing for provider")))?;

	let query_str = serde_html_form::to_string(&query)
		.map_err(|e| err!(error!("Failed to encode query: {e}")))?;

	let mut authorize_with_query = authorize_url;
	authorize_with_query.set_query(Some(&query_str));

	// MSC3824: detect registration intent from the `action` query parameter
	// on the SSO redirect request itself (not the client's redirect URL).
	// When the provider has a `registration_url`, send the user there
	// first with `redirect_uri` pointing back to the authorize endpoint
	// so they return to the normal OIDC flow after registering.
	let is_register = action.as_deref() == Some("register");

	let location = if is_register
		&& let Some(mut reg_url) = provider.registration_url.clone()
	{
		// After registration, redirect the user back to the client (e.g.
		// Cinny) rather than to the OIDC authorize URL.  Rauthy validates
		// redirect_uri against registered client_uris, and the full
		// authorize URL with query params fails that check.  The user will
		// log in via SSO from the client after completing registration.
		if let Some(client_url) = services.server.config.well_known.client.as_ref() {
			let url_str = client_url.as_str().trim_end_matches('/');
			reg_url
				.query_pairs_mut()
				.append_pair("redirect_uri", url_str);
		}
		reg_url
	} else {
		authorize_with_query
	};

	let cookie_val = GrantCookie {
		client_id: provider.client_id.as_str().into(),
		state: sess_id.as_str().into(),
		nonce: cookie_nonce.as_str().into(),
		redirect_uri: redirect_url.as_str().into(),
	};

	let cookie_val_str = serde_html_form::to_string(&cookie_val)
		.map_err(|e| err!(error!("Failed to encode cookie: {e}")))?;

	// Registration flows go through an external signup page first, so
	// allow extra time (15 min) for the user to complete registration
	// before the grant session expires.
	let default_duration = if is_register { 900 } else { 300 };
	let grant_duration = provider.grant_session_duration.unwrap_or(default_duration);

	// SameSite=Lax is correct for SSO: the callback is always a top-level
	// navigation (GET redirect from the provider), and Lax cookies are sent
	// for top-level navigations. SameSite=None would trigger Chrome's
	// third-party cookie blocking. Secure is set when the callback is HTTPS.
	let secure = provider
		.callback_url
		.as_ref()
		.is_some_and(|url| url.scheme() == "https");

	let cookie = format!(
		"{GRANT_SESSION_COOKIE}={cookie_val_str}; \
		 Max-Age={grant_duration}; Path=/; SameSite=Lax; {}HttpOnly",
		if secure { "Secure; " } else { "" },
	);

	let session = conduwuit_service::oauth::Session {
		idp_id: Some(idp_id.to_owned()),
		sess_id: Some(sess_id),
		redirect_url: Some(redirect_url),
		code_verifier: Some(code_verifier),
		query_nonce: Some(query_nonce),
		cookie_nonce: Some(cookie_nonce),
		authorize_expires_at: SystemTime::now().checked_add(Duration::from_secs(grant_duration)),
		..Default::default()
	};

	services.oauth.sessions.put(&session, None);

	Ok((location.to_string(), Some(Cow::Owned(cookie))))
}

/// # `GET /_matrix/client/unstable/login/sso/callback/{idpId}`
///
/// OAuth2 callback from the identity provider.
pub(crate) async fn sso_callback_route(
	State(services): State<crate::State>,
	Path(idp_id): Path<String>,
	Query(params): Query<CallbackParams>,
	headers: http::HeaderMap,
) -> Result<axum::response::Response> {
	if let Some(error) = &params.error {
		let desc = params
			.error_description
			.as_deref()
			.unwrap_or("Unknown error");
		let error = html_escape(error);
		let desc = html_escape(desc);
		return Ok(sso_html_response(format!(
			"<html><body><h1>Authentication Failed</h1><p>{error}: {desc}</p>\
			 <p><a href=\"/\">Return to login</a></p></body></html>"
		)));
	}

	let code = params
		.code
		.as_deref()
		.ok_or_else(|| err!(Request(Forbidden("Missing code in callback"))))?;
	let sess_id = params
		.state
		.as_deref()
		.ok_or_else(|| err!(Request(Forbidden("Missing state in callback"))))?;

	let session = services.oauth.sessions.get(sess_id).await?;
	let provider = services.oauth.get_provider(&idp_id).await?;

	// Validate session.
	if session.sess_id.as_deref() != Some(sess_id) {
		return Err!(Request(Unauthorized("Session ID not recognized.")));
	}
	if session.idp_id.as_deref() != Some(idp_id.as_str()) {
		return Err!(Request(Unauthorized("Identity provider mismatch.")));
	}

	// Validate session expiry.
	validate_grant_session(&session)?;

	validate_grant_cookie(&headers, &session, &provider)?;

	// Exchange authorization code for access token.
	let token_response = services
		.oauth
		.request_token(&provider, &session, code)
		.await?;

	let session = conduwuit_service::oauth::Session {
		scope: token_response.scope,
		token_type: token_response.token_type,
		access_token: token_response.access_token,
		refresh_token: token_response.refresh_token,
		..session
	};

	// Fetch userinfo.
	let userinfo = services.oauth.request_userinfo(&provider, &session).await?;
	let unique_id = conduwuit_service::oauth::unique_id(&provider, &userinfo.sub)?;

	let session = conduwuit_service::oauth::Session {
		user_info: Some(userinfo.clone()),
		..session
	};

	// 1. Check email allowlist only for trusted providers that assert the
	// presented email has been verified.
	if let Some(email) = trusted_verified_email(&provider, &userinfo) {
		if let Ok(mapped_user_id) = services.oauth.sessions.get_user_by_email(email).await {
			if let Ok(user_id) = OwnedUserId::try_from(mapped_user_id) {
				return complete_sso_login(&services, session, &user_id, Some(&unique_id)).await;
			}
		}
	}

	// 2. Check for existing session by unique_id (returning user).
	if let Ok(existing) = services.oauth.sessions.get_by_unique_id(&unique_id).await {
		if let Some(user_id) = existing.user_id.as_ref() {
			// Clean up old session if different from current.
			if let Some(old_sess_id) = existing.sess_id.as_deref() {
				if Some(old_sess_id) != session.sess_id.as_deref() {
					services.oauth.sessions.delete(old_sess_id).await;
				}
			}
			return complete_sso_login(&services, session, user_id, Some(&unique_id)).await;
		}
	}

	// 3. New user — check if registration is allowed via this provider.
	if !provider.registration {
		return Err!(Request(Forbidden(
			"Registration is not enabled for this identity provider."
		)));
	}

	// 4. Auto-register if open SSO registration is enabled.
	if services.server.config.sso_allow_open_registration {
		let user_id = decide_user_id(&services, &provider, &userinfo, &unique_id).await?;
		if !services.users.exists(&user_id).await {
			register_user(&services, &provider, &userinfo, &user_id).await?;
			store_email_mapping(&services, &provider, &user_id, &userinfo).await;
		}
		return complete_sso_login(&services, session, &user_id, Some(&unique_id)).await;
	}

	// 5. Persist the session and prompt the user. Show the account linking
	// page first (existing users can verify their password to link), with an
	// option to switch to the invite-token page for new users.
	services.oauth.sessions.put(&session, None);

	Ok(sso_html_response(render_link_prompt(sess_id, None)))
}

/// # `POST /_continuwuity/sso/token_submit`
///
/// Complete invite-only SSO registration after the provider callback.
pub(crate) async fn sso_token_submit_route(
	State(services): State<crate::State>,
	headers: http::HeaderMap,
	Form(form): Form<TokenFormParams>,
) -> Result<axum::response::Response> {
	let session = services.oauth.sessions.get(&form.sess_id).await?;

	if session.sess_id.as_deref() != Some(form.sess_id.as_str()) {
		return Err!(Request(Unauthorized("Session ID not recognized.")));
	}

	validate_grant_session(&session)?;

	let provider_id = session
		.idp_id
		.as_deref()
		.ok_or_else(|| err!(Request(Unauthorized("Missing identity provider in session."))))?;
	let provider = services.oauth.get_provider(provider_id).await?;

	validate_grant_cookie(&headers, &session, &provider)?;

	if !provider.registration {
		return Err!(Request(Forbidden(
			"Registration is not enabled for this identity provider."
		)));
	}

	let userinfo = session
		.user_info
		.as_ref()
		.ok_or_else(|| err!(Request(NotFound("Session missing userinfo"))))?;
	let unique_id = conduwuit_service::oauth::unique_id(&provider, &userinfo.sub)?;

	if let Ok(existing) = services.oauth.sessions.get_by_unique_id(&unique_id).await {
		if let Some(user_id) = existing.user_id.as_ref() {
			return complete_sso_login(&services, session, user_id, Some(&unique_id)).await;
		}
	}

	let token = form.token.trim().to_owned();
	let Some(valid_token) = services.registration_tokens.validate_token(token).await else {
		return Ok(sso_html_response(render_token_prompt(
			&form.sess_id,
			Some("Invalid or expired invite token."),
		)));
	};

	let user_id = decide_user_id(&services, &provider, userinfo, &unique_id).await?;

	// Invite-token onboarding must never bind an unlinked SSO identity to an
	// existing local account.
	if services.users.exists(&user_id).await {
		return Err!(Request(UserInUse("User ID is not available.")));
	}

	register_user(&services, &provider, userinfo, &user_id).await?;
	services.registration_tokens.mark_token_as_used(valid_token);

	store_email_mapping(&services, &provider, &user_id, userinfo).await;

	complete_sso_login(&services, session, &user_id, Some(&unique_id)).await
}

/// # `POST /_continuwuity/sso/link`
///
/// Self-service account linking: user enters their existing Matrix username +
/// password to link their account to their SSO identity. The SSO session must
/// already have userinfo populated (i.e. the user came through the SSO
/// callback). On success, stores the email↔user_id mapping and completes
/// the SSO login flow.
pub(crate) async fn sso_link_account_route(
	State(services): State<crate::State>,
	headers: http::HeaderMap,
	Form(form): Form<LinkFormParams>,
) -> Result<axum::response::Response> {
	let session = services.oauth.sessions.get(&form.sess_id).await?;

	if session.sess_id.as_deref() != Some(form.sess_id.as_str()) {
		return Err!(Request(Unauthorized("Session ID not recognized.")));
	}

	validate_grant_session(&session)?;

	let provider_id = session
		.idp_id
		.as_deref()
		.ok_or_else(|| err!(Request(Unauthorized("Missing identity provider in session."))))?;
	let provider = services.oauth.get_provider(provider_id).await?;

	validate_grant_cookie(&headers, &session, &provider)?;

	let userinfo = session
		.user_info
		.as_ref()
		.ok_or_else(|| err!(Request(NotFound("Session missing userinfo"))))?;
	let unique_id = conduwuit_service::oauth::unique_id(&provider, &userinfo.sub)?;

	// If user is already linked (race with another tab), just complete login.
	if let Ok(existing) = services.oauth.sessions.get_by_unique_id(&unique_id).await {
		if let Some(user_id) = existing.user_id.as_ref() {
			return complete_sso_login(&services, session, user_id, Some(&unique_id)).await;
		}
	}

	// Use a single generic error for all credential failures to prevent
	// user enumeration (same pattern as m.login.password).
	let credential_error = "Wrong username or password.";

	// Validate the username — parse with local server name. If the user
	// provides a full Matrix ID, verify it belongs to this server.
	let username = form.username.trim();
	let server_name = &services.server.config.server_name;
	let user_id = if username.starts_with('@') {
		let parsed = UserId::parse(username)
			.map_err(|_| err!(Request(Forbidden("Invalid username."))))?
			.to_owned();
		if parsed.server_name() != server_name {
			return Ok(sso_html_response(render_link_prompt(
				&form.sess_id,
				Some(credential_error),
			)));
		}
		parsed
	} else {
		UserId::parse_with_server_name(username, server_name)
			.map_err(|_| err!(Request(Forbidden("Invalid username."))))?
	};

	if !services.users.exists(&user_id).await {
		return Ok(sso_html_response(render_link_prompt(
			&form.sess_id,
			Some(credential_error),
		)));
	}

	// Only allow linking to password-origin accounts (or legacy accounts with
	// no origin set). SSO-origin accounts should use the returning user flow.
	if services
		.users
		.origin(&user_id)
		.await
		.is_ok_and(|origin| origin != "password")
	{
		return Ok(sso_html_response(render_link_prompt(
			&form.sess_id,
			Some(credential_error),
		)));
	}

	// Verify password.
	let password_hash = services
		.users
		.password_hash(&user_id)
		.await
		.map_err(|_| err!(Request(Forbidden("Wrong username or password."))))?;

	if password_hash.is_empty() {
		return Ok(sso_html_response(render_link_prompt(
			&form.sess_id,
			Some(credential_error),
		)));
	}

	if hash::verify_password(&form.password, &password_hash).is_err() {
		return Ok(sso_html_response(render_link_prompt(
			&form.sess_id,
			Some(credential_error),
		)));
	}

	// Password verified — store the email mapping and complete SSO login.
	store_email_mapping(&services, &provider, &user_id, userinfo).await;

	info!(%user_id, "Account linked to SSO identity via self-service");
	if services.server.config.admin_room_notices {
		let idp_name = provider.name.as_deref().unwrap_or(provider.brand.as_str());
		services
			.admin
			.notice(&format!(
				"User \"{user_id}\" linked their account to {idp_name} via self-service SSO"
			))
			.await;
	}

	complete_sso_login(&services, session, &user_id, Some(&unique_id)).await
}

#[derive(Debug, Deserialize)]
pub(crate) struct PageParams {
	sess_id: String,
}

/// # `GET /_continuwuity/sso/link_page`
///
/// Serve the account linking page (navigated from the token page).
pub(crate) async fn sso_link_page_route(
	State(services): State<crate::State>,
	Query(params): Query<PageParams>,
	headers: http::HeaderMap,
) -> Result<axum::response::Response> {
	let session = services.oauth.sessions.get(&params.sess_id).await?;
	validate_grant_session(&session)?;
	let provider_id = session
		.idp_id
		.as_deref()
		.ok_or_else(|| err!(Request(Unauthorized("Missing identity provider in session."))))?;
	let provider = services.oauth.get_provider(provider_id).await?;
	validate_grant_cookie(&headers, &session, &provider)?;

	Ok(sso_html_response(render_link_prompt(&params.sess_id, None)))
}

/// # `GET /_continuwuity/sso/token_page`
///
/// Serve the invite token page (navigated from the link page).
pub(crate) async fn sso_token_page_route(
	State(services): State<crate::State>,
	Query(params): Query<PageParams>,
	headers: http::HeaderMap,
) -> Result<axum::response::Response> {
	let session = services.oauth.sessions.get(&params.sess_id).await?;
	validate_grant_session(&session)?;
	let provider_id = session
		.idp_id
		.as_deref()
		.ok_or_else(|| err!(Request(Unauthorized("Missing identity provider in session."))))?;
	let provider = services.oauth.get_provider(provider_id).await?;
	validate_grant_cookie(&headers, &session, &provider)?;

	Ok(sso_html_response(render_token_prompt(&params.sess_id, None)))
}

/// Complete SSO login for a known user — generate login token and redirect.
async fn complete_sso_login(
	services: &Services,
	session: conduwuit_service::oauth::Session,
	user_id: &UserId,
	unique_id: Option<&str>,
) -> Result<axum::response::Response> {
	// Auto-create user if in email allowlist but not yet registered.
	// Only allowed when the provider permits registration.
	if !services.users.exists(user_id).await {
		let provider_id = session.idp_id.as_deref().unwrap_or("unknown");
		let provider = services.oauth.get_provider(provider_id).await.ok();
		let registration_allowed = provider.as_ref().is_some_and(|p| p.registration);

		if !registration_allowed {
			return Err!(Request(Forbidden(
				"Registration is not enabled for this identity provider."
			)));
		}

		if let (Some(provider), Some(userinfo)) = (&provider, &session.user_info) {
			register_user(services, provider, userinfo, user_id).await?;
			store_email_mapping(services, provider, user_id, userinfo).await;
		}
	}

	// Always check active + suspended status before issuing a login token.
	if !services.users.is_active_local(user_id).await {
		return Err!(Request(UserDeactivated("This user has been deactivated.")));
	}

	if services
		.users
		.is_suspended(user_id)
		.await
		.unwrap_or(false)
	{
		return Err!(Request(Forbidden("This user has been suspended.")));
	}

	let login_token = utils::random_string(TOKEN_LENGTH);
	services.users.create_login_token(user_id, &login_token);

	let mut final_url = session
		.redirect_url
		.clone()
		.ok_or_else(|| err!(Request(InvalidParam("Missing redirect URL in session data"))))?;
	final_url
		.query_pairs_mut()
		.append_pair("loginToken", &login_token);

	let session = conduwuit_service::oauth::Session {
		user_id: Some(user_id.to_owned()),
		..session
	};
	services.oauth.sessions.put(&session, unique_id);

	let mut response = Redirect::to(final_url.as_str()).into_response();
	response
		.headers_mut()
		.insert(header::SET_COOKIE, clear_grant_cookie());
	Ok(response)
}

/// Decide the Matrix user ID for an SSO user based on provider claims.
///
/// Uses a tiered fallback chain filtered by provider `userid_claims` config.
/// Each candidate is validated: must be a legal Matrix localpart, not
/// forbidden, and not already taken by a non-SSO user.
///
/// Ported from Tuwunel's `decide_user_id` with addition of `strip_domain`
/// for providers that include domain in usernames (e.g., Zitadel).
async fn decide_user_id(
	services: &Services,
	provider: &conduwuit_service::oauth::Provider,
	userinfo: &conduwuit_service::oauth::UserInfo,
	unique_id: &str,
) -> Result<OwnedUserId> {
	let allowed = |claim: &str| -> bool {
		provider.userid_claims.is_empty() || provider.userid_claims.iter().any(|c| c == claim)
	};

	// Strip domain from identifiers containing '@' (Zitadel returns
	// preferred_username as "user@domain").
	let strip_domain = |s: &str| -> String {
		s.split_once('@')
			.map_or(s, |(local, _)| local)
			.to_lowercase()
	};

	let choices: [Option<String>; 5] = [
		userinfo
			.preferred_username
			.as_deref()
			.filter(|_| allowed("preferred_username"))
			.map(|s| strip_domain(s)),
		userinfo
			.username
			.as_deref()
			.filter(|_| allowed("username"))
			.map(|s| strip_domain(s)),
		userinfo
			.nickname
			.as_deref()
			.filter(|_| allowed("nickname"))
			.map(str::to_lowercase),
		(provider.brand == "github")
			.then_some(userinfo.sub.as_str())
			.filter(|_| allowed("login"))
			.map(str::to_lowercase),
		userinfo
			.email
			.as_deref()
			.and_then(|email| email.split_once('@'))
			.map(|(local, _)| local)
			.filter(|_| allowed("email"))
			.map(str::to_lowercase),
	];

	let server_name = &services.server.config.server_name;

	for choice in choices.into_iter().flatten() {
		if let Some(user_id) = try_user_id(services, server_name, &choice, false).await {
			return Ok(user_id);
		}
	}

	// Deterministic fallback: truncated hash of unique_id (15-23 chars).
	let hash = Sha256::digest(unique_id.as_bytes());
	let fallback = b64.encode(&hash[..12]).to_lowercase();
	if let Some(user_id) = try_user_id(services, server_name, &fallback, true).await {
		return Ok(user_id);
	}

	Err!(Request(UserInUse("User ID is not available.")))
}

/// Validate a candidate username and return a user ID if it's usable.
///
/// Checks:
/// - Valid Matrix localpart (no disallowed characters)
/// - Not in the forbidden_usernames regex set
/// - Not already taken by a non-SSO user
/// - If `may_exist` is false, rejects already-existing usernames entirely
async fn try_user_id(
	services: &Services,
	server_name: &ServerName,
	username: &str,
	may_exist: bool,
) -> Option<OwnedUserId> {
	let user_id = UserId::parse_with_server_name(username, server_name)
		.inspect_err(|e| warn!(?username, "SSO username invalid: {e}"))
		.ok()?;

	if let Err(e) = user_id.validate_strict() {
		warn!(?username, "SSO username contains disallowed characters: {e}");
		return None;
	}

	if services.globals.forbidden_usernames().is_match(username) {
		warn!(?username, "SSO username forbidden.");
		return None;
	}

	if services.users.exists(&user_id).await {
		debug_warn!(?username, "SSO username already exists.");

		// Only allow reuse if the existing account is SSO-origin.
		if services
			.users
			.origin(&user_id)
			.await
			.ok()
			.is_none_or(|origin| origin != "sso")
		{
			debug_warn!(?username, "Existing user has non-SSO origin, skipping.");
			return None;
		}

		if !may_exist {
			return None;
		}
	}

	Some(user_id)
}

/// Register a new Matrix user account from SSO provider claims.
///
/// Sets password to "*" (disabled), origin to "sso", display name from
/// provider claims. Downloads and uploads provider avatar if available.
/// Posts an admin room notice about the new registration.
async fn register_user(
	services: &Services,
	provider: &conduwuit_service::oauth::Provider,
	userinfo: &conduwuit_service::oauth::UserInfo,
	user_id: &UserId,
) -> Result<()> {
	info!(%user_id, "Creating new SSO user account");

	services
		.users
		.create(user_id, Some("*"), Some("sso"))
		.await?;

	initialize_user_profile(services, user_id, userinfo.name.as_deref()).await?;

	// Download and set avatar from provider.
	if let Some(avatar_url) = userinfo
		.avatar_url
		.as_deref()
		.or(userinfo.picture.as_deref())
	{
		if let Err(e) = set_avatar(services, user_id, avatar_url).await {
			debug_warn!(%user_id, %avatar_url, "Failed to set SSO avatar: {e}");
		}
	}

	// Admin room notice.
	let idp_name = provider.name.as_deref().unwrap_or(provider.brand.as_str());

	let notice = format!("New user \"{user_id}\" registered on this server via {idp_name}");

	info!("{notice}");
	if services.server.config.admin_room_notices {
		services.admin.notice(&notice).await;
	}

	Ok(())
}

async fn initialize_user_profile(
	services: &Services,
	user_id: &UserId,
	displayname: Option<&str>,
) -> Result<()> {
	let mut displayname = displayname
		.unwrap_or_else(|| user_id.localpart())
		.to_owned();

	let suffix = services.globals.new_user_displayname_suffix();
	if !suffix.is_empty() {
		displayname.push(' ');
		displayname.push_str(suffix);
	}

	services.users.set_displayname(user_id, Some(displayname));

	services
		.account_data
		.update(
			None,
			user_id,
			GlobalAccountDataEventType::PushRules.to_string().into(),
			&serde_json::to_value(ruma::events::push_rules::PushRulesEvent {
				content: ruma::events::push_rules::PushRulesEventContent {
					global: push::Ruleset::server_default(user_id),
				},
			})?,
		)
		.await?;

	let was_first_user = services.firstrun.empower_first_user(user_id).await?;
	if !was_first_user && services.config.suspend_on_register {
		services
			.users
			.suspend_account(user_id, &services.globals.server_user)
			.await;

		if services.server.config.admin_room_notices {
			services
				.admin
				.send_loud_message(RoomMessageEventContent::text_plain(format!(
					"User {user_id} has been suspended as they are not the first user on this \
					 server. Please review and unsuspend them if appropriate."
				)))
				.await
				.ok();
		}
	}

	for room in &services.server.config.auto_join_rooms {
		let Ok(room_id) = services.rooms.alias.resolve(room).await else {
			error!(
				"Failed to resolve room alias to room ID when attempting to auto join {room}, \
				 skipping"
			);
			continue;
		};

		if !services
			.rooms
			.state_cache
			.server_in_room(services.globals.server_name(), &room_id)
			.await
		{
			warn!("Skipping room {room} to automatically join as we have never joined before.");
			continue;
		}

		let Some(room_server_name) = room.server_name() else {
			continue;
		};

		match super::join_room_by_id_helper(
			services,
			user_id,
			&room_id,
			Some("Automatically joining this room upon registration".to_owned()),
			&[services.globals.server_name().to_owned(), room_server_name.to_owned()],
			&None,
		)
		.await
		{
			| Ok(_) => {
				info!("Automatically joined room {room} for user {user_id}");
			},
			| Err(e) => {
				error!("Failed to automatically join room {room} for user {user_id}: {e}");
			},
		}
	}

	Ok(())
}

async fn store_email_mapping(
	services: &Services,
	provider: &conduwuit_service::oauth::Provider,
	user_id: &UserId,
	userinfo: &conduwuit_service::oauth::UserInfo,
) {
	let Some(email) = trusted_verified_email(provider, userinfo) else {
		return;
	};

	match services.oauth.sessions.get_user_by_email(email).await {
		| Ok(existing_user_id) if existing_user_id != user_id.as_str() => {
			warn!(
				%email,
				%user_id,
				existing_user_id,
				"Refusing to overwrite existing SSO email mapping"
			);
		},
		| _ => {
			services
				.oauth
				.sessions
				.set_email(user_id.as_str(), email)
				.await
		},
	}
}

fn trusted_verified_email<'a>(
	provider: &conduwuit_service::oauth::Provider,
	userinfo: &'a conduwuit_service::oauth::UserInfo,
) -> Option<&'a str> {
	if !provider.trusted || userinfo.email_verified != Some(true) {
		return None;
	}

	userinfo.email.as_deref()
}

#[cfg(test)]
mod tests {
	use conduwuit::config::IdentityProvider;

	use super::trusted_verified_email;

	fn provider(trusted: bool) -> IdentityProvider {
		IdentityProvider {
			brand: "zitadel".to_owned(),
			client_id: "client".to_owned(),
			client_secret: None,
			client_secret_file: None,
			issuer_url: None,
			authorization_url: None,
			token_url: None,
			userinfo_url: None,
			revocation_url: None,
			callback_url: None,
			discovery: true,
			discovery_url: None,
			base_path: String::new(),
			default: false,
			name: Some("Zitadel".to_owned()),
			icon: None,
			scope: vec!["openid".to_owned(), "email".to_owned()],
			userid_claims: vec!["preferred_username".to_owned()],
			grant_session_duration: Some(300),
			registration: true,
			registration_url: None,
			trusted,
		}
	}

	#[test]
	fn trusted_verified_email_requires_trusted_provider() {
		let userinfo = conduwuit_service::oauth::UserInfo {
			email: Some("alice@example.com".to_owned()),
			email_verified: Some(true),
			..Default::default()
		};

		assert_eq!(trusted_verified_email(&provider(false), &userinfo), None);
	}

	#[test]
	fn trusted_verified_email_requires_verified_claim() {
		let userinfo = conduwuit_service::oauth::UserInfo {
			email: Some("alice@example.com".to_owned()),
			email_verified: Some(false),
			..Default::default()
		};

		assert_eq!(trusted_verified_email(&provider(true), &userinfo), None);
	}

	#[test]
	fn trusted_verified_email_returns_email_when_both_conditions_hold() {
		let userinfo = conduwuit_service::oauth::UserInfo {
			email: Some("alice@example.com".to_owned()),
			email_verified: Some(true),
			..Default::default()
		};

		assert_eq!(trusted_verified_email(&provider(true), &userinfo), Some("alice@example.com"));
	}
}

/// Download an avatar image from a URL and upload it to the homeserver's
/// media store, then set it as the user's avatar.
async fn set_avatar(services: &Services, user_id: &UserId, avatar_url: &str) -> Result<()> {
	use conduwuit_service::media::MXC_LENGTH;
	use ruma::Mxc;

	// Validate avatar URL to prevent SSRF — only allow https (or http for
	// providers that don't support TLS in dev).
	let parsed = Url::parse(avatar_url)
		.map_err(|_| err!(Request(InvalidParam("Invalid avatar URL"))))?;

	if !matches!(parsed.scheme(), "https" | "http") {
		return Err!(Request(InvalidParam("Avatar URL must be http(s)")));
	}

	const MAX_AVATAR_SIZE: usize = 5 * 1024 * 1024; // 5 MiB

	let response = services
		.client
		.default
		.get(avatar_url)
		.send()
		.await?
		.error_for_status()?;

	let content_type = response
		.headers()
		.get(header::CONTENT_TYPE)
		.and_then(|v| v.to_str().ok())
		.map(ToOwned::to_owned);

	let bytes = response.bytes().await?;

	if bytes.len() > MAX_AVATAR_SIZE {
		return Err!(Request(TooLarge("Avatar exceeds 5 MiB size limit")));
	}

	let media_id = utils::random_string(MXC_LENGTH);
	let mxc = Mxc {
		server_name: services.globals.server_name(),
		media_id: &media_id,
	};

	services
		.media
		.create(&mxc, Some(user_id), None, content_type.as_deref(), &bytes)
		.await?;

	let mxc_uri: OwnedMxcUri = mxc.to_string().into();
	services.users.set_avatar_url(user_id, Some(mxc_uri));

	Ok(())
}

/// Escape a string for safe inclusion in HTML content.
fn html_escape(s: &str) -> String {
	s.replace('&', "&amp;")
		.replace('<', "&lt;")
		.replace('>', "&gt;")
		.replace('"', "&quot;")
		.replace('\'', "&#x27;")
}

/// Wrap HTML content in a response with a CSP that allows inline styles
/// and form submission. Without this, Continuwuity's default
/// `sandbox; default-src 'none'` CSP blocks all rendering.
fn sso_html_response(html: String) -> axum::response::Response {
	(
		[(
			header::CONTENT_SECURITY_POLICY,
			"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'".to_owned(),
		)],
		Html(html),
	)
		.into_response()
}

fn render_token_prompt(sess_id: &str, error: Option<&str>) -> String {
	let error_html = error.map_or_else(String::new, |message| {
		format!(r#"<p class="error" role="alert">{message}</p>"#)
	});

	format!(
		r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Invite Token Required</title>
<style>
body {{
	font-family: system-ui, sans-serif;
	background: #111827;
	color: #f3f4f6;
	display: flex;
	justify-content: center;
	align-items: center;
	min-height: 100vh;
	margin: 0;
	padding: 1.5rem;
}}
.card {{
	background: #1f2937;
	border: 1px solid #374151;
	border-radius: 12px;
	padding: 2rem;
	max-width: 420px;
	width: 100%;
	box-shadow: 0 20px 45px rgba(0, 0, 0, 0.35);
}}
h1 {{
	font-size: 1.4rem;
	margin: 0 0 0.75rem;
}}
p {{
	color: #d1d5db;
	line-height: 1.5;
	margin: 0 0 1rem;
}}
.error {{
	background: #7f1d1d;
	border: 1px solid #ef4444;
	border-radius: 8px;
	color: #fee2e2;
	padding: 0.75rem;
}}
input[type="text"] {{
	width: 100%;
	padding: 0.8rem 0.9rem;
	border: 1px solid #4b5563;
	border-radius: 8px;
	background: #111827;
	color: inherit;
	font-size: 1rem;
	box-sizing: border-box;
	margin: 0.25rem 0 1rem;
}}
button {{
	width: 100%;
	padding: 0.8rem 0.9rem;
	border: none;
	border-radius: 8px;
	background: #2563eb;
	color: white;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
}}
button:hover {{
	background: #1d4ed8;
}}
</style>
</head>
<body>
<div class="card">
<h1>Invite Token Required</h1>
<p>SSO authentication succeeded, but this server only allows new accounts with an invite token.</p>
{error_html}
<form method="POST" action="/_continuwuity/sso/token_submit">
<input type="hidden" name="sess_id" value="{sess_id}">
<input type="text" name="token" placeholder="Enter invite token" required autofocus>
<button type="submit">Continue</button>
</form>
<p style="font-size: 0.8rem; color: #6b7280; margin-top: 1rem; text-align: center;"><a href="/_continuwuity/sso/link_page?sess_id={sess_id}" style="color: #60a5fa;">Already have an account? Link it to SSO</a></p>
</div>
</body>
</html>"#
	)
}

fn render_link_prompt(sess_id: &str, error: Option<&str>) -> String {
	let error_html = error.map_or_else(String::new, |message| {
		format!(r#"<p class="error" role="alert">{message}</p>"#)
	});

	format!(
		r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Link Your Account</title>
<style>
body {{
	font-family: system-ui, sans-serif;
	background: #111827;
	color: #f3f4f6;
	display: flex;
	justify-content: center;
	align-items: center;
	min-height: 100vh;
	margin: 0;
	padding: 1.5rem;
}}
.card {{
	background: #1f2937;
	border: 1px solid #374151;
	border-radius: 12px;
	padding: 2rem;
	max-width: 420px;
	width: 100%;
	box-shadow: 0 20px 45px rgba(0, 0, 0, 0.35);
}}
h1 {{
	font-size: 1.4rem;
	margin: 0 0 0.75rem;
}}
p {{
	color: #d1d5db;
	line-height: 1.5;
	margin: 0 0 1rem;
}}
.error {{
	background: #7f1d1d;
	border: 1px solid #ef4444;
	border-radius: 8px;
	color: #fee2e2;
	padding: 0.75rem;
}}
label {{
	display: block;
	font-size: 0.9rem;
	color: #9ca3af;
	margin: 0 0 0.3rem;
}}
input[type="text"], input[type="password"] {{
	width: 100%;
	padding: 0.8rem 0.9rem;
	border: 1px solid #4b5563;
	border-radius: 8px;
	background: #111827;
	color: inherit;
	font-size: 1rem;
	box-sizing: border-box;
	margin: 0 0 0.75rem;
}}
button {{
	width: 100%;
	padding: 0.8rem 0.9rem;
	border: none;
	border-radius: 8px;
	background: #2563eb;
	color: white;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
	margin-top: 0.25rem;
}}
button:hover {{
	background: #1d4ed8;
}}
.hint {{
	font-size: 0.8rem;
	color: #6b7280;
	margin-top: 1rem;
	text-align: center;
}}
</style>
</head>
<body>
<div class="card">
<h1>Link Your Account</h1>
<p>SSO authentication succeeded. Enter your existing username and password to link your account.</p>
{error_html}
<form method="POST" action="/_continuwuity/sso/link">
<input type="hidden" name="sess_id" value="{sess_id}">
<label for="username">Username</label>
<input type="text" id="username" name="username" placeholder="e.g. kafka" required autofocus>
<label for="password">Password</label>
<input type="password" id="password" name="password" required>
<button type="submit">Link &amp; Sign In</button>
</form>
<p class="hint">After linking, you can sign in with SSO from now on.</p>
<p class="hint"><a href="/_continuwuity/sso/token_page?sess_id={sess_id}" style="color: #60a5fa;">Don't have an account? Register with invite token</a></p>
</div>
</body>
</html>"#
	)
}

fn validate_grant_session(session: &conduwuit_service::oauth::Session) -> Result<()> {
	// Treat a missing expiry as expired (defensive against schema issues or
	// overflow in `checked_add`).
	let expired = session
		.authorize_expires_at
		.map_or(true, |exp| SystemTime::now() > exp);

	if expired {
		return Err!(Request(Unauthorized("Authorization grant session has expired.")));
	}

	Ok(())
}

fn validate_grant_cookie(
	headers: &http::HeaderMap,
	session: &conduwuit_service::oauth::Session,
	provider: &conduwuit_service::oauth::Provider,
) -> Result<()> {
	let cookie_header = headers
		.get(header::COOKIE)
		.and_then(|v| v.to_str().ok())
		.unwrap_or("");

	let grant_cookie = cookie_header
		.split(';')
		.map(str::trim)
		.find(|c| c.starts_with(&format!("{GRANT_SESSION_COOKIE}=")))
		.and_then(|c| c.strip_prefix(&format!("{GRANT_SESSION_COOKIE}=")))
		.and_then(|v| serde_html_form::from_str::<GrantCookie<'_>>(v).ok())
		.ok_or_else(|| err!(Request(Unauthorized("Missing SSO cookie"))))?;

	let sess_id = session
		.sess_id
		.as_deref()
		.ok_or_else(|| err!(Request(Unauthorized("Session ID not recognized."))))?;

	if grant_cookie.state.as_ref() != sess_id {
		return Err!(Request(Unauthorized("Cookie state mismatch.")));
	}

	if Some(grant_cookie.nonce.as_ref()) != session.cookie_nonce.as_deref() {
		return Err!(Request(Unauthorized("Cookie nonce mismatch.")));
	}

	if grant_cookie.client_id.as_ref() != provider.client_id.as_str() {
		return Err!(Request(Unauthorized("Cookie client_id mismatch.")));
	}

	if session.redirect_url.as_ref().map(Url::as_str) != Some(grant_cookie.redirect_uri.as_ref())
	{
		return Err!(Request(Unauthorized("Cookie redirect URI mismatch.")));
	}

	Ok(())
}

fn clear_grant_cookie() -> header::HeaderValue {
	// Match the original cookie's attributes so the browser clears the right one.
	format!("{GRANT_SESSION_COOKIE}=; Max-Age=0; Path=/; SameSite=Lax; HttpOnly")
		.parse()
		.expect("static cookie string is always valid")
}
