use std::time::SystemTime;

use axum::{
	Form, Json,
	extract::{Query, State},
	response::{Html, IntoResponse, Redirect},
};
use axum_extra::{
	TypedHeader,
	headers::{Authorization, authorization::Bearer},
};
use conduwuit::{Err, Result, err, info, utils};
use conduwuit_service::oauth::oidc_server::{
	DcrRequest, IdTokenClaims, OidcAuthRequest, OidcServer, ProviderMetadata,
};
use http::StatusCode;
use ruma::OwnedDeviceId;
use serde::{Deserialize, Serialize};
use url::Url;

const OIDC_REQ_ID_LENGTH: usize = 32;

#[derive(Serialize)]
struct AuthIssuerResponse {
	issuer: String,
}

pub(crate) async fn auth_issuer_route(
	State(services): State<crate::State>,
	headers: http::HeaderMap,
) -> Result<impl IntoResponse> {
	let issuer = oidc_issuer_url(&services, &headers)?;
	Ok(Json(AuthIssuerResponse { issuer }))
}

pub(crate) async fn openid_configuration_route(
	State(services): State<crate::State>,
	headers: http::HeaderMap,
) -> Result<impl IntoResponse> {
	Ok(Json(oidc_metadata(&services, &headers)?))
}

fn oidc_metadata(
	services: &conduwuit_service::Services,
	headers: &http::HeaderMap,
) -> Result<ProviderMetadata> {
	let issuer = oidc_issuer_url(services, headers)?;
	let base = issuer.trim_end_matches('/').to_owned();

	Ok(ProviderMetadata {
		issuer,
		authorization_endpoint: format!("{base}/_continuwuity/oidc/authorize"),
		token_endpoint: format!("{base}/_continuwuity/oidc/token"),
		registration_endpoint: Some(format!("{base}/_continuwuity/oidc/registration")),
		revocation_endpoint: Some(format!("{base}/_continuwuity/oidc/revoke")),
		jwks_uri: format!("{base}/_continuwuity/oidc/jwks"),
		userinfo_endpoint: Some(format!("{base}/_continuwuity/oidc/userinfo")),
		account_management_uri: Some(format!("{base}/_continuwuity/oidc/account")),
		account_management_actions_supported: Some(vec![
			"org.matrix.profile".to_owned(),
			"org.matrix.sessions_list".to_owned(),
			"org.matrix.session_view".to_owned(),
			"org.matrix.session_end".to_owned(),
			"org.matrix.cross_signing_reset".to_owned(),
		]),
		response_types_supported: vec!["code".to_owned()],
		response_modes_supported: Some(vec!["query".to_owned(), "fragment".to_owned()]),
		grant_types_supported: Some(vec![
			"authorization_code".to_owned(),
			"refresh_token".to_owned(),
		]),
		code_challenge_methods_supported: Some(vec!["S256".to_owned()]),
		token_endpoint_auth_methods_supported: Some(vec!["none".to_owned()]),
		scopes_supported: Some(vec![
			"openid".to_owned(),
			"urn:matrix:org.matrix.msc2967.client:api:*".to_owned(),
			"urn:matrix:org.matrix.msc2967.client:device:*".to_owned(),
		]),
		subject_types_supported: Some(vec!["public".to_owned()]),
		id_token_signing_alg_values_supported: Some(vec!["ES256".to_owned()]),
		prompt_values_supported: Some(vec!["create".to_owned()]),
		claim_types_supported: Some(vec!["normal".to_owned()]),
		claims_supported: Some(vec![
			"iss".to_owned(),
			"sub".to_owned(),
			"aud".to_owned(),
			"exp".to_owned(),
			"iat".to_owned(),
			"nonce".to_owned(),
		]),
	})
}

pub(crate) async fn registration_route(
	State(services): State<crate::State>,
	Json(body): Json<DcrRequest>,
) -> Result<impl IntoResponse> {
	let oidc = get_oidc_server(&services)?;
	if body.redirect_uris.is_empty() {
		return Err!(Request(InvalidParam("redirect_uris must not be empty")));
	}

	let reg = oidc.register_client(body)?;
	info!(
		"OIDC client registered: {} ({})",
		reg.client_id,
		reg.client_name.as_deref().unwrap_or("unnamed")
	);

	Ok((
		StatusCode::CREATED,
		Json(serde_json::json!({
			"client_id": reg.client_id,
			"client_id_issued_at": reg.registered_at,
			"redirect_uris": reg.redirect_uris,
			"client_name": reg.client_name,
			"client_uri": reg.client_uri,
			"logo_uri": reg.logo_uri,
			"contacts": reg.contacts,
			"token_endpoint_auth_method": reg.token_endpoint_auth_method,
			"grant_types": reg.grant_types,
			"response_types": reg.response_types,
			"application_type": reg.application_type,
		})),
	))
}

#[derive(Debug, Deserialize)]
pub(crate) struct AuthorizeParams {
	client_id: String,
	redirect_uri: String,
	response_type: String,
	scope: String,
	state: Option<String>,
	nonce: Option<String>,
	code_challenge: Option<String>,
	code_challenge_method: Option<String>,
}

pub(crate) async fn authorize_route(
	State(services): State<crate::State>,
	headers: http::HeaderMap,
	request: axum::extract::Request,
) -> Result<impl IntoResponse> {
	let params: AuthorizeParams =
		serde_html_form::from_str(request.uri().query().unwrap_or_default())
			.map_err(|e| err!(Request(InvalidParam("Invalid query parameters: {e}"))))?;

	let oidc = get_oidc_server(&services)?;

	if params.response_type != "code" {
		return Err!(Request(InvalidParam("Only response_type=code is supported")));
	}

	oidc.validate_redirect_uri(&params.client_id, &params.redirect_uri)
		.await?;

	if !has_supported_authorization_scope(&params.scope) {
		return Err!(Request(InvalidParam("openid or a Matrix scope is required")));
	}

	let req_id = utils::random_string(OIDC_REQ_ID_LENGTH);
	let now = SystemTime::now();

	oidc.store_auth_request(
		&req_id,
		&OidcAuthRequest {
			client_id: params.client_id,
			redirect_uri: params.redirect_uri,
			scope: params.scope,
			state: params.state,
			nonce: params.nonce,
			code_challenge: params.code_challenge,
			code_challenge_method: params.code_challenge_method,
			created_at: now,
			expires_at: now
				.checked_add(OidcServer::auth_request_lifetime())
				.unwrap_or(now),
		},
	);

	let default_idp = services
		.server
		.config
		.identity_provider
		.iter()
		.find(|(_, idp)| idp.default)
		.or_else(|| services.server.config.identity_provider.iter().next())
		.ok_or_else(|| err!(Config("identity_provider", "No identity provider configured")))?;

	let idp_id = default_idp.0;
	let base = oidc_issuer_url(&services, &headers)?;
	let base = base.trim_end_matches('/');

	let mut complete_url = Url::parse(&format!("{base}/_continuwuity/oidc/_complete"))
		.map_err(|e| err!(error!("Failed to build complete URL: {e}")))?;
	complete_url
		.query_pairs_mut()
		.append_pair("oidc_req_id", &req_id);

	let mut sso_url =
		Url::parse(&format!("{base}/_matrix/client/v3/login/sso/redirect/{idp_id}"))
			.map_err(|e| err!(error!("Failed to build SSO URL: {e}")))?;
	sso_url
		.query_pairs_mut()
		.append_pair("redirectUrl", complete_url.as_str());

	Ok(Redirect::temporary(sso_url.as_str()))
}

#[derive(Debug, Deserialize)]
pub(crate) struct CompleteParams {
	oidc_req_id: String,
	#[serde(rename = "loginToken")]
	login_token: String,
}

pub(crate) async fn complete_route(
	State(services): State<crate::State>,
	Query(params): Query<CompleteParams>,
) -> Result<impl IntoResponse> {
	let oidc = get_oidc_server(&services)?;

	let user_id = services
		.users
		.find_from_login_token(&params.login_token)
		.await
		.map_err(|_| err!(Request(Forbidden("Invalid or expired login token"))))?;

	let auth_req = oidc.take_auth_request(&params.oidc_req_id).await?;
	let code = oidc.create_auth_code(&auth_req, user_id);

	let mut redirect_url = Url::parse(&auth_req.redirect_uri)
		.map_err(|e| err!(Request(InvalidParam("Invalid redirect_uri: {e}"))))?;
	redirect_url.query_pairs_mut().append_pair("code", &code);
	if let Some(state) = &auth_req.state {
		redirect_url.query_pairs_mut().append_pair("state", state);
	}

	Ok(Redirect::temporary(redirect_url.as_str()))
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // refresh_token used when token refresh is implemented
pub(crate) struct TokenRequest {
	grant_type: String,
	code: Option<String>,
	redirect_uri: Option<String>,
	client_id: Option<String>,
	code_verifier: Option<String>,
	refresh_token: Option<String>,
}

pub(crate) async fn token_route(
	State(services): State<crate::State>,
	headers: http::HeaderMap,
	Form(body): Form<TokenRequest>,
) -> impl IntoResponse {
	match body.grant_type.as_str() {
		| "authorization_code" => token_authorization_code(&services, &headers, &body)
			.await
			.unwrap_or_else(|e| {
				oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", &e.to_string())
			}),
		| "refresh_token" => token_refresh(&services, &headers, &body)
			.await
			.unwrap_or_else(|e| {
				oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", &e.to_string())
			}),
		| _ => oauth_error(
			StatusCode::BAD_REQUEST,
			"unsupported_grant_type",
			"Unsupported grant_type",
		),
	}
}

async fn token_authorization_code(
	services: &conduwuit_service::Services,
	headers: &http::HeaderMap,
	body: &TokenRequest,
) -> Result<axum::response::Response> {
	let code = body
		.code
		.as_deref()
		.ok_or_else(|| err!(Request(InvalidParam("code is required"))))?;
	let redirect_uri = body
		.redirect_uri
		.as_deref()
		.ok_or_else(|| err!(Request(InvalidParam("redirect_uri is required"))))?;
	let client_id = body
		.client_id
		.as_deref()
		.ok_or_else(|| err!(Request(InvalidParam("client_id is required"))))?;

	let oidc = get_oidc_server(services)?;
	let session = oidc
		.exchange_auth_code(code, client_id, redirect_uri, body.code_verifier.as_deref())
		.await?;

	let user_id = &session.user_id;
	let access_token = services.users.generate_unique_token().await;
	let device_id: OwnedDeviceId = extract_device_id(&session.scope)
		.map(OwnedDeviceId::from)
		.unwrap_or_else(|| utils::random_string(10).into());

	services
		.users
		.create_device(user_id, &device_id, &access_token, Some("OIDC Client".to_owned()), None)
		.await?;

	info!("{user_id} logged in via OIDC (device {device_id})");

	let response = build_token_response(
		services,
		headers,
		oidc,
		client_id,
		&session.scope,
		user_id,
		&device_id,
		&access_token,
		session.nonce,
	)
	.await?;

	Ok(Json(response).into_response())
}

async fn token_refresh(
	services: &conduwuit_service::Services,
	headers: &http::HeaderMap,
	body: &TokenRequest,
) -> Result<axum::response::Response> {
	let refresh_token = body
		.refresh_token
		.as_deref()
		.ok_or_else(|| err!(Request(InvalidParam("refresh_token is required"))))?;
	let client_id = body
		.client_id
		.as_deref()
		.ok_or_else(|| err!(Request(InvalidParam("client_id is required"))))?;

	let oidc = get_oidc_server(services)?;
	let session = oidc
		.exchange_refresh_token(refresh_token, client_id)
		.await?;

	let access_token = services.users.generate_unique_token().await;
	services
		.users
		.set_token(&session.user_id, &session.device_id, &access_token)
		.await?;

	let response = build_token_response(
		services,
		headers,
		oidc,
		client_id,
		&session.scope,
		&session.user_id,
		&session.device_id,
		&access_token,
		None,
	)
	.await?;

	Ok(Json(response).into_response())
}

#[derive(Debug, Deserialize)]
pub(crate) struct RevokeRequest {
	token: String,
}

pub(crate) async fn revoke_route(
	State(services): State<crate::State>,
	Form(body): Form<RevokeRequest>,
) -> Result<impl IntoResponse> {
	if let Ok((user_id, device_id)) = services.users.find_from_token(&body.token).await {
		if let Ok(oidc) = get_oidc_server(&services) {
			oidc.revoke_refresh_token_for_device(&user_id, &device_id)
				.await
				.ok();
		}
		services.users.remove_device(&user_id, &device_id).await;
	}
	if let Ok(oidc) = get_oidc_server(&services)
		&& let Ok(session) = oidc.revoke_refresh_token(&body.token).await
	{
		services
			.users
			.remove_device(&session.user_id, &session.device_id)
			.await;
	}
	Ok(Json(serde_json::json!({})))
}

pub(crate) async fn jwks_route(
	State(services): State<crate::State>,
) -> Result<impl IntoResponse> {
	let oidc = get_oidc_server(&services)?;
	Ok(Json(oidc.jwks()))
}

pub(crate) async fn userinfo_route(
	State(services): State<crate::State>,
	TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse> {
	let token = bearer.token();
	let (user_id, _device_id) = services
		.users
		.find_from_token(token)
		.await
		.map_err(|_| err!(Request(Unauthorized("Invalid access token"))))?;
	let displayname = services.users.displayname(&user_id).await.ok();
	let avatar_url = services.users.avatar_url(&user_id).await.ok();
	Ok(Json(serde_json::json!({
		"sub": user_id.to_string(),
		"name": displayname,
		"picture": avatar_url,
	})))
}

pub(crate) async fn account_route() -> impl IntoResponse {
	Html(
		"<html><body><h1>Account Management</h1>\
		 <p>Not yet implemented. Use your identity provider.</p></body></html>",
	)
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> axum::response::Response {
	(
		status,
		Json(serde_json::json!({"error": error, "error_description": description})),
	)
		.into_response()
}

fn get_oidc_server(services: &conduwuit_service::Services) -> Result<&OidcServer> {
	services
		.oauth
		.oidc_server
		.as_deref()
		.ok_or_else(|| err!(Request(NotFound("OIDC server not configured"))))
}

fn oidc_issuer_url(
	services: &conduwuit_service::Services,
	headers: &http::HeaderMap,
) -> Result<String> {
	request_base_url(services, headers)
		.or_else(|| {
			services
				.server
				.config
				.well_known
				.client
				.as_ref()
				.map(|url| {
					let s = url.to_string();
					if s.ends_with('/') { s } else { s + "/" }
				})
		})
		.ok_or_else(|| err!(Config("well_known.client", "Must be set for OIDC server")))
}

fn request_base_url(
	services: &conduwuit_service::Services,
	headers: &http::HeaderMap,
) -> Option<String> {
	let fallback_scheme = services
		.server
		.config
		.well_known
		.client
		.as_ref()
		.map(|url| url.scheme())
		.unwrap_or("https");

	request_base_url_from_headers(headers, fallback_scheme)
}

fn request_base_url_from_headers(
	headers: &http::HeaderMap,
	fallback_scheme: &str,
) -> Option<String> {
	let host = headers
		.get("x-forwarded-host")
		.or_else(|| headers.get(http::header::HOST))
		.and_then(|v| v.to_str().ok())
		.map(str::trim)
		.filter(|v| !v.is_empty())?;

	let scheme = headers
		.get("x-forwarded-proto")
		.and_then(|v| v.to_str().ok())
		.map(str::trim)
		.filter(|v| !v.is_empty())
		.unwrap_or(fallback_scheme);

	Some(format!("{scheme}://{host}/"))
}

fn has_supported_authorization_scope(scope: &str) -> bool {
	scope
		.split_whitespace()
		.any(|scope| scope == "openid" || scope.starts_with("urn:matrix:"))
}

#[cfg(test)]
mod tests {
	use super::{has_supported_authorization_scope, request_base_url_from_headers};

	#[test]
	fn request_base_url_prefers_forwarded_headers() {
		let mut headers = http::HeaderMap::new();
		headers.insert("x-forwarded-host", "mx.example.com".parse().unwrap());
		headers.insert("x-forwarded-proto", "https".parse().unwrap());

		assert_eq!(
			request_base_url_from_headers(&headers, "https").as_deref(),
			Some("https://mx.example.com/")
		);
	}

	#[test]
	fn request_base_url_falls_back_to_host_and_configured_scheme() {
		let mut headers = http::HeaderMap::new();
		headers.insert(http::header::HOST, "mx.example.com".parse().unwrap());

		assert_eq!(
			request_base_url_from_headers(&headers, "https").as_deref(),
			Some("https://mx.example.com/")
		);
	}

	#[test]
	fn supported_authorization_scope_accepts_matrix_scopes_without_openid() {
		assert!(has_supported_authorization_scope(
			"urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:ABC123"
		));
	}

	#[test]
	fn supported_authorization_scope_rejects_non_matrix_non_openid_scopes() {
		assert!(!has_supported_authorization_scope("profile email"));
	}
}

fn extract_device_id(scope: &str) -> Option<String> {
	scope
		.split_whitespace()
		.find_map(|s| s.strip_prefix("urn:matrix:org.matrix.msc2967.client:device:"))
		.map(ToOwned::to_owned)
}

async fn build_token_response(
	services: &conduwuit_service::Services,
	headers: &http::HeaderMap,
	oidc: &OidcServer,
	client_id: &str,
	scope: &str,
	user_id: &ruma::UserId,
	device_id: &ruma::DeviceId,
	access_token: &str,
	nonce: Option<String>,
) -> Result<serde_json::Value> {
	let refresh_token = oidc
		.create_refresh_token(client_id, scope, user_id.to_owned(), device_id.to_owned())
		.await;

	let mut response = serde_json::json!({
		"access_token": access_token,
		"refresh_token": refresh_token,
		"token_type": "Bearer",
		"scope": scope,
	});

	if scope.contains("openid") {
		let now = SystemTime::now()
			.duration_since(SystemTime::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		let issuer = oidc_issuer_url(services, headers)?;
		let claims = IdTokenClaims {
			iss: issuer,
			sub: user_id.to_string(),
			aud: client_id.to_owned(),
			exp: now.saturating_add(3600),
			iat: now,
			nonce,
			at_hash: Some(OidcServer::at_hash(access_token)),
		};
		response["id_token"] = serde_json::json!(oidc.sign_id_token(&claims)?);
	}

	Ok(response)
}
