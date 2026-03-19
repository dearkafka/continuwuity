use std::{
	sync::Arc,
	time::{Duration, SystemTime},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as b64};
use conduwuit::{Err, Result, err, info, utils};
use database::{Cbor, Deserialized, Map};
use jsonwebtoken as jwt;
use ring::{
	rand::SystemRandom,
	signature::{self, EcdsaKeyPair, KeyPair},
};
use ruma::{DeviceId, OwnedDeviceId, OwnedUserId, UserId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const AUTH_CODE_LENGTH: usize = 64;
const OIDC_CLIENT_ID_LENGTH: usize = 32;
const AUTH_CODE_LIFETIME: Duration = Duration::from_secs(600);
const AUTH_REQUEST_LIFETIME: Duration = Duration::from_secs(600);
const REFRESH_TOKEN_LENGTH: usize = 64;
const REFRESH_TOKEN_LIFETIME: Duration = Duration::from_secs(60 * 60 * 24 * 30);
const REFRESH_TOKEN_PREFIX: &str = "refresh_";
const SIGNING_KEY_DB_KEY: &str = "oidc_signing_key";

pub struct OidcServer {
	db: Data,
	signing_key_der: Vec<u8>,
	jwk: serde_json::Value,
	key_id: String,
}

struct Data {
	oidc_signingkey: Arc<Map>,
	oidcclientid_registration: Arc<Map>,
	oidccode_authsession: Arc<Map>,
	oidcreqid_authrequest: Arc<Map>,
	oidcrefresh_session: Arc<Map>,
	oidcuserdevice_refresh: Arc<Map>,
}

#[derive(Debug, Deserialize)]
pub struct DcrRequest {
	pub redirect_uris: Vec<String>,
	pub client_name: Option<String>,
	pub client_uri: Option<String>,
	pub logo_uri: Option<String>,
	#[serde(default)]
	pub contacts: Vec<String>,
	pub token_endpoint_auth_method: Option<String>,
	pub grant_types: Option<Vec<String>>,
	pub response_types: Option<Vec<String>>,
	pub application_type: Option<String>,
	pub policy_uri: Option<String>,
	pub tos_uri: Option<String>,
	pub software_id: Option<String>,
	pub software_version: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcClientRegistration {
	pub client_id: String,
	pub redirect_uris: Vec<String>,
	pub client_name: Option<String>,
	pub client_uri: Option<String>,
	pub logo_uri: Option<String>,
	pub contacts: Vec<String>,
	pub token_endpoint_auth_method: String,
	pub grant_types: Vec<String>,
	pub response_types: Vec<String>,
	pub application_type: Option<String>,
	pub policy_uri: Option<String>,
	pub tos_uri: Option<String>,
	pub software_id: Option<String>,
	pub software_version: Option<String>,
	pub registered_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthCodeSession {
	pub code: String,
	pub client_id: String,
	pub redirect_uri: String,
	pub scope: String,
	pub state: Option<String>,
	pub nonce: Option<String>,
	pub code_challenge: Option<String>,
	pub code_challenge_method: Option<String>,
	pub user_id: OwnedUserId,
	pub created_at: SystemTime,
	pub expires_at: SystemTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcAuthRequest {
	pub client_id: String,
	pub redirect_uri: String,
	pub scope: String,
	pub state: Option<String>,
	pub nonce: Option<String>,
	pub code_challenge: Option<String>,
	pub code_challenge_method: Option<String>,
	pub created_at: SystemTime,
	pub expires_at: SystemTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefreshTokenSession {
	pub refresh_token: String,
	pub client_id: String,
	pub scope: String,
	pub user_id: OwnedUserId,
	pub device_id: OwnedDeviceId,
	pub created_at: SystemTime,
	pub expires_at: SystemTime,
}

#[derive(Serialize, Deserialize)]
struct SigningKeyData {
	key_der: Vec<u8>,
	key_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProviderMetadata {
	pub issuer: String,
	pub authorization_endpoint: String,
	pub token_endpoint: String,
	pub registration_endpoint: Option<String>,
	pub revocation_endpoint: Option<String>,
	pub jwks_uri: String,
	pub userinfo_endpoint: Option<String>,
	pub account_management_uri: Option<String>,
	pub account_management_actions_supported: Option<Vec<String>>,
	pub response_types_supported: Vec<String>,
	pub response_modes_supported: Option<Vec<String>>,
	pub grant_types_supported: Option<Vec<String>>,
	pub code_challenge_methods_supported: Option<Vec<String>>,
	pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
	pub scopes_supported: Option<Vec<String>>,
	pub subject_types_supported: Option<Vec<String>>,
	pub id_token_signing_alg_values_supported: Option<Vec<String>>,
	pub prompt_values_supported: Option<Vec<String>>,
	pub claim_types_supported: Option<Vec<String>>,
	pub claims_supported: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
	pub iss: String,
	pub sub: String,
	pub aud: String,
	pub exp: u64,
	pub iat: u64,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub nonce: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub at_hash: Option<String>,
}

impl OidcServer {
	pub(crate) fn build(args: &crate::Args<'_>) -> Result<Self> {
		let db = Data {
			oidc_signingkey: args.db["oidc_signingkey"].clone(),
			oidcclientid_registration: args.db["oidcclientid_registration"].clone(),
			oidccode_authsession: args.db["oidccode_authsession"].clone(),
			oidcreqid_authrequest: args.db["oidcreqid_authrequest"].clone(),
			oidcrefresh_session: args.db["oidcrefresh_session"].clone(),
			oidcuserdevice_refresh: args.db["oidcuserdevice_refresh"].clone(),
		};

		let (signing_key_der, key_id) = match db
			.oidc_signingkey
			.get_blocking(SIGNING_KEY_DB_KEY)
			.and_then(|handle| {
				handle
					.deserialized::<Cbor<SigningKeyData>>()
					.map(|cbor| cbor.0)
			}) {
			| Ok(data) => {
				info!("Loaded existing OIDC signing key (kid={})", data.key_id);
				(data.key_der, data.key_id)
			},
			| Err(_) => {
				let (key_der, key_id) = Self::generate_signing_key()?;
				info!("Generated new OIDC signing key (kid={key_id})");
				let data = SigningKeyData {
					key_der: key_der.clone(),
					key_id: key_id.clone(),
				};
				db.oidc_signingkey.raw_put(SIGNING_KEY_DB_KEY, Cbor(&data));
				(key_der, key_id)
			},
		};

		let jwk = Self::build_jwk(&signing_key_der, &key_id)?;
		Ok(Self { db, signing_key_der, jwk, key_id })
	}

	fn generate_signing_key() -> Result<(Vec<u8>, String)> {
		let rng = SystemRandom::new();
		let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
		let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng)
			.map_err(|e| err!(error!("Failed to generate ECDSA key: {e}")))?;
		let key_id = utils::random_string(16);
		Ok((pkcs8.as_ref().to_vec(), key_id))
	}

	fn build_jwk(signing_key_der: &[u8], key_id: &str) -> Result<serde_json::Value> {
		let rng = SystemRandom::new();
		let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
		let key_pair = EcdsaKeyPair::from_pkcs8(alg, signing_key_der, &rng)
			.map_err(|e| err!(error!("Failed to load ECDSA key: {e}")))?;
		let public_bytes = key_pair.public_key().as_ref();
		let x = b64.encode(&public_bytes[1..33]);
		let y = b64.encode(&public_bytes[33..65]);
		Ok(serde_json::json!({
			"kty": "EC", "crv": "P-256", "use": "sig",
			"alg": "ES256", "kid": key_id, "x": x, "y": y
		}))
	}

	pub fn register_client(&self, request: DcrRequest) -> Result<OidcClientRegistration> {
		let client_id = utils::random_string(OIDC_CLIENT_ID_LENGTH);
		let (auth_method, grant_types, response_types) =
			normalize_registration_metadata(&request)?;

		let registration = OidcClientRegistration {
			client_id: client_id.clone(),
			redirect_uris: request.redirect_uris,
			client_name: request.client_name,
			client_uri: request.client_uri,
			logo_uri: request.logo_uri,
			contacts: request.contacts,
			token_endpoint_auth_method: auth_method,
			grant_types,
			response_types,
			application_type: request.application_type,
			policy_uri: request.policy_uri,
			tos_uri: request.tos_uri,
			software_id: request.software_id,
			software_version: request.software_version,
			registered_at: SystemTime::now()
				.duration_since(SystemTime::UNIX_EPOCH)
				.unwrap_or_default()
				.as_secs(),
		};
		self.db
			.oidcclientid_registration
			.raw_put(&*client_id, Cbor(&registration));
		Ok(registration)
	}

	pub async fn get_client(&self, client_id: &str) -> Result<OidcClientRegistration> {
		self.db
			.oidcclientid_registration
			.get(client_id)
			.await
			.deserialized::<Cbor<OidcClientRegistration>>()
			.map(|cbor| cbor.0)
			.map_err(|_| err!(Request(NotFound("Unknown client_id"))))
	}

	pub async fn validate_redirect_uri(&self, client_id: &str, redirect_uri: &str) -> Result {
		let client = self.get_client(client_id).await?;
		if client.redirect_uris.iter().any(|uri| uri == redirect_uri) {
			Ok(())
		} else {
			Err!(Request(InvalidParam("redirect_uri not registered for this client")))
		}
	}

	pub fn store_auth_request(&self, req_id: &str, request: &OidcAuthRequest) {
		self.db.oidcreqid_authrequest.raw_put(req_id, Cbor(request));
	}

	pub async fn take_auth_request(&self, req_id: &str) -> Result<OidcAuthRequest> {
		let request: OidcAuthRequest = self
			.db
			.oidcreqid_authrequest
			.get(req_id)
			.await
			.deserialized::<Cbor<OidcAuthRequest>>()
			.map(|cbor| cbor.0)
			.map_err(|_| err!(Request(NotFound("Unknown or expired authorization request"))))?;
		self.db.oidcreqid_authrequest.remove(req_id);
		if SystemTime::now() > request.expires_at {
			return Err!(Request(NotFound("Authorization request has expired")));
		}
		Ok(request)
	}

	#[must_use]
	pub fn create_auth_code(&self, auth_req: &OidcAuthRequest, user_id: OwnedUserId) -> String {
		let code = utils::random_string(AUTH_CODE_LENGTH);
		let now = SystemTime::now();
		let session = AuthCodeSession {
			code: code.clone(),
			client_id: auth_req.client_id.clone(),
			redirect_uri: auth_req.redirect_uri.clone(),
			scope: auth_req.scope.clone(),
			state: auth_req.state.clone(),
			nonce: auth_req.nonce.clone(),
			code_challenge: auth_req.code_challenge.clone(),
			code_challenge_method: auth_req.code_challenge_method.clone(),
			user_id,
			created_at: now,
			expires_at: now.checked_add(AUTH_CODE_LIFETIME).unwrap_or(now),
		};
		self.db.oidccode_authsession.raw_put(&*code, Cbor(&session));
		code
	}

	pub async fn exchange_auth_code(
		&self,
		code: &str,
		client_id: &str,
		redirect_uri: &str,
		code_verifier: Option<&str>,
	) -> Result<AuthCodeSession> {
		let session: AuthCodeSession = self
			.db
			.oidccode_authsession
			.get(code)
			.await
			.deserialized::<Cbor<AuthCodeSession>>()
			.map(|cbor| cbor.0)
			.map_err(|_| err!(Request(Forbidden("Invalid or expired authorization code"))))?;

		self.db.oidccode_authsession.remove(code);

		if SystemTime::now() > session.expires_at {
			return Err!(Request(Forbidden("Authorization code has expired")));
		}
		if session.client_id != client_id {
			return Err!(Request(Forbidden("client_id mismatch")));
		}
		if session.redirect_uri != redirect_uri {
			return Err!(Request(Forbidden("redirect_uri mismatch")));
		}

		if let Some(challenge) = &session.code_challenge {
			let Some(verifier) = code_verifier else {
				return Err!(Request(Forbidden("code_verifier required for PKCE")));
			};
			Self::validate_code_verifier(verifier)?;
			let method = session.code_challenge_method.as_deref().unwrap_or("S256");
			let computed = match method {
				| "S256" => {
					let hash = Sha256::digest(verifier.as_bytes());
					b64.encode(hash)
				},
				| "plain" => verifier.to_owned(),
				| _ => return Err!(Request(InvalidParam("Unsupported code_challenge_method"))),
			};
			if computed != *challenge {
				return Err!(Request(Forbidden("PKCE verification failed")));
			}
		}

		Ok(session)
	}

	#[must_use]
	pub async fn create_refresh_token(
		&self,
		client_id: &str,
		scope: &str,
		user_id: OwnedUserId,
		device_id: OwnedDeviceId,
	) -> String {
		self.revoke_refresh_token_for_device(&user_id, &device_id)
			.await
			.ok();

		let refresh_token = generate_refresh_token();
		let now = SystemTime::now();
		self.db
			.oidcuserdevice_refresh
			.put_raw((&user_id, &device_id), &refresh_token);
		let session = RefreshTokenSession {
			refresh_token: refresh_token.clone(),
			client_id: client_id.to_owned(),
			scope: scope.to_owned(),
			user_id,
			device_id,
			created_at: now,
			expires_at: now.checked_add(REFRESH_TOKEN_LIFETIME).unwrap_or(now),
		};
		self.db
			.oidcrefresh_session
			.raw_put(&*refresh_token, Cbor(&session));
		refresh_token
	}

	pub async fn exchange_refresh_token(
		&self,
		refresh_token: &str,
		client_id: &str,
	) -> Result<RefreshTokenSession> {
		let session: RefreshTokenSession = self
			.db
			.oidcrefresh_session
			.get(refresh_token)
			.await
			.deserialized::<Cbor<RefreshTokenSession>>()
			.map(|cbor| cbor.0)
			.map_err(|_| err!(Request(Forbidden("Invalid or expired refresh token"))))?;

		if SystemTime::now() > session.expires_at {
			self.revoke_refresh_token(refresh_token).await.ok();
			return Err!(Request(Forbidden("Refresh token has expired")));
		}
		if session.client_id != client_id {
			return Err!(Request(Forbidden("client_id mismatch")));
		}

		self.revoke_refresh_token(refresh_token).await.ok();

		Ok(session)
	}

	pub async fn revoke_refresh_token(&self, refresh_token: &str) -> Result<RefreshTokenSession> {
		let session: RefreshTokenSession = self
			.db
			.oidcrefresh_session
			.get(refresh_token)
			.await
			.deserialized::<Cbor<RefreshTokenSession>>()
			.map(|cbor| cbor.0)
			.map_err(|_| err!(Request(NotFound("Unknown refresh token"))))?;

		let userdevice = (&session.user_id, &session.device_id);
		self.db.oidcuserdevice_refresh.del(userdevice);
		self.db.oidcrefresh_session.remove(refresh_token);
		Ok(session)
	}

	pub async fn revoke_refresh_token_for_device(
		&self,
		user_id: &UserId,
		device_id: &DeviceId,
	) -> Result {
		let refresh_token = self
			.db
			.oidcuserdevice_refresh
			.qry(&(user_id, device_id))
			.await?
			.deserialized::<String>()?;

		self.revoke_refresh_token(&refresh_token).await.map(|_| ())
	}

	/// Validate code_verifier per RFC 7636 Section 4.1: 43-128 chars,
	/// unreserved characters only.
	fn validate_code_verifier(verifier: &str) -> Result {
		if !(43..=128).contains(&verifier.len()) {
			return Err!(Request(InvalidParam("code_verifier must be 43-128 characters")));
		}
		if !verifier.bytes().all(|b| {
			b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~'
		}) {
			return Err!(Request(InvalidParam("code_verifier contains invalid characters")));
		}
		Ok(())
	}

	pub fn sign_id_token(&self, claims: &IdTokenClaims) -> Result<String> {
		let mut header = jwt::Header::new(jwt::Algorithm::ES256);
		header.kid = Some(self.key_id.clone());
		let key = jwt::EncodingKey::from_ec_der(&self.signing_key_der);
		jwt::encode(&header, claims, &key)
			.map_err(|e| err!(error!("Failed to sign ID token: {e}")))
	}

	#[must_use]
	pub fn jwks(&self) -> serde_json::Value {
		serde_json::json!({"keys": [self.jwk.clone()]})
	}

	#[must_use]
	pub fn at_hash(access_token: &str) -> String {
		let hash = Sha256::digest(access_token.as_bytes());
		b64.encode(&hash[..16])
	}

	#[must_use]
	pub fn auth_request_lifetime() -> Duration {
		AUTH_REQUEST_LIFETIME
	}
}

fn generate_refresh_token() -> String {
	format!("{REFRESH_TOKEN_PREFIX}{}", utils::random_string(REFRESH_TOKEN_LENGTH))
}

fn normalize_registration_metadata(
	request: &DcrRequest,
) -> Result<(String, Vec<String>, Vec<String>)> {
	let auth_method = request
		.token_endpoint_auth_method
		.clone()
		.unwrap_or_else(|| "none".to_owned());
	if auth_method != "none" {
		return Err!(Request(InvalidParam("Only token_endpoint_auth_method=none is supported")));
	}

	let grant_types = request
		.grant_types
		.clone()
		.unwrap_or_else(|| vec!["authorization_code".to_owned(), "refresh_token".to_owned()]);
	if !grant_types
		.iter()
		.any(|grant_type| grant_type == "authorization_code")
		|| grant_types
			.iter()
			.any(|grant_type| grant_type != "authorization_code" && grant_type != "refresh_token")
	{
		return Err!(Request(InvalidParam(
			"Only authorization_code and refresh_token grant types are supported"
		)));
	}

	let response_types = request
		.response_types
		.clone()
		.unwrap_or_else(|| vec!["code".to_owned()]);
	if response_types.len() != 1 || response_types[0] != "code" {
		return Err!(Request(InvalidParam("Only response_type=code is supported")));
	}

	Ok((auth_method, grant_types, response_types))
}

#[cfg(test)]
mod tests {
	use super::{DcrRequest, generate_refresh_token, normalize_registration_metadata};

	fn request() -> DcrRequest {
		DcrRequest {
			redirect_uris: vec!["https://example.com/callback".to_owned()],
			client_name: None,
			client_uri: None,
			logo_uri: None,
			contacts: Vec::new(),
			token_endpoint_auth_method: None,
			grant_types: None,
			response_types: None,
			application_type: None,
			policy_uri: None,
			tos_uri: None,
			software_id: None,
			software_version: None,
		}
	}

	#[test]
	fn registration_defaults_match_supported_metadata() {
		let (auth_method, grant_types, response_types) =
			normalize_registration_metadata(&request()).expect("defaults should be accepted");

		assert_eq!(auth_method, "none");
		assert_eq!(grant_types, vec!["authorization_code", "refresh_token"]);
		assert_eq!(response_types, vec!["code"]);
	}

	#[test]
	fn registration_rejects_confidential_client_auth() {
		let mut request = request();
		request.token_endpoint_auth_method = Some("client_secret_post".to_owned());

		assert!(normalize_registration_metadata(&request).is_err());
	}

	#[test]
	fn registration_rejects_unsupported_grant_types() {
		let mut request = request();
		request.grant_types = Some(vec!["authorization_code".to_owned(), "password".to_owned()]);

		assert!(normalize_registration_metadata(&request).is_err());
	}

	#[test]
	fn refresh_tokens_have_expected_prefix() {
		let refresh_token = generate_refresh_token();

		assert!(refresh_token.starts_with("refresh_"));
		assert!(refresh_token.len() > "refresh_".len());
	}
}
