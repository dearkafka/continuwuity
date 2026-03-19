use std::{sync::Arc, time::SystemTime};

use conduwuit::Result;
use database::{Cbor, Deserialized, Map};
use futures::StreamExt;
use ruma::{OwnedUserId, UserId};
use serde::{Deserialize, Serialize};
use url::Url;

use super::UserInfo;

/// Number of characters generated for the code_verifier. The code_verifier is a
/// random string which must be between 43 and 128 characters.
pub const CODE_VERIFIER_LENGTH: usize = 64;

/// Number of characters generated for the Session ID.
pub const SESSION_ID_LENGTH: usize = 32;

/// Session represents an OAuth authorization session yielding an associated
/// Matrix user registration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Session {
	/// Identity Provider ID associated with this session.
	pub idp_id: Option<String>,

	/// Session ID used as the index key.
	pub sess_id: Option<String>,

	/// Token type (bearer, mac, etc).
	pub token_type: Option<String>,

	/// Access token from the provider.
	pub access_token: Option<String>,

	/// Duration in seconds the access_token is valid for.
	pub expires_in: Option<u64>,

	/// Point in time that the access_token expires.
	pub expires_at: Option<SystemTime>,

	/// Token used to refresh the access_token.
	pub refresh_token: Option<String>,

	/// Duration in seconds the refresh_token is valid for.
	pub refresh_token_expires_in: Option<u64>,

	/// Point in time that the refresh_token expires.
	pub refresh_token_expires_at: Option<SystemTime>,

	/// Access scope actually granted.
	pub scope: Option<String>,

	/// Client redirect URL to return to after auth.
	pub redirect_url: Option<Url>,

	/// PKCE challenge preimage.
	pub code_verifier: Option<String>,

	/// Random string passed in the grant session cookie.
	pub cookie_nonce: Option<String>,

	/// Random single-use string passed in the provider redirect.
	pub query_nonce: Option<String>,

	/// Point in time the authorization grant session expires.
	pub authorize_expires_at: Option<SystemTime>,

	/// Associated Matrix User Id.
	pub user_id: Option<OwnedUserId>,

	/// Last userinfo response.
	pub user_info: Option<UserInfo>,
}

pub struct Sessions {
	db: Data,
}

struct Data {
	oauthid_session: Arc<Map>,
	oauthuniqid_oauthid: Arc<Map>,
	userid_oauthid: Arc<Map>,
	email_userid: Arc<Map>,
	userid_email: Arc<Map>,
}

impl Sessions {
	pub(super) fn new(db: &Arc<database::Database>) -> Self {
		Self {
			db: Data {
				oauthid_session: db["oauthid_session"].clone(),
				oauthuniqid_oauthid: db["oauthuniqid_oauthid"].clone(),
				userid_oauthid: db["userid_oauthid"].clone(),
				email_userid: db["email_userid"].clone(),
				userid_email: db["userid_email"].clone(),
			},
		}
	}

	/// Store or update a session.
	pub fn put(&self, session: &Session, unique_id: Option<&str>) {
		let sess_id = session
			.sess_id
			.as_deref()
			.expect("Missing sess_id in session");

		self.db.oauthid_session.raw_put(sess_id, Cbor(session));

		if let Some(unique_id) = unique_id {
			self.db.oauthuniqid_oauthid.insert(unique_id, sess_id);
		}

		if let Some(user_id) = session.user_id.as_deref() {
			self.db.userid_oauthid.raw_put(user_id, sess_id);
		}
	}

	/// Fetch a session by its sess_id.
	pub async fn get(&self, sess_id: &str) -> Result<Session> {
		self.db
			.oauthid_session
			.get(sess_id)
			.await
			.deserialized::<Cbor<Session>>()
			.map(|cbor| cbor.0)
	}

	/// Fetch a session by its unique identity hash (issuer+sub).
	pub async fn get_by_unique_id(&self, unique_id: &str) -> Result<Session> {
		let sess_id: String = self
			.db
			.oauthuniqid_oauthid
			.get(unique_id)
			.await
			.deserialized()?;

		self.get(&sess_id).await
	}

	/// Delete a session.
	pub fn delete(&self, sess_id: &str) {
		self.db.oauthid_session.remove(sess_id);
	}

	/// Check if a user has any SSO sessions.
	pub async fn user_has_session(&self, user_id: &UserId) -> bool {
		self.db.userid_oauthid.get(user_id).await.is_ok()
	}

	/// Look up a user_id by email from the allowlist.
	pub async fn get_user_by_email(&self, email: &str) -> Result<String> {
		self.db.email_userid.get(email).await.deserialized()
	}

	/// Store or replace an email ↔ user_id mapping, keeping both indexes in
	/// sync.
	pub async fn set_email(&self, user_id: &str, email: &str) {
		if let Ok(previous_email) = self.get_email(user_id).await
			&& previous_email != email
		{
			self.db.email_userid.remove(&previous_email);
		}

		if let Ok(previous_user_id) = self.get_user_by_email(email).await
			&& previous_user_id != user_id
		{
			self.db.userid_email.remove(&previous_user_id);
		}

		self.db.email_userid.insert(email, user_id);
		self.db.userid_email.insert(user_id, email);
	}

	/// Get the email for a user.
	pub async fn get_email(&self, user_id: &str) -> Result<String> {
		self.db.userid_email.get(user_id).await.deserialized()
	}

	/// Remove the email mapping for a user.
	pub fn remove_email(&self, user_id: &str, email: &str) {
		self.db.email_userid.remove(email);
		self.db.userid_email.remove(user_id);
	}

	/// List all email ↔ user_id mappings.
	pub fn list_emails(&self) -> impl futures::Stream<Item = (String, String)> + Send + '_ {
		use conduwuit::utils::stream::TryIgnore;
		self.db
			.email_userid
			.stream()
			.ignore_err()
			.map(|(email, user_id): (&str, &str)| (email.to_owned(), user_id.to_owned()))
	}
}
