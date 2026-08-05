use std::{sync::Arc, time::SystemTime};

use conduwuit::{Result, error};
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

	/// Unique identity hash (SHA256 of issuer + sub), used for returning-user
	/// dedup and session cleanup. Populated by `put()` when a `unique_id` is
	/// provided.
	#[serde(default)]
	pub unique_id: Option<String>,
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

	/// Store or update a session. When `unique_id` is provided it is
	/// persisted both as a secondary index and inside the session itself so
	/// that `delete` can clean up the index without needing provider config.
	///
	/// # Panics
	///
	/// Never — returns early if `sess_id` is missing (should not happen in
	/// normal operation).
	pub fn put(&self, session: &Session, unique_id: Option<&str>) {
		let Some(sess_id) = session.sess_id.as_deref() else {
			error!("BUG: Sessions::put called without sess_id");
			return;
		};

		// Merge unique_id into the stored session so delete() can find it.
		let session = if unique_id.is_some() && session.unique_id.as_deref() != unique_id {
			Session {
				unique_id: unique_id.map(str::to_owned),
				..session.clone()
			}
		} else {
			session.clone()
		};

		self.db.oauthid_session.raw_put(sess_id, Cbor(&session));

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

	/// Delete a session and clean up all associated index entries.
	///
	/// Only removes secondary indexes (`oauthuniqid_oauthid`,
	/// `userid_oauthid`) if they still point to this session, preventing a
	/// newer session's entries from being clobbered.
	pub async fn delete(&self, sess_id: &str) {
		if let Ok(session) = self.get(sess_id).await {
			// Clean unique_id index.
			if let Some(unique_id) = session.unique_id.as_deref() {
				let still_ours = self
					.db
					.oauthuniqid_oauthid
					.get(unique_id)
					.await
					.deserialized::<String>()
					.is_ok_and(|stored| stored == sess_id);

				if still_ours {
					self.db.oauthuniqid_oauthid.remove(unique_id);
				}
			}

			// Clean user_id index.
			if let Some(user_id) = session.user_id.as_deref() {
				let still_ours = self
					.db
					.userid_oauthid
					.get(user_id)
					.await
					.deserialized::<String>()
					.is_ok_and(|stored| stored == sess_id);

				if still_ours {
					self.db.userid_oauthid.remove(user_id);
				}
			}
		}

		self.db.oauthid_session.remove(sess_id);
	}

	/// Check if a user has any SSO sessions.
	pub async fn user_has_session(&self, user_id: &UserId) -> bool {
		self.db.userid_oauthid.get(user_id).await.is_ok()
	}

	/// Look up a user_id by email from the allowlist.
	/// Email is normalized to lowercase for case-insensitive matching.
	pub async fn get_user_by_email(&self, email: &str) -> Result<String> {
		let email = email.to_lowercase();
		self.db.email_userid.get(&*email).await.deserialized()
	}

	/// Store or replace an email ↔ user_id mapping, keeping both indexes in
	/// sync. Email is normalized to lowercase for case-insensitive matching.
	pub async fn set_email(&self, user_id: &str, email: &str) {
		let email = email.to_lowercase();

		if let Ok(previous_email) = self.get_email(user_id).await
			&& previous_email != email
		{
			self.db.email_userid.remove(&previous_email);
		}

		if let Ok(previous_user_id) = self.get_user_by_email(&email).await
			&& previous_user_id != user_id
		{
			self.db.userid_email.remove(&previous_user_id);
		}

		self.db.email_userid.insert(&*email, user_id);
		self.db.userid_email.insert(user_id, &*email);
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
