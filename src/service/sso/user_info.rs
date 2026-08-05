use serde::{Deserialize, Serialize};

/// Selection of userinfo response claims from an OAuth2/OIDC provider.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UserInfo {
	/// Unique identifier. Usually a number on most services. We consider a
	/// concatenation of the `iss` and `sub` to be a universally unique
	/// identifier for some user/identity.
	///
	/// `login` alias intended for GitHub.
	#[serde(alias = "login")]
	pub sub: String,

	/// The login username we first consider when defined.
	pub preferred_username: Option<String>,

	/// The login username considered.
	pub username: Option<String>,

	/// The login username considered if none preferred.
	pub nickname: Option<String>,

	/// Full name.
	pub name: Option<String>,

	/// First name.
	pub given_name: Option<String>,

	/// Last name.
	pub family_name: Option<String>,

	/// Email address (`email` scope).
	pub email: Option<String>,

	/// Whether the provider asserts that `email` is verified.
	pub email_verified: Option<bool>,

	/// URL to avatar (GitHub/GitLab).
	pub avatar_url: Option<String>,

	/// URL to avatar (Google).
	pub picture: Option<String>,
}
