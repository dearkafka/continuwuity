use conduwuit::{Err, Result};
use conduwuit_macros::admin_command;

#[admin_command]
pub(super) async fn issue(&self, ttl: String, usage_limit: u64) -> Result {
	if usage_limit == 0 {
		return Err!("usage-limit must be at least 1");
	}

	let invite = self
		.services
		.sso_invites
		.issue_default_invite(&ttl, usage_limit)
		.await?;

	let groups = if invite.user_group_ids.is_empty() {
		"none".to_owned()
	} else {
		invite.user_group_ids.join(", ")
	};

	let mut output = format!(
		"New SSO invite issued via `{}`:\n\
		 - URL: `{}`\n\
		 - Token ID: `{}`\n\
		 - Usage limit: `{}`\n\
		 - Group IDs: `{groups}`",
		invite.provider_id, invite.invite_url, invite.token_id, invite.usage_limit,
	);

	if let Some(expires_at) = &invite.expires_at {
		output.push_str(&format!("\n- Expires at: `{expires_at}`"));
	}

	self.write_str(&output).await
}
