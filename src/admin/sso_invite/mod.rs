mod commands;

use clap::Subcommand;
use conduwuit::Result;

use crate::admin_command_dispatch;

#[admin_command_dispatch]
#[derive(Debug, Subcommand)]
pub enum SsoInviteCommand {
	/// Issue a new SSO invite link via the default identity provider
	Issue {
		/// Invite lifetime understood by the provider API, e.g. `24h` or `7d`
		#[arg(long, default_value = "7d")]
		ttl: String,

		/// Maximum number of uses before the invite expires
		#[arg(long, default_value_t = 1)]
		usage_limit: u64,
	},
}
