//! ORM-agnostic domain types.
//!
//! These types cross the repository trait boundary and have no backend-specific
//! dependencies. Each backend converts between its internal ORM-annotated models
//! and these types via private conversion methods.

mod session_ops;
pub use session_ops::*;

mod rate_limit;
pub use rate_limit::*;

mod user;
pub use user::*;

mod audit;
pub use audit::*;

#[cfg(feature = "email-password")]
mod password;
#[cfg(feature = "email-password")]
pub use password::*;

#[cfg(feature = "passkey")]
mod passkey;
#[cfg(feature = "passkey")]
pub use passkey::*;

#[cfg(feature = "mfa")]
mod mfa;
#[cfg(feature = "mfa")]
pub use mfa::*;

#[cfg(feature = "oauth")]
mod oauth;
#[cfg(feature = "oauth")]
pub use oauth::*;

#[cfg(feature = "api-key")]
mod api_key;
#[cfg(feature = "api-key")]
pub use api_key::*;

#[cfg(feature = "bearer")]
mod bearer;
#[cfg(feature = "bearer")]
pub use bearer::*;

#[cfg(feature = "magic-link")]
mod magic_link;
#[cfg(feature = "magic-link")]
pub use magic_link::*;

#[cfg(feature = "oauth2-server")]
mod oauth2_server;
#[cfg(feature = "oauth2-server")]
pub use oauth2_server::*;

#[cfg(feature = "account-lockout")]
mod account_lockout;
#[cfg(feature = "account-lockout")]
pub use account_lockout::*;

#[cfg(feature = "webhooks")]
mod webhooks;
#[cfg(feature = "webhooks")]
pub use webhooks::*;
