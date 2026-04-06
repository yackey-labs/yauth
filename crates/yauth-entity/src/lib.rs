//! ORM-agnostic domain types for yauth.
//!
//! These types cross the repository trait boundary and have no backend-specific
//! dependencies. Each backend converts between its internal ORM-annotated models
//! and these types via private conversion methods.

mod user;
pub use user::*;

mod session_ops;
pub use session_ops::*;

mod rate_limit;
pub use rate_limit::*;

mod audit;
pub use audit::*;

mod password;
pub use password::*;

mod passkey;
pub use passkey::*;

mod mfa;
pub use mfa::*;

mod oauth;
pub use oauth::*;

mod api_key;
pub use api_key::*;

mod bearer;
pub use bearer::*;

mod magic_link;
pub use magic_link::*;

mod oauth2_server;
pub use oauth2_server::*;

mod account_lockout;
pub use account_lockout::*;

mod webhooks;
pub use webhooks::*;
