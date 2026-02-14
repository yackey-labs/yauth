use crate::state::YAuthState;
use axum::Router;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthEvent {
    UserRegistered {
        user_id: Uuid,
        email: String,
    },
    LoginSucceeded {
        user_id: Uuid,
        method: String,
    },
    LoginFailed {
        email: String,
        method: String,
        reason: String,
    },
    SessionCreated {
        user_id: Uuid,
        session_id: Uuid,
    },
    Logout {
        user_id: Uuid,
        session_id: Uuid,
    },
    PasswordChanged {
        user_id: Uuid,
    },
    EmailVerified {
        user_id: Uuid,
    },
    MfaEnabled {
        user_id: Uuid,
        method: String,
    },
    MfaDisabled {
        user_id: Uuid,
        method: String,
    },
    UserBanned {
        user_id: Uuid,
    },
    UserUnbanned {
        user_id: Uuid,
    },
    MagicLinkSent {
        email: String,
    },
    MagicLinkVerified {
        user_id: Uuid,
        is_new_user: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventResponse {
    Continue,
    RequireMfa {
        user_id: Uuid,
        pending_session_id: Uuid,
    },
    Block {
        status: u16,
        message: String,
    },
}

pub struct PluginContext<'a> {
    pub state: &'a YAuthState,
}

impl<'a> PluginContext<'a> {
    pub fn new(state: &'a YAuthState) -> Self {
        Self { state }
    }
}

pub trait YAuthPlugin: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn public_routes(&self, ctx: &PluginContext) -> Option<Router<YAuthState>>;
    fn protected_routes(&self, ctx: &PluginContext) -> Option<Router<YAuthState>>;
    fn on_event(&self, _event: &AuthEvent, _ctx: &PluginContext) -> EventResponse {
        EventResponse::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_event_serialization_roundtrip() {
        let event = AuthEvent::LoginSucceeded {
            user_id: Uuid::nil(),
            method: "email".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: AuthEvent = serde_json::from_str(&json).unwrap();
        match parsed {
            AuthEvent::LoginSucceeded { user_id, method } => {
                assert_eq!(user_id, Uuid::nil());
                assert_eq!(method, "email");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn event_response_continue_serializes() {
        let resp = EventResponse::Continue;
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("Continue"));
    }

    #[test]
    fn event_response_require_mfa_serializes() {
        let resp = EventResponse::RequireMfa {
            user_id: Uuid::nil(),
            pending_session_id: Uuid::nil(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: EventResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            EventResponse::RequireMfa { .. } => {}
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn event_response_block_serializes() {
        let resp = EventResponse::Block {
            status: 403,
            message: "denied".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("403"));
        assert!(json.contains("denied"));
    }

    #[test]
    fn all_event_variants_serialize() {
        let events: Vec<AuthEvent> = vec![
            AuthEvent::UserRegistered {
                user_id: Uuid::nil(),
                email: "a@b.c".into(),
            },
            AuthEvent::LoginSucceeded {
                user_id: Uuid::nil(),
                method: "email".into(),
            },
            AuthEvent::LoginFailed {
                email: "a@b.c".into(),
                method: "email".into(),
                reason: "bad password".into(),
            },
            AuthEvent::SessionCreated {
                user_id: Uuid::nil(),
                session_id: Uuid::nil(),
            },
            AuthEvent::Logout {
                user_id: Uuid::nil(),
                session_id: Uuid::nil(),
            },
            AuthEvent::PasswordChanged {
                user_id: Uuid::nil(),
            },
            AuthEvent::EmailVerified {
                user_id: Uuid::nil(),
            },
            AuthEvent::MfaEnabled {
                user_id: Uuid::nil(),
                method: "totp".into(),
            },
            AuthEvent::MfaDisabled {
                user_id: Uuid::nil(),
                method: "totp".into(),
            },
            AuthEvent::UserBanned {
                user_id: Uuid::nil(),
            },
            AuthEvent::UserUnbanned {
                user_id: Uuid::nil(),
            },
            AuthEvent::MagicLinkSent {
                email: "a@b.c".into(),
            },
            AuthEvent::MagicLinkVerified {
                user_id: Uuid::nil(),
                is_new_user: true,
            },
        ];
        for event in &events {
            let json = serde_json::to_string(event).unwrap();
            let _: AuthEvent = serde_json::from_str(&json).unwrap();
        }
    }
}
