//! Sign-button state machine (Section 7 of design doc).
//!
//! States: Disabled → Armed → Submitting
//! Forbidden: Sign hidden entirely, only Reject shown.
//!
//! Disabled when:
//!   - unprocessed warnings exist
//!   - Danger 5s countdown active
//!   - overall risk is Forbidden (transitions to Forbidden, not Disabled)
//!
//! Armed: user clicked Sign → reveals Confirm Sign + Cancel
//! Cancel → back to Disabled
//! Confirm Sign → Submitting (POST decision)

use oc_core::RiskLevel;

/// Sign button state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignState {
    /// Sign button disabled (unprocessed warnings, danger countdown, etc.).
    Disabled,
    /// User clicked Sign; Confirm + Cancel visible.
    Armed,
    /// POST in flight.
    Submitting,
    /// Sign button hidden entirely; only Reject shown.
    Forbidden,
}

/// Inputs that determine the sign-button state.
#[derive(Debug, Clone)]
pub struct SignContext {
    pub risk_level: RiskLevel,
    pub unprocessed_warnings: u32,
    pub danger_countdown_active: bool,
    pub already_submitted: bool,
}

impl SignState {
    /// Compute the current state from context.
    pub fn from_context(ctx: &SignContext) -> Self {
        if ctx.already_submitted {
            return Self::Submitting;
        }
        if ctx.risk_level == RiskLevel::Forbidden {
            return Self::Forbidden;
        }
        if ctx.unprocessed_warnings > 0 || ctx.danger_countdown_active {
            return Self::Disabled;
        }
        Self::Disabled
    }

    /// Transition on user action. Returns new state or `None` if invalid.
    pub fn transition(self, action: Action) -> Option<Self> {
        match (self, action) {
            (Self::Disabled, Action::ClickSign) => Some(Self::Armed),
            (Self::Armed, Action::Cancel) => Some(Self::Disabled),
            (Self::Armed, Action::ConfirmSign) => Some(Self::Submitting),
            _ => None,
        }
    }
}

/// User actions on the sign button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    ClickSign,
    Cancel,
    ConfirmSign,
}

#[cfg(test)]
mod submit_actions_state_machine {
    use super::*;

    #[test]
    fn forbidden_hides_sign() {
        let ctx = SignContext {
            risk_level: RiskLevel::Forbidden,
            unprocessed_warnings: 0,
            danger_countdown_active: false,
            already_submitted: false,
        };
        assert_eq!(SignState::from_context(&ctx), SignState::Forbidden);
    }

    #[test]
    fn disabled_with_unprocessed_warnings() {
        let ctx = SignContext {
            risk_level: RiskLevel::Warning,
            unprocessed_warnings: 2,
            danger_countdown_active: false,
            already_submitted: false,
        };
        assert_eq!(SignState::from_context(&ctx), SignState::Disabled);
    }

    #[test]
    fn disabled_with_danger_countdown() {
        let ctx = SignContext {
            risk_level: RiskLevel::Danger,
            unprocessed_warnings: 0,
            danger_countdown_active: true,
            already_submitted: false,
        };
        assert_eq!(SignState::from_context(&ctx), SignState::Disabled);
    }

    #[test]
    fn disabled_when_safe_no_warnings() {
        let ctx = SignContext {
            risk_level: RiskLevel::Safe,
            unprocessed_warnings: 0,
            danger_countdown_active: false,
            already_submitted: false,
        };
        assert_eq!(SignState::from_context(&ctx), SignState::Disabled);
    }

    #[test]
    fn submitting_when_already_submitted() {
        let ctx = SignContext {
            risk_level: RiskLevel::Safe,
            unprocessed_warnings: 0,
            danger_countdown_active: false,
            already_submitted: true,
        };
        assert_eq!(SignState::from_context(&ctx), SignState::Submitting);
    }

    #[test]
    fn disabled_to_armed() {
        let next = SignState::Disabled.transition(Action::ClickSign);
        assert_eq!(next, Some(SignState::Armed));
    }

    #[test]
    fn armed_cancel_back_to_disabled() {
        let next = SignState::Armed.transition(Action::Cancel);
        assert_eq!(next, Some(SignState::Disabled));
    }

    #[test]
    fn armed_confirm_to_submitting() {
        let next = SignState::Armed.transition(Action::ConfirmSign);
        assert_eq!(next, Some(SignState::Submitting));
    }

    #[test]
    fn invalid_transitions_return_none() {
        assert_eq!(SignState::Disabled.transition(Action::Cancel), None);
        assert_eq!(SignState::Disabled.transition(Action::ConfirmSign), None);
        assert_eq!(SignState::Submitting.transition(Action::ClickSign), None);
        assert_eq!(SignState::Forbidden.transition(Action::ClickSign), None);
    }

    #[test]
    fn full_flow_disabled_to_submitting() {
        let s = SignState::Disabled;
        let s = s.transition(Action::ClickSign).unwrap();
        assert_eq!(s, SignState::Armed);
        let s = s.transition(Action::ConfirmSign).unwrap();
        assert_eq!(s, SignState::Submitting);
    }

    #[test]
    fn armed_cancel_then_re_arm() {
        let s = SignState::Armed;
        let s = s.transition(Action::Cancel).unwrap();
        assert_eq!(s, SignState::Disabled);
        let s = s.transition(Action::ClickSign).unwrap();
        assert_eq!(s, SignState::Armed);
    }
}
