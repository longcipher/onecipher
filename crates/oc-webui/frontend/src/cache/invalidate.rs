use crate::api::ws::WsEvent;
use crate::cache::{Scene, invalidate_scene};

/// Map a WebSocket event to cache scene invalidation.
/// Called from the WS message handler to keep the cache fresh.
pub fn handle_invalidation(event: &WsEvent) {
    match event {
        WsEvent::PendingApproval { .. } | WsEvent::ApprovalResolved { .. } => {
            invalidate_scene(Scene::Approvals);
        }
        WsEvent::AutoLocked => {
            // On auto-lock, invalidate everything — UI should redirect to unlock.
            crate::cache::invalidate_all();
        }
        WsEvent::AutoLockWarning { .. } => {
            // No cache impact, just a UI warning.
        }
    }
}

// ponytail: add more event types (wallet_changed, session_updated, settings_patched)
// from the WS feed when the backend emits them. Each maps to its Scene.
