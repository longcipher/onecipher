//! Maps daemon push events onto cache invalidations.
//!
//! This is the bridge that makes the cache *converge*: the daemon is the only
//! writer of truth, and every state change it pushes over the WebSocket must
//! land here, or the UI drifts. [`handle_invalidation`] is called from the WS
//! message handler for every decoded event — including ones with no cache
//! impact, so that adding a new event forces a decision about which scene it
//! touches rather than defaulting to "stale".

use crate::{
    api::ws::WsEvent,
    cache::{Scene, invalidate_all, invalidate_scene},
};

/// Map a WebSocket event to cache scene invalidation.
///
/// Returns the scenes that were invalidated, which the tests assert on and
/// callers may log.
pub fn handle_invalidation(event: &WsEvent) -> Vec<Scene> {
    match event {
        WsEvent::PendingApproval { .. } | WsEvent::ApprovalResolved { .. } => {
            // A resolved approval can also move funds, so the balances and the
            // audit trail are no longer trustworthy either. Under-invalidating
            // here is what leaves a signed-away balance on screen.
            let scenes = vec![Scene::Approvals, Scene::Balances, Scene::Audit];
            for scene in &scenes {
                invalidate_scene(*scene);
            }
            scenes
        }
        WsEvent::AutoLocked => {
            // The vault is locked: nothing previously fetched is still
            // authorized, so drop all of it rather than leaving decrypted
            // material rendered behind a lock screen.
            invalidate_all();
            Scene::ALL.to_vec()
        }
        WsEvent::AutoLockWarning { .. } => {
            // Purely a countdown banner — no server state changed.
            Vec::new()
        }
    }
}

// ponytail: add more event types (wallet_changed, session_updated,
// settings_patched) from the WS feed when the backend emits them. Each maps to
// its Scene.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{TEST_LOCK, scene_epoch_value};

    fn approval() -> crate::api::ws::PendingApproval {
        crate::api::ws::PendingApproval {
            id: "a1".into(),
            method: "eth_sendTransaction".into(),
            params: None,
            dapp_origin: None,
            chain_id: None,
            risk_level: "low".into(),
            risk_reasons: vec![],
            created_at_unix: None,
            expires_at_unix: None,
            simulation: None,
        }
    }

    #[test]
    fn a_pending_approval_invalidates_approvals_balances_and_audit() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let scenes = handle_invalidation(&WsEvent::PendingApproval { approval: approval() });
        assert!(scenes.contains(&Scene::Approvals));
        assert!(scenes.contains(&Scene::Balances));
        assert!(scenes.contains(&Scene::Audit));
    }

    #[test]
    fn a_resolved_approval_wakes_its_subscribers() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = scene_epoch_value(Scene::Approvals);
        handle_invalidation(&WsEvent::ApprovalResolved {
            id: "a1".into(),
            decision: "approved".into(),
        });
        assert_eq!(
            scene_epoch_value(Scene::Approvals),
            before + 1,
            "resolving an approval must refetch the queue"
        );
    }

    #[test]
    fn a_resolved_approval_also_wakes_balances() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // The regression this guards: an approved transfer used to leave the
        // pre-transfer balance on screen indefinitely.
        let before = scene_epoch_value(Scene::Balances);
        handle_invalidation(&WsEvent::ApprovalResolved {
            id: "a1".into(),
            decision: "approved".into(),
        });
        assert_eq!(scene_epoch_value(Scene::Balances), before + 1);
    }

    #[test]
    fn auto_lock_invalidates_everything() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let before: Vec<u64> = Scene::ALL.iter().map(|s| scene_epoch_value(*s)).collect();
        let scenes = handle_invalidation(&WsEvent::AutoLocked);
        assert_eq!(scenes.len(), Scene::ALL.len());
        for (scene, was) in Scene::ALL.iter().zip(before) {
            assert_eq!(
                scene_epoch_value(*scene),
                was + 1,
                "scene {} survived auto-lock",
                scene.as_str()
            );
        }
    }

    #[test]
    fn an_auto_lock_warning_invalidates_nothing() {
        let _g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let before: Vec<u64> = Scene::ALL.iter().map(|s| scene_epoch_value(*s)).collect();
        let scenes = handle_invalidation(&WsEvent::AutoLockWarning { in_secs: 30 });
        assert!(scenes.is_empty());
        for (scene, was) in Scene::ALL.iter().zip(before) {
            assert_eq!(
                scene_epoch_value(*scene),
                was,
                "a countdown banner must not trigger refetches"
            );
        }
    }
}
