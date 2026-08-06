use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use web_sys::{CloseEvent, ErrorEvent, MessageEvent, WebSocket};

#[derive(Debug, Clone, Deserialize)]
pub struct PendingApproval {
    pub id: String,
    pub method: String,
    pub params: Option<String>,
    pub dapp_origin: Option<String>,
    pub chain_id: Option<String>,
    pub risk_level: String,
    pub risk_reasons: Vec<RiskReason>,
    pub created_at_unix: Option<u64>,
    pub expires_at_unix: Option<u64>,
    pub simulation: Option<TxSimulation>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TxSimulation {
    pub success: Option<bool>,
    pub gas_used: Option<u64>,
    pub balance_change: Option<Vec<TokenDelta>>,
    pub decoded_action: Option<DecodedAction>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenDelta {
    pub token: String,
    pub direction: String,
    pub amount: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DecodedAction {
    pub contract_name: Option<String>,
    pub function_name: Option<String>,
    pub human_readable: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RiskReason {
    pub code: Option<String>,
    pub level: Option<String>,
    pub message: Option<String>,
    pub source: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum WsEvent {
    #[serde(rename = "pending_approval")]
    PendingApproval { approval: PendingApproval },
    #[serde(rename = "approval_resolved")]
    ApprovalResolved { id: String, decision: String },
    #[serde(rename = "auto_locked")]
    AutoLocked,
    #[serde(rename = "auto_lock_warning")]
    AutoLockWarning { in_secs: u64 },
}

/// Connect WebSocket and broadcast pending approvals into a shared signal.
pub fn connect_ws(approvals: RwSignal<Vec<PendingApproval>>) {
    let location = web_sys::window().unwrap().location();
    let protocol = location.protocol().unwrap_or_else(|_| "http:".into());
    let ws_protocol = if protocol == "https:" { "wss:" } else { "ws:" };
    let host = location.host().unwrap_or_else(|_| "localhost".into());
    let url = format!("{ws_protocol}//{host}/ws");

    let ws = WebSocket::new(&url).unwrap();
    ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

    let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
        let text = match ev.data().as_string() {
            Some(t) => t,
            None => return,
        };
        let event: WsEvent = match serde_json::from_str(&text) {
            Ok(e) => e,
            Err(_) => return,
        };

        // Converge the data cache first, so any component that re-renders as a
        // result of the signal updates below reads post-invalidation state.
        // Skipping this is what used to leave resolved approvals and spent
        // balances on screen until a manual reload.
        crate::cache::invalidate::handle_invalidation(&event);

        match event {
            WsEvent::PendingApproval { approval } => {
                approvals.update(|list| {
                    if !list.iter().any(|a| a.id == approval.id) {
                        list.push(approval);
                    }
                });
            }
            WsEvent::ApprovalResolved { id, .. } => {
                approvals.update(|list| {
                    list.retain(|a| a.id != id);
                });
            }
            WsEvent::AutoLocked => {
                // The queue is authorized state too — clear it alongside the
                // cache rather than leaving pending items rendered behind the
                // lock screen.
                approvals.update(Vec::clear);
            }
            WsEvent::AutoLockWarning { .. } => {}
        }
    });
    ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();

    let onerror = Closure::<dyn FnMut(ErrorEvent)>::new(|_ev: ErrorEvent| {});
    ws.set_onerror(Some(onerror.as_ref().unchecked_ref()));
    onerror.forget();

    let onclose = Closure::<dyn FnMut(CloseEvent)>::new(|_ev: CloseEvent| {});
    ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));
    onclose.forget();
}
