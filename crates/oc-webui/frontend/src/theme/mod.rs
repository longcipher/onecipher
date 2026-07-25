pub mod dark;

/// Default design tokens (matching oc-core::theme).
/// Injected as CSS custom properties into `<style id="oc-tokens">`.
const DEFAULT_TOKENS: &str = r#"
:root {
    --oc-bg: #0f172a;
    --oc-bg-card: #1e293b;
    --oc-bg-input: #334155;
    --oc-text: #f8fafc;
    --oc-text-muted: #94a3b8;
    --oc-border: #475569;
    --oc-accent: #3b82f6;
    --oc-accent-hover: #2563eb;
    --oc-danger: #ef4444;
    --oc-warning: #eab308;
    --oc-success: #22c55e;
    --oc-radius: 8px;
    --oc-font: system-ui, -apple-system, sans-serif;
}
html.dark {
    color-scheme: dark;
}
html:not(.dark) {
    --oc-bg: #f8fafc;
    --oc-bg-card: #ffffff;
    --oc-bg-input: #e2e8f0;
    --oc-text: #0f172a;
    --oc-text-muted: #64748b;
    --oc-border: #cbd5e1;
    --oc-accent: #3b82f6;
    --oc-accent-hover: #2563eb;
    color-scheme: light;
}
"#;

/// Inject CSS custom properties into the document head.
pub fn inject_tokens() {
    let window = web_sys::window().expect("no window");
    let document = window.document().expect("no document");
    let head = document.head().expect("no head");

    // Remove existing token style if present
    if let Some(existing) = document.get_element_by_id("oc-tokens") {
        existing.remove();
    }

    let style = document
        .create_element("style")
        .expect("create style element");
    style.set_id("oc-tokens");
    style.set_text_content(Some(DEFAULT_TOKENS));
    head.append_child(&style).expect("append style");
}
