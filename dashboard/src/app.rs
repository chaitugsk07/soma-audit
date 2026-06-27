//! App shell: router, sidebar, header with token + tenant inputs.

use crate::pages::{AuditPage, KeysPage, SealsPage, SourcesPage, VerifyPage};
use crate::util::{local_storage_get, local_storage_set};
use leptos::prelude::*;
use leptos_router::{
    components::{FlatRoutes, Redirect, Route, Router},
    hooks::use_location,
    path,
};
use soma_ui::{Input, Sidebar, SidebarItem, ThemeToggle, STYLES};

// ── Context passed to every page ──────────────────────────────────────────────

/// Shared signals threaded via context so pages can read them without prop drilling.
#[derive(Clone, Copy)]
pub struct AppCtx {
    pub token: RwSignal<String>,
    pub tenant_id: RwSignal<String>,
}

fn sidebar_items() -> Vec<SidebarItem> {
    vec![
        SidebarItem {
            label: "Sources".to_string(),
            href: "/sources".to_string(),
            icon: Some(soma_ui::icons::icondata::LuServer),
        },
        SidebarItem {
            label: "Audit Events".to_string(),
            href: "/audit".to_string(),
            icon: Some(soma_ui::icons::icondata::LuList),
        },
        SidebarItem {
            label: "Verify".to_string(),
            href: "/verify".to_string(),
            icon: Some(soma_ui::icons::icondata::LuShield),
        },
        SidebarItem {
            label: "Seals".to_string(),
            href: "/seals".to_string(),
            icon: Some(soma_ui::icons::icondata::LuKey),
        },
        SidebarItem {
            label: "Keys".to_string(),
            href: "/keys".to_string(),
            icon: Some(soma_ui::icons::icondata::LuSettings),
        },
    ]
}

#[component]
fn AppShell(children: Children) -> impl IntoView {
    let ctx = use_context::<AppCtx>().expect("AppCtx must be provided");
    let location = use_location();
    let active_path = Signal::derive(move || location.pathname.get());

    // Health status dot: poll /health on mount
    let healthy = RwSignal::new(false);
    leptos::task::spawn_local(async move {
        healthy.set(crate::api::get_health().await);
    });

    let brand = view! {
        <span class="font-heading font-bold text-lg text-foreground tracking-tight">
            "soma-audit"
        </span>
    }
    .into_any();

    view! {
        <div class="flex h-screen bg-background overflow-hidden">
            <Sidebar
                items=sidebar_items()
                active_path=active_path
                brand=brand
            />
            <div class="flex flex-col flex-1 overflow-hidden">
                // Top bar
                <header class="flex items-center justify-between px-4 h-auto min-h-14 py-2 border-b border-border bg-card shrink-0 gap-4 flex-wrap">
                    <div class="flex items-center gap-2">
                        // Connection dot
                        <span
                            class=move || if healthy.get() {
                                "h-2 w-2 rounded-full bg-green-500"
                            } else {
                                "h-2 w-2 rounded-full bg-red-400"
                            }
                            title=move || if healthy.get() { "Server reachable" } else { "Server unreachable" }
                        />
                        <span class="font-heading font-semibold text-foreground text-sm">"soma-audit"</span>
                    </div>
                    <div class="flex items-center gap-2 flex-wrap">
                        // Tenant ID input
                        <div class="w-56">
                            <Input
                                value=ctx.tenant_id
                                placeholder="tenant-id (UUID)".to_string()
                                on:change=move |e| {
                                    let v = event_target_value(&e);
                                    local_storage_set("soma_audit_tenant_id", &v);
                                }
                            />
                        </div>
                        // Admin token input
                        <div class="w-56">
                            <Input
                                input_type="password".to_string()
                                value=ctx.token
                                placeholder="admin token".to_string()
                                on:change=move |e| {
                                    let v = event_target_value(&e);
                                    local_storage_set("soma_audit_token", &v);
                                }
                            />
                        </div>
                        <ThemeToggle />
                    </div>
                </header>
                // Page content
                <main class="flex-1 overflow-auto p-6">
                    {children()}
                </main>
            </div>
        </div>
    }
}

#[component]
pub fn App() -> impl IntoView {
    // Initialize from localStorage so token/tenant survive page reloads.
    let token = RwSignal::new(
        local_storage_get("soma_audit_token").unwrap_or_default(),
    );
    let tenant_id = RwSignal::new(
        local_storage_get("soma_audit_tenant_id").unwrap_or_default(),
    );
    provide_context(AppCtx { token, tenant_id });

    view! {
        <style>{STYLES}</style>
        <Router>
            <AppShell>
                <FlatRoutes fallback=|| view! { <div class="text-muted-foreground">"Page not found"</div> }>
                    <Route path=path!("/") view=|| view! { <Redirect path="/sources" /> } />
                    <Route path=path!("/sources") view=SourcesPage />
                    <Route path=path!("/audit") view=AuditPage />
                    <Route path=path!("/verify") view=VerifyPage />
                    <Route path=path!("/seals") view=SealsPage />
                    <Route path=path!("/keys") view=KeysPage />
                </FlatRoutes>
            </AppShell>
        </Router>
    }
}
