//! Sources page — lists all source services discovered by the central server.

use crate::api::{get_sources, SourceRecord};
use crate::app::AppCtx;
use crate::util::relative_time;
use leptos::prelude::*;
use soma_ui::{
    Alert, AlertDescription, AlertTitle, AlertVariant, Button, ButtonSize, ButtonVariant, Empty,
    PageHeader, Spinner, Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
};

fn health_dot(last_seen: &str) -> impl IntoView {
    // Parse ISO timestamp and compute age in seconds using js_sys (same pattern as util.rs).
    let age_secs = {
        let then_ms = js_sys::Date::parse(last_seen);
        if then_ms.is_nan() {
            f64::MAX
        } else {
            (js_sys::Date::now() - then_ms) / 1000.0
        }
    };

    let (color, title) = if age_secs < 300.0 {
        ("bg-green-500", "Healthy (seen < 5 min ago)")
    } else if age_secs < 3600.0 {
        ("bg-yellow-400", "Degraded (seen < 1 hr ago)")
    } else {
        ("bg-red-500", "Stale (seen > 1 hr ago)")
    };

    view! {
        <span
            class=format!("inline-block h-2.5 w-2.5 rounded-full {color}")
            title=title
        />
    }
}

#[component]
pub fn SourcesPage() -> impl IntoView {
    let ctx = use_context::<AppCtx>().expect("AppCtx required");

    let sources: RwSignal<Vec<SourceRecord>> = RwSignal::new(vec![]);
    let load_err: RwSignal<Option<(u16, String)>> = RwSignal::new(None);
    let loading = RwSignal::new(false);
    let loaded = RwSignal::new(false);

    let load = move || {
        let token = ctx.token.get();
        loading.set(true);
        load_err.set(None);
        leptos::task::spawn_local(async move {
            match get_sources(&token).await {
                Ok(rows) => {
                    sources.set(rows);
                    loaded.set(true);
                }
                Err(e) => {
                    load_err.set(Some((e.status, e.message)));
                    loaded.set(true);
                }
            }
            loading.set(false);
        });
    };

    // Auto-load on mount.
    {
        let load = load.clone();
        leptos::task::spawn_local(async move { load(); });
    }

    let navigate = leptos_router::hooks::use_navigate();

    view! {
        <div class="space-y-6">
            <PageHeader title="Sources".to_string()>
                <Button
                    variant=ButtonVariant::Outline
                    size=ButtonSize::Sm
                    on:click=move |_| load()
                >
                    "Refresh"
                </Button>
            </PageHeader>

            {move || load_err.get().map(|(status, msg)| {
                let (title, body) = if status == 401 {
                    ("Unauthorized", "Check your admin token in the header.".to_string())
                } else {
                    ("Failed to load sources", msg.clone())
                };
                view! {
                    <Alert variant=AlertVariant::Destructive>
                        <AlertTitle>{title}</AlertTitle>
                        <AlertDescription>{body}</AlertDescription>
                    </Alert>
                }
            })}

            {move || {
                if !loaded.get() && loading.get() {
                    return view! { <div class="flex justify-center py-8"><Spinner /></div> }.into_any();
                }
                if loaded.get() && sources.get().is_empty() && load_err.get().is_none() {
                    return view! {
                        <Empty
                            title="No sources".to_string()
                            description="No services have sent events yet.".to_string()
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="text-muted-foreground/40">
                                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                                <line x1="8" y1="21" x2="16" y2="21"/>
                                <line x1="12" y1="17" x2="12" y2="21"/>
                            </svg>
                        </Empty>
                    }.into_any();
                }
                if sources.get().is_empty() {
                    return ().into_any();
                }
                let navigate = navigate.clone();
                view! {
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead class="w-6".to_string()>"Health"</TableHead>
                                <TableHead>"Service"</TableHead>
                                <TableHead>"Tenant"</TableHead>
                                <TableHead>"Host"</TableHead>
                                <TableHead>"Version"</TableHead>
                                <TableHead>"Last Seen"</TableHead>
                                <TableHead>"Events"</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            <For
                                each=move || sources.get()
                                key=|s| format!("{}-{}", s.source_service, s.tenant_id)
                                children=move |src| {
                                    let tenant_short = if src.tenant_id.len() > 8 {
                                        format!("{}…", &src.tenant_id[..8])
                                    } else {
                                        src.tenant_id.clone()
                                    };
                                    let last_seen_rel = relative_time(&src.last_seen);
                                    let last_seen_abs = src.last_seen.clone();
                                    let tenant_id_for_nav = src.tenant_id.clone();
                                    let navigate = navigate.clone();
                                    let on_row_click = move |_| {
                                        ctx.tenant_id.set(tenant_id_for_nav.clone());
                                        navigate("/audit", Default::default());
                                    };
                                    view! {
                                        <TableRow
                                            class="cursor-pointer hover:bg-muted/50".to_string()
                                            on:click=on_row_click
                                        >
                                            <TableCell>
                                                {health_dot(&src.last_seen)}
                                            </TableCell>
                                            <TableCell class="font-mono text-xs".to_string()>
                                                {src.source_service.clone()}
                                            </TableCell>
                                            <TableCell class="font-mono text-xs text-muted-foreground".to_string()>
                                                <span title=src.tenant_id.clone()>{tenant_short}</span>
                                            </TableCell>
                                            <TableCell class="text-xs text-muted-foreground".to_string()>
                                                {src.host_url.clone().unwrap_or_else(|| "—".to_string())}
                                            </TableCell>
                                            <TableCell class="text-xs text-muted-foreground font-mono".to_string()>
                                                {src.version.clone().unwrap_or_else(|| "—".to_string())}
                                            </TableCell>
                                            <TableCell class="text-xs text-muted-foreground".to_string()>
                                                <span title=last_seen_abs>{last_seen_rel}</span>
                                            </TableCell>
                                            <TableCell class="text-xs".to_string()>
                                                {src.event_count}
                                            </TableCell>
                                        </TableRow>
                                    }
                                }
                            />
                        </TableBody>
                    </Table>
                }.into_any()
            }}
        </div>
    }
}
