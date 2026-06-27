//! Audit Events page — the main view for browsing the append-only audit log.
//!
//! Filters wired to the server API: tenant_id (from shell), event_type, source_service,
//! from, to (date range), cursor, limit.

use crate::api::{get_audit, AuditRecord, Page};
use crate::app::AppCtx;
use crate::util::relative_time;
use leptos::prelude::*;
use soma_ui::{
    Alert, AlertDescription, AlertTitle, AlertVariant, Badge, BadgeVariant, Button, ButtonSize,
    ButtonVariant, Empty, Input, PageHeader, Spinner, Table, TableBody, TableCell, TableHead,
    TableHeader, TableRow,
};

fn outcome_badge(outcome: &str) -> impl IntoView {
    let label = outcome.to_string();
    let variant = match outcome {
        "success" => BadgeVariant::Success,
        "denied" | "error" => BadgeVariant::Destructive,
        _ => BadgeVariant::Secondary,
    };
    view! { <Badge variant=variant>{label}</Badge> }
}

fn event_type_badge(event_type: &str) -> impl IntoView {
    let label = event_type.to_string();
    let variant = if event_type.contains("delete") || event_type.contains("revoke") {
        BadgeVariant::Destructive
    } else if event_type.contains("write") || event_type.contains("create") {
        BadgeVariant::Default
    } else {
        BadgeVariant::Secondary
    };
    view! { <Badge variant=variant>{label}</Badge> }
}

fn short_id(id: &str) -> String {
    if id.len() > 8 {
        format!("{}…", &id[..8])
    } else {
        id.to_string()
    }
}

#[component]
pub fn AuditPage() -> impl IntoView {
    let ctx = use_context::<AppCtx>().expect("AppCtx required");

    let event_type_filter = RwSignal::new(String::new());
    let source_service_filter = RwSignal::new(String::new());
    let from_filter = RwSignal::new(String::new());
    let to_filter = RwSignal::new(String::new());
    let cursor: RwSignal<Option<i64>> = RwSignal::new(None);
    let events: RwSignal<Vec<AuditRecord>> = RwSignal::new(vec![]);
    let next_cursor: RwSignal<Option<i64>> = RwSignal::new(None);
    let load_err: RwSignal<Option<(u16, String)>> = RwSignal::new(None);
    let loading = RwSignal::new(false);
    let initial_loaded = RwSignal::new(false);

    let load_events = move |append: bool| {
        // Read untracked: `load_events` runs from non-reactive contexts (button
        // clicks, the debounced task). The Effect below owns the reactive deps.
        let token = ctx.token.get_untracked();
        let tenant = ctx.tenant_id.get_untracked();
        if tenant.is_empty() {
            load_err.set(Some((
                0,
                "Enter a tenant ID in the header to load events.".to_string(),
            )));
            initial_loaded.set(true);
            return;
        }
        let et = event_type_filter.get_untracked();
        let ss = source_service_filter.get_untracked();
        let from = from_filter.get_untracked();
        let to = to_filter.get_untracked();
        let cur = if append { cursor.get_untracked() } else { None };
        loading.set(true);
        load_err.set(None);
        leptos::task::spawn_local(async move {
            match get_audit(
                &token,
                &tenant,
                if et.is_empty() { None } else { Some(&et) },
                if ss.is_empty() { None } else { Some(&ss) },
                if from.is_empty() { None } else { Some(&from) },
                if to.is_empty() { None } else { Some(&to) },
                cur,
                50,
            )
            .await
            {
                Ok(Page {
                    items,
                    next_cursor: nc,
                }) => {
                    if append {
                        events.update(|v| v.extend(items));
                    } else {
                        events.set(items);
                    }
                    next_cursor.set(nc);
                    cursor.set(nc);
                    initial_loaded.set(true);
                }
                Err(e) => {
                    load_err.set(Some((e.status, e.message)));
                    initial_loaded.set(true);
                }
            }
            loading.set(false);
        });
    };

    let on_apply = move |_| {
        cursor.set(None);
        events.set(vec![]);
        next_cursor.set(None);
        initial_loaded.set(false);
        load_events(false);
    };

    // Auto-load when both token and tenant_id become non-empty (fixes no-token 401 on mount
    // and auto-loads when navigating from Sources with a pre-filled tenant).
    // Debounced 400 ms so rapid keystrokes don't fire real queries on every character.
    Effect::new(move |_| {
        let t = ctx.token.get();
        let tenant = ctx.tenant_id.get();
        if t.is_empty() || tenant.is_empty() {
            return;
        }
        let token_at_trigger = t.clone();
        let tenant_at_trigger = tenant.clone();
        let load_events = load_events.clone();
        leptos::task::spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(400).await;
            if ctx.token.get_untracked() == token_at_trigger
                && ctx.tenant_id.get_untracked() == tenant_at_trigger
            {
                cursor.set(None);
                events.set(vec![]);
                next_cursor.set(None);
                initial_loaded.set(false);
                load_events(false);
            }
        });
    });

    view! {
        <div class="space-y-6">
            <PageHeader title="Audit Events".to_string()>
                <Button
                    variant=ButtonVariant::Default
                    size=ButtonSize::Sm
                    on:click=on_apply
                >
                    "Load events"
                </Button>
            </PageHeader>

            // Filters
            <div class="flex items-center gap-3 flex-wrap">
                <div class="w-56">
                    <Input
                        value=event_type_filter
                        placeholder="event_type filter".to_string()
                    />
                </div>
                <div class="w-48">
                    <Input
                        value=source_service_filter
                        placeholder="source_service filter".to_string()
                    />
                </div>
                <div class="w-44">
                    <Input
                        value=from_filter
                        placeholder="from (RFC3339)".to_string()
                    />
                </div>
                <div class="w-44">
                    <Input
                        value=to_filter
                        placeholder="to (RFC3339)".to_string()
                    />
                </div>
                <Button
                    variant=ButtonVariant::Outline
                    size=ButtonSize::Sm
                    on:click=on_apply
                >
                    "Apply"
                </Button>
            </div>

            // Error state
            {move || load_err.get().map(|(status, msg)| {
                let (title, body) = if status == 401 {
                    ("Unauthorized", "Check your admin token in the header.".to_string())
                } else if status == 0 {
                    ("Configuration", msg.clone())
                } else {
                    ("Failed to load events", msg.clone())
                };
                view! {
                    <Alert variant=AlertVariant::Destructive>
                        <AlertTitle>{title}</AlertTitle>
                        <AlertDescription>{body}</AlertDescription>
                    </Alert>
                }
            })}

            // Table / empty / loading
            {move || {
                if !initial_loaded.get() && loading.get() {
                    return view! { <div class="flex justify-center py-8"><Spinner /></div> }.into_any();
                }
                if initial_loaded.get() && events.get().is_empty() && load_err.get().is_none() {
                    return view! {
                        <Empty
                            title="No audit events".to_string()
                            description="No events found for this tenant and filter combination.".to_string()
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="text-muted-foreground/40">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                                <polyline points="14 2 14 8 20 8"/>
                                <line x1="16" y1="13" x2="8" y2="13"/>
                                <line x1="16" y1="17" x2="8" y2="17"/>
                                <polyline points="10 9 9 9 8 9"/>
                            </svg>
                        </Empty>
                    }.into_any();
                }
                if events.get().is_empty() {
                    return ().into_any();
                }
                view! {
                    <div class="space-y-4">
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead class="w-16".to_string()>"#"</TableHead>
                                    <TableHead>"Time"</TableHead>
                                    <TableHead>"Service"</TableHead>
                                    <TableHead>"Event"</TableHead>
                                    <TableHead>"Actor"</TableHead>
                                    <TableHead>"Resource"</TableHead>
                                    <TableHead>"Outcome"</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                <For
                                    each=move || events.get()
                                    key=|e| e.id.clone()
                                    children=move |ev| {
                                        let ts = ev.occurred_at.clone();
                                        let rel = relative_time(&ts);
                                        let actor_display = match (&ev.actor_id, &ev.actor_role) {
                                            (Some(id), Some(role)) => format!("{} ({})", short_id(id), role),
                                            (Some(id), None) => short_id(id),
                                            (None, Some(role)) => role.clone(),
                                            _ => "—".to_string(),
                                        };
                                        let resource_display = match (&ev.resource_type, &ev.resource_id) {
                                            (Some(rt), Some(rid)) => format!("{}/{}", rt, rid),
                                            (Some(rt), None) => rt.clone(),
                                            _ => "—".to_string(),
                                        };
                                        let event_type = ev.event_type.clone();
                                        let outcome = ev.outcome.clone();
                                        let service = ev.source_service.clone();
                                        view! {
                                            <TableRow>
                                                <TableCell class="text-xs text-muted-foreground font-mono".to_string()>
                                                    {ev.seq_num}
                                                </TableCell>
                                                <TableCell class="text-xs text-muted-foreground".to_string()>
                                                    <span title=ts>{rel}</span>
                                                </TableCell>
                                                <TableCell class="text-xs text-muted-foreground font-mono".to_string()>
                                                    {service}
                                                </TableCell>
                                                <TableCell>
                                                    {event_type_badge(&event_type)}
                                                </TableCell>
                                                <TableCell class="text-xs font-mono text-muted-foreground".to_string()>
                                                    {actor_display}
                                                </TableCell>
                                                <TableCell class="text-xs text-muted-foreground max-w-[180px] truncate".to_string()>
                                                    <span title=resource_display.clone()>{resource_display.clone()}</span>
                                                </TableCell>
                                                <TableCell>
                                                    {outcome_badge(&outcome)}
                                                </TableCell>
                                            </TableRow>
                                        }
                                    }
                                />
                            </TableBody>
                        </Table>

                        {move || next_cursor.get().map(|_| view! {
                            <div class="flex justify-center pt-2">
                                <Button
                                    variant=ButtonVariant::Outline
                                    size=ButtonSize::Sm
                                    on:click=move |_| load_events(true)
                                >
                                    {move || if loading.get() {
                                        view! { <span class="flex items-center gap-2"><Spinner />"Loading…"</span> }.into_any()
                                    } else {
                                        view! { <span>"Load more"</span> }.into_any()
                                    }}
                                </Button>
                            </div>
                        })}
                    </div>
                }.into_any()
            }}
        </div>
    }
}
