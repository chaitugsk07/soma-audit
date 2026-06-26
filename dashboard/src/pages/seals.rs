//! Seals page — table of chain seals for the selected tenant.
//!
//! Each seal is an Ed25519 signature over the chain head hash at a given sequence number,
//! providing external verifiability: anyone with the public key can verify the seal
//! without needing access to the live server.

use crate::api::{get_seals, SealRecord, Page};
use crate::app::AppCtx;
use crate::util::relative_time;
use leptos::prelude::*;
use soma_ui::{
    Alert, AlertDescription, AlertTitle, AlertVariant, Button, ButtonSize, ButtonVariant, Empty,
    PageHeader, Spinner, Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
};

fn truncate_hash(h: &str) -> String {
    if h.len() > 16 { format!("{}…", &h[..16]) } else { h.to_string() }
}

#[component]
pub fn SealsPage() -> impl IntoView {
    let ctx = use_context::<AppCtx>().expect("AppCtx required");
    let seals: RwSignal<Vec<SealRecord>> = RwSignal::new(vec![]);
    let next_cursor: RwSignal<Option<i64>> = RwSignal::new(None);
    let cursor: RwSignal<Option<i64>> = RwSignal::new(None);
    let load_err: RwSignal<Option<(u16, String)>> = RwSignal::new(None);
    let loading = RwSignal::new(false);
    let initial_loaded = RwSignal::new(false);

    let load_seals = move |append: bool| {
        let token = ctx.token.get();
        let tenant = ctx.tenant_id.get();
        if tenant.is_empty() {
            load_err.set(Some((0, "Enter a tenant ID in the header to load seals.".to_string())));
            initial_loaded.set(true);
            return;
        }
        let cur = if append { cursor.get() } else { None };
        loading.set(true);
        load_err.set(None);
        leptos::task::spawn_local(async move {
            match get_seals(&token, &tenant, cur).await {
                Ok(Page { items, next_cursor: nc }) => {
                    if append {
                        seals.update(|v| v.extend(items));
                    } else {
                        seals.set(items);
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

    let on_load = move |_| {
        cursor.set(None);
        seals.set(vec![]);
        next_cursor.set(None);
        initial_loaded.set(false);
        load_seals(false);
    };

    view! {
        <div class="space-y-6">
            <PageHeader
                title="Chain Seals".to_string()
                subtitle=Some(
                    "Each seal is an Ed25519 signature over the chain head hash, enabling external verification without server access.".to_string()
                )
            >
                <Button
                    variant=ButtonVariant::Default
                    size=ButtonSize::Sm
                    on:click=on_load
                >
                    "Load seals"
                </Button>
            </PageHeader>

            // Error
            {move || load_err.get().map(|(status, msg)| {
                let (title, body) = if status == 401 {
                    ("Unauthorized", "Check your admin token in the header.".to_string())
                } else if status == 0 {
                    ("Configuration", msg.clone())
                } else {
                    ("Failed to load seals", msg.clone())
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
                if initial_loaded.get() && seals.get().is_empty() && load_err.get().is_none() {
                    return view! {
                        <Empty
                            title="No seals yet".to_string()
                            description="Seals are created when the server periodically snapshots the chain head.".to_string()
                        />
                    }.into_any();
                }
                if seals.get().is_empty() {
                    return ().into_any();
                }
                view! {
                    <div class="space-y-4">
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>"Up to seq #"</TableHead>
                                    <TableHead>"Chain head hash"</TableHead>
                                    <TableHead>"Sealed at"</TableHead>
                                    <TableHead>"Key ID"</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                <For
                                    each=move || seals.get()
                                    key=|s| s.id.clone()
                                    children=move |seal| {
                                        let ts = seal.sealed_at.clone();
                                        let rel = relative_time(&ts);
                                        let hash_short = truncate_hash(&seal.chain_head_hash);
                                        let hash_full = seal.chain_head_hash.clone();
                                        let kid = seal.public_key_id.clone();
                                        view! {
                                            <TableRow>
                                                <TableCell class="font-mono text-xs".to_string()>
                                                    {seal.up_to_seq_num}
                                                </TableCell>
                                                <TableCell class="font-mono text-xs text-muted-foreground".to_string()>
                                                    <span title=hash_full>{hash_short}</span>
                                                </TableCell>
                                                <TableCell class="text-xs text-muted-foreground".to_string()>
                                                    <span title=ts>{rel}</span>
                                                </TableCell>
                                                <TableCell class="font-mono text-xs text-muted-foreground".to_string()>
                                                    {kid}
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
                                    on:click=move |_| load_seals(true)
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
