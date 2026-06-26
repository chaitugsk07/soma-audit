//! Keys page — show the server's Ed25519 public keys so external verifiers can copy them.

use crate::api::{get_keys, PublicKey};
use crate::app::AppCtx;
use crate::util::copy_to_clipboard;
use leptos::prelude::*;
use soma_ui::{
    Alert, AlertDescription, AlertTitle, AlertVariant, Button, ButtonSize, ButtonVariant, Empty,
    PageHeader, Spinner,
};

#[component]
fn KeyCard(key: PublicKey) -> impl IntoView {
    let copy_label = RwSignal::new("Copy");
    let x = key.x.clone();

    view! {
        <div class="rounded-lg border border-border bg-card p-4 space-y-3">
            <div class="flex items-center justify-between gap-2">
                <div class="space-y-0.5">
                    <p class="text-xs text-muted-foreground font-mono">"kid"</p>
                    <p class="text-sm font-medium font-mono">{key.kid.clone()}</p>
                </div>
                <div class="flex items-center gap-2 text-xs text-muted-foreground">
                    <span class="rounded-sm border border-border px-1.5 py-0.5 font-mono">{key.kty.clone()}</span>
                    <span class="rounded-sm border border-border px-1.5 py-0.5 font-mono">{key.crv.clone()}</span>
                </div>
            </div>
            <div class="space-y-1">
                <p class="text-xs text-muted-foreground font-mono">"x (base64url public key)"</p>
                <div class="flex items-center gap-2">
                    <code class="flex-1 block rounded bg-muted px-2 py-1.5 text-xs font-mono break-all text-foreground">
                        {key.x.clone()}
                    </code>
                    <Button
                        variant=ButtonVariant::Outline
                        size=ButtonSize::Sm
                        on:click=move |_| copy_to_clipboard(x.clone(), copy_label)
                    >
                        {move || copy_label.get()}
                    </Button>
                </div>
            </div>
        </div>
    }
}

#[component]
pub fn KeysPage() -> impl IntoView {
    let ctx = use_context::<AppCtx>().expect("AppCtx required");
    let keys: RwSignal<Vec<PublicKey>> = RwSignal::new(vec![]);
    let load_err: RwSignal<Option<(u16, String)>> = RwSignal::new(None);
    let loading = RwSignal::new(false);
    let loaded = RwSignal::new(false);

    let load_keys = move |_| {
        let token = ctx.token.get();
        loading.set(true);
        load_err.set(None);
        leptos::task::spawn_local(async move {
            match get_keys(&token).await {
                Ok(resp) => {
                    keys.set(resp.keys);
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

    view! {
        <div class="space-y-6">
            <PageHeader
                title="Signing Keys".to_string()
                subtitle=Some(
                    "Ed25519 public keys used to sign chain seals. Copy these for external verification.".to_string()
                )
            >
                <Button
                    variant=ButtonVariant::Default
                    size=ButtonSize::Sm
                    on:click=load_keys
                >
                    "Load keys"
                </Button>
            </PageHeader>

            // Error
            {move || load_err.get().map(|(status, msg)| {
                let (title, body) = if status == 401 {
                    ("Unauthorized", "Check your admin token in the header.".to_string())
                } else {
                    ("Failed to load keys", msg.clone())
                };
                view! {
                    <Alert variant=AlertVariant::Destructive>
                        <AlertTitle>{title}</AlertTitle>
                        <AlertDescription>{body}</AlertDescription>
                    </Alert>
                }
            })}

            // Loading
            {move || (loading.get() && !loaded.get()).then(|| view! {
                <div class="flex justify-center py-8"><Spinner /></div>
            })}

            // Key cards / empty
            {move || {
                if !loaded.get() {
                    return ().into_any();
                }
                let k = keys.get();
                if k.is_empty() {
                    return view! {
                        <Empty
                            title="No keys found".to_string()
                            description="The server has no signing keys configured.".to_string()
                        />
                    }.into_any();
                }
                view! {
                    <div class="space-y-3">
                        <For
                            each=move || keys.get()
                            key=|k| k.kid.clone()
                            children=move |k| view! { <KeyCard key=k /> }
                        />
                    </div>
                }.into_any()
            }}
        </div>
    }
}
