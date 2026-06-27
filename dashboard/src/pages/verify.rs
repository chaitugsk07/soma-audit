//! Verify page — walks the entire chain for the selected tenant and reports integrity.
//!
//! NOTE: For large chains this is a full sequential walk on the server.
//! A progress UX (SSE / streaming) is a future improvement once the server supports it.

use crate::api::{verify_chain, VerifyResult};
use crate::app::AppCtx;
use leptos::prelude::*;
use soma_ui::{
    Alert, AlertDescription, AlertTitle, AlertVariant, Button, ButtonSize, ButtonVariant,
    PageHeader, Spinner,
};

#[component]
pub fn VerifyPage() -> impl IntoView {
    let ctx = use_context::<AppCtx>().expect("AppCtx required");
    let verifying = RwSignal::new(false);
    let result: RwSignal<Option<Result<VerifyResult, String>>> = RwSignal::new(None);

    let on_verify = move |_| {
        let token = ctx.token.get();
        let tenant = ctx.tenant_id.get();
        if tenant.is_empty() {
            result.set(Some(Err(
                "Enter a tenant ID in the header first.".to_string()
            )));
            return;
        }
        verifying.set(true);
        result.set(None);
        leptos::task::spawn_local(async move {
            let r = verify_chain(&token, &tenant).await.map_err(|e| {
                if e.status == 401 {
                    "Unauthorized — check your admin token.".to_string()
                } else {
                    e.message
                }
            });
            result.set(Some(r));
            verifying.set(false);
        });
    };

    view! {
        <div class="space-y-6">
            <PageHeader
                title="Verify Chain".to_string()
                subtitle=Some("Walk the append-only chain and verify every hash link for the selected tenant.".to_string())
            >
                <Button
                    variant=ButtonVariant::Default
                    size=ButtonSize::Sm
                    on:click=on_verify
                >
                    {move || if verifying.get() {
                        view! { <span class="flex items-center gap-2"><Spinner />"Verifying…"</span> }.into_any()
                    } else {
                        view! { <span>"Verify chain"</span> }.into_any()
                    }}
                </Button>
            </PageHeader>

            // Instructions when idle
            {move || result.get().is_none().then(|| view! {
                <Alert variant=AlertVariant::Info>
                    <AlertTitle>"How verification works"</AlertTitle>
                    <AlertDescription>
                        "Each audit entry includes a hash of the previous entry, forming a tamper-evident chain. \
                        Verification walks every entry for the tenant and confirms the hashes are unbroken. \
                        For large chains this may take a moment."
                    </AlertDescription>
                </Alert>
            })}

            // Result
            {move || result.get().map(|r| match r {
                Ok(v) => if v.ok {
                    if v.entries_checked == 0 {
                        view! {
                            <Alert variant=AlertVariant::Info>
                                <AlertTitle>"No chain yet"</AlertTitle>
                                <AlertDescription>
                                    "No audit events have been recorded for this tenant yet — nothing to verify."
                                </AlertDescription>
                            </Alert>
                        }.into_any()
                    } else {
                    view! {
                        <Alert variant=AlertVariant::Success>
                            <AlertTitle>
                                <span class="text-green-600 dark:text-green-400">
                                    "Chain intact"
                                </span>
                            </AlertTitle>
                            <AlertDescription>
                                {format!("{} entries verified — the chain is unbroken.", v.entries_checked)}
                            </AlertDescription>
                        </Alert>
                    }.into_any()
                    }
                } else {
                    view! {
                        <Alert variant=AlertVariant::Destructive>
                            <AlertTitle>"Chain integrity failure"</AlertTitle>
                            <AlertDescription>
                                {match v.first_broken_seq {
                                    Some(seq) => format!(
                                        "Chain broken at entry #{} — possible tampering or data corruption. \
                                         Checked {} entries before the break.",
                                        seq, v.entries_checked
                                    ),
                                    None => format!(
                                        "Integrity check failed after {} entries.",
                                        v.entries_checked
                                    ),
                                }}
                            </AlertDescription>
                        </Alert>
                    }.into_any()
                },
                Err(e) => view! {
                    <Alert variant=AlertVariant::Destructive>
                        <AlertTitle>"Verification failed"</AlertTitle>
                        <AlertDescription>{e}</AlertDescription>
                    </Alert>
                }.into_any(),
            })}
        </div>
    }
}
