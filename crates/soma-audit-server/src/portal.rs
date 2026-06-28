#[cfg(feature = "embed-dashboard")]
use rust_embed::RustEmbed;

#[cfg(feature = "embed-dashboard")]
#[derive(RustEmbed)]
#[folder = "../../dashboard/dist"]
pub struct Assets;

/// Stub handler used when `embed-dashboard` is not enabled.
#[cfg(not(feature = "embed-dashboard"))]
pub async fn portal_stub() -> axum::response::Response {
    use axum::{
        body::Body,
        http::{header, StatusCode},
        response::IntoResponse,
    };
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/html; charset=utf-8",
        )],
        Body::from(
            r#"<!doctype html><html><head><title>soma-audit</title></head>
<body><h1>soma-audit dashboard</h1><p>Build the dashboard to see the UI.</p></body></html>"#,
        ),
    )
        .into_response()
}
