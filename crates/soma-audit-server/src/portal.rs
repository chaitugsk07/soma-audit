use axum::{
    body::Body,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};

#[cfg(feature = "embed-dashboard")]
use rust_embed::RustEmbed;

#[cfg(feature = "embed-dashboard")]
#[derive(RustEmbed)]
#[folder = "../../dashboard/dist"]
struct Assets;

#[cfg(feature = "embed-dashboard")]
fn mime_for_path(path: &str) -> &'static str {
    if path.ends_with(".js") {
        "application/javascript"
    } else if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else if path.ends_with(".woff2") {
        "font/woff2"
    } else if path.ends_with(".wasm") {
        "application/wasm"
    } else {
        "application/octet-stream"
    }
}

pub async fn portal_handler(uri: Uri) -> impl IntoResponse {
    #[cfg(feature = "embed-dashboard")]
    {
        let path = uri.path().trim_start_matches('/');

        if !path.is_empty() {
            if let Some(content) = Assets::get(path) {
                let mime = mime_for_path(path);
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, mime)
                    .body(Body::from(content.data.into_owned()))
                    .unwrap();
            }
        }

        if let Some(content) = Assets::get("index.html") {
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(Body::from(content.data.into_owned()))
                .unwrap();
        }
    }

    #[cfg(not(feature = "embed-dashboard"))]
    let _ = uri;

    let stub = r#"<!doctype html><html><head><title>soma-audit</title></head>
<body><h1>soma-audit dashboard</h1><p>Build the dashboard to see the UI.</p></body></html>"#;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(stub))
        .unwrap()
}
