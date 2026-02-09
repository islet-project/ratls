use axum::{Router, body::Body, extract, http, response::IntoResponse, routing};
use axum_extra::{TypedHeader, headers::Range};
use hyper::Response;
use log::{debug, error, info};
use std::{ops::Bound, sync::Arc};
use tokio::{io::AsyncSeekExt, sync::RwLock};
use tokio_util::io::ReaderStream;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

use crate::GenericResult;
use crate::files::{FilesProvider, Payload};
use crate::tls::{self, Config, Protocol};

static NOT_FOUND: (http::StatusCode, &str) = (
    http::StatusCode::NOT_FOUND,
    "In the beginning there was darkness... Or was it 404? I can't remember.",
);

type SafeFiles = Arc<RwLock<dyn FilesProvider>>;

pub async fn run<T: FilesProvider + 'static>(files: T, config: Config) -> GenericResult<()>
{
    let files = Arc::new(RwLock::new(files));

    let app = Router::new()
        .route("/{*address}", routing::get(get_file))
        .with_state(files)
        .fallback(fallback)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

    let address = format!("0.0.0.0:{}", config.port);
    debug!("Binding address: {}", address);
    let listener = tokio::net::TcpListener::bind(address).await?;

    match config.tls {
        Protocol::NoTLS => axum::serve(listener, app).await?,
        Protocol::TLS => tls::serve_tls(listener, app, config).await?,
        Protocol::RaTLS => tls::serve_ratls(listener, app, config).await?,
    }

    Ok(())
}

async fn fallback() -> (http::StatusCode, &'static str)
{
    NOT_FOUND
}

async fn get_file(
    extract::State(files): extract::State<SafeFiles>,
    extract::Path(address): extract::Path<String>,
    range: Option<TypedHeader<Range>>,
) -> impl IntoResponse
{
    let files = files.read().await;
    info!("Handling request: {}", address);

    let payload = files.get_payload(&address).await;
    let Some(payload) = payload else {
        return NOT_FOUND.into_response();
    };

    serve_file(payload, range).await
}

fn range_not_acceptable(payload: Payload) -> Response<Body>
{
    let headers = [(
        http::header::CONTENT_RANGE,
        &format!("bytes */{}", payload.size),
    )];
    let body = Body::empty();
    (http::StatusCode::NOT_ACCEPTABLE, headers, body).into_response()
}

async fn serve_file(mut payload: Payload, range: Option<TypedHeader<Range>>) -> Response<Body>
{
    let Some(TypedHeader(range)) = range else {
        let headers = [
            (http::header::CONTENT_TYPE, &payload.media_type),
            (http::header::CONTENT_LENGTH, &format!("{}", payload.size)),
        ];
        let body = Body::from_stream(ReaderStream::new(payload.file));
        return (headers, body).into_response();
    };

    let ranges: Vec<_> = range.satisfiable_ranges(payload.size).collect();
    if ranges.is_empty() {
        error!("Ranges are not satisfiable");
        return range_not_acceptable(payload);
    }

    match (ranges.len(), ranges[0]) {
        // very basic implementation of "range: bytes=SKIP-" client header
        (1, (Bound::Included(skip), Bound::Unbounded)) => {
            debug!("Simple \"range: bytes={}-\" requested", skip);
            if let Err(e) = payload.file.seek(std::io::SeekFrom::Start(skip)).await {
                error!("Error seeking file: {}", e);
                return range_not_acceptable(payload);
            };

            let body = Body::from_stream(ReaderStream::new(payload.file));
            let headers = [
                (http::header::CONTENT_TYPE, &payload.media_type),
                (
                    http::header::CONTENT_LENGTH,
                    &format!("{}", payload.size - skip),
                ),
                (
                    http::header::CONTENT_RANGE,
                    &format!("bytes {}-{}/{}", skip, payload.size - 1, payload.size),
                ),
            ];
            (http::StatusCode::PARTIAL_CONTENT, headers, body).into_response()
        }
        // reject all the other variants of partial content or multi-parts
        _ => {
            error!("Only a simple \"range: bytes=SKIP-\" is supported");
            range_not_acceptable(payload)
        }
    }
}
