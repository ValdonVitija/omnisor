use crate::{store::Store, unix_nanos};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsPartialSuccess, ExportMetricsServiceResponse,
};
use prost::Message;
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
use telemetry::{Configuration, ExportMetricsServiceRequest};

#[derive(Clone)]
pub(crate) struct IngestState {
    pub config: Arc<Configuration>,
    pub store: Arc<Mutex<Store>>,
    pub authorization: Arc<String>,
    pub synthetic: bool,
    pub started: std::time::Instant,
}

pub(crate) fn router(state: IngestState) -> Router {
    Router::new()
        .route("/v1/metrics", post(ingest))
        .route("/synthetic/metrics", get(crate::synthetic::exporter))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(state)
}

async fn ingest(State(state): State<IngestState>, headers: HeaderMap, body: Bytes) -> Response {
    let supplied = headers
        .get("authorization")
        .map(|h| h.as_bytes())
        .unwrap_or_default();
    if !bool::from(state.authorization.as_bytes().ct_eq(supplied)) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if headers.get("content-type").and_then(|h| h.to_str().ok()) != Some("application/x-protobuf")
        || headers
            .get("content-encoding")
            .is_some_and(|h| h != "identity")
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let request = match ExportMetricsServiceRequest::decode(body) {
        Ok(value) => value,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let received = unix_nanos();
    let batch = telemetry::normalize(&request, &state.config, "local", received);
    let mut store = state.store.lock().unwrap_or_else(|e| e.into_inner());
    let before = store.data.rejected;
    store.ingest(
        batch.observations,
        received,
        batch.rejected.len(),
        batch.ignored_points,
    );
    let rejected = store.data.rejected - before;
    let partial_success = (rejected > 0).then(|| ExportMetricsPartialSuccess {
        rejected_data_points: rejected as i64,
        error_message: "Some datapoints did not match the device profile or timestamp bounds"
            .into(),
    });
    (
        [("content-type", "application/x-protobuf")],
        ExportMetricsServiceResponse { partial_success }.encode_to_vec(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use opentelemetry_proto::tonic::metrics::v1::{
        Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, metric, number_data_point,
    };
    use tower::ServiceExt;
    fn state() -> IngestState {
        let catalog = crate::Catalog::bundled().unwrap();
        let device = crate::DeviceIdentity {
            id: "d1".into(),
            name: "test".into(),
            ..Default::default()
        };
        IngestState {
            config: Arc::new(catalog.normalization("synthetic", &device).unwrap()),
            store: Arc::new(Mutex::new(Store::new("d1".into(), 2))),
            authorization: Arc::new("Bearer session-test".into()),
            synthetic: false,
            started: std::time::Instant::now(),
        }
    }
    fn payload(device: &str, value: f64) -> Vec<u8> {
        ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                scope_metrics: vec![ScopeMetrics {
                    metrics: vec![Metric {
                        name: "omnisor_cpu_utilization_ratio".into(),
                        data: Some(metric::Data::Gauge(Gauge {
                            data_points: vec![NumberDataPoint {
                                attributes: vec![
                                    telemetry::string_attribute("device_id", device),
                                    telemetry::string_attribute("cpu", "0"),
                                ],
                                time_unix_nano: unix_nanos(),
                                value: Some(number_data_point::Value::AsDouble(value)),
                                ..Default::default()
                            }],
                        })),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec()
    }
    fn request(body: Vec<u8>, token: &str, encoding: &str) -> Request<Body> {
        Request::post("/v1/metrics")
            .header("content-type", "application/x-protobuf")
            .header("authorization", token)
            .header("content-encoding", encoding)
            .body(Body::from(body))
            .unwrap()
    }
    #[tokio::test]
    async fn unauthorized_invalid_and_compressed_requests_do_not_mutate_state() {
        let state = state();
        for (request, status) in [
            (
                request(payload("d1", 0.4), "Bearer wrong", "identity"),
                StatusCode::UNAUTHORIZED,
            ),
            (
                request(payload("d1", 0.4), "Bearer session-test", "gzip"),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                request(vec![255], "Bearer session-test", "identity"),
                StatusCode::BAD_REQUEST,
            ),
            (
                request(vec![0; 1024 * 1024 + 1], "Bearer session-test", "identity"),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            assert_eq!(
                router(state.clone())
                    .oneshot(request)
                    .await
                    .unwrap()
                    .status(),
                status
            );
        }
        assert_eq!(state.store.lock().unwrap().data.sequence, 0);
    }
    #[tokio::test]
    async fn accepted_points_use_local_identity_and_bad_profiles_get_otlp_partial_success() {
        let state = state();
        let response = router(state.clone())
            .oneshot(request(
                payload("d1", 0.4),
                "Bearer session-test",
                "identity",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            state.store.lock().unwrap().data.observations()[0].tenant_id,
            "local"
        );
        for (device, value) in [("unenrolled", 0.4), ("d1", 2.)] {
            let response = router(state.clone())
                .oneshot(request(
                    payload(device, value),
                    "Bearer session-test",
                    "identity",
                ))
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            assert_eq!(
                ExportMetricsServiceResponse::decode(body)
                    .unwrap()
                    .partial_success
                    .unwrap()
                    .rejected_data_points,
                1
            );
        }
    }
}
