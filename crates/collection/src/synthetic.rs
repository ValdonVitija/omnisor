use crate::ingest::IngestState;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub(crate) async fn exporter(State(state): State<IngestState>) -> Response {
    if !state.synthetic {
        return StatusCode::NOT_FOUND.into_response();
    }
    let elapsed = state.started.elapsed().as_secs_f64();
    let cpu = 0.48 + (elapsed / 11.).sin() * 0.31;
    let memory = 58_000_000. + (elapsed / 17.).sin() * 10_000_000.;
    let rx = (elapsed * 250_000. + 180_000. * (1. - (elapsed / 9.).cos())) as u64;
    let tx = (elapsed * 135_000. + 120_000. * (1. - (elapsed / 13.).cos())) as u64;
    let body = format!(
        r#"# TYPE omnisor_cpu_utilization_ratio gauge
omnisor_cpu_utilization_ratio{{cpu="0"}} {cpu}
# TYPE omnisor_memory_used_bytes gauge
omnisor_memory_used_bytes{{pool="Processor"}} {memory}
# TYPE omnisor_memory_free_bytes gauge
omnisor_memory_free_bytes{{pool="Processor"}} {free}
# TYPE omnisor_interface_admin_status gauge
omnisor_interface_admin_status{{interface="GigabitEthernet0/1"}} 1
omnisor_interface_admin_status{{interface="GigabitEthernet0/2"}} 2
# TYPE omnisor_interface_oper_status gauge
omnisor_interface_oper_status{{interface="GigabitEthernet0/1"}} 1
omnisor_interface_oper_status{{interface="GigabitEthernet0/2"}} 2
# TYPE omnisor_interface_receive_bytes_total counter
omnisor_interface_receive_bytes_total{{interface="GigabitEthernet0/1"}} {rx}
# TYPE omnisor_interface_transmit_bytes_total counter
omnisor_interface_transmit_bytes_total{{interface="GigabitEthernet0/1"}} {tx}
"#,
        free = 100_000_000. - memory
    );
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}
