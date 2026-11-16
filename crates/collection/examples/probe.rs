//! Exercise the same collection session as the desktop against a real exporter.
use collection::{
    Catalog, CollectionPlan, DeviceIdentity, Phase, Session, Source,
    access::{Credentials, DeviceTarget, RuntimeTools, SavedDevices},
};
use std::{
    fs::OpenOptions,
    time::{Duration, Instant},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("Usage: probe PROFILE METRICS_URL CAPTURE_JSON or probe --device DEVICE_ID CAPTURE_JSON (set OMNISOR_OTELCOL, OMNISOR_SNMP_EXPORTER, OMNISOR_DEVICES_FILE)".into());
    }
    let plan = if args[0] == "--device" {
        let catalog = Catalog::bundled()?;
        let devices = SavedDevices::discover(&catalog)?;
        catalog.plan_device(
            &DeviceTarget::Saved(args[1].clone()),
            &devices,
            Credentials::default(),
            &RuntimeTools::discover(),
        )?
    } else {
        let collector = std::env::var_os("OMNISOR_OTELCOL")
            .ok_or("Set OMNISOR_OTELCOL to the Collector executable")?
            .into();
        CollectionPlan {
            device: DeviceIdentity {
                id: "lab-ios-01".into(),
                name: "GNS3 IOS SNMP validation".into(),
                ..Default::default()
            },
            profile_id: args[0].clone(),
            interval_seconds: 10,
            collector,
            source: Source::Prometheus {
                endpoint: args[1].clone(),
                bearer_token: std::env::var("OMNISOR_SOURCE_TOKEN").unwrap_or_default(),
            },
        }
    };
    let session = Session::start(plan)?;
    let result = probe(&session, &args[2]);
    session.shutdown_blocking();
    result
}
fn probe(session: &Session, output: &str) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(100);
    loop {
        let snapshot = session.snapshot();
        if snapshot.phase == Phase::Failed {
            return Err(format!(
                "Collection failed: {:?}; {:?}",
                snapshot.error, snapshot.diagnostics
            )
            .into());
        }
        let metrics = &snapshot.metrics;
        let resources_ready = snapshot.profile_id != "cisco-iosvl2"
            || (metrics.latest_series("device.cpu.utilization").is_some()
                && metrics.latest_series("device.memory.utilization").is_some());
        if resources_ready
            && metrics.is_fresh(collection::unix_nanos(), snapshot.interval_seconds)
            && metrics
                .latest_series("interface.receive.bits_per_second")
                .is_some()
        {
            let observations = metrics.observations();
            let findings = telemetry::findings(&observations);
            let capture = serde_json::json!({"description":"Real GNS3 IOSvL2 native macOS SNMP exporter → native Collector → authenticated OTLP capture. No CLI output supplies these observations.","observations":observations,"findings":findings});
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            serde_json::to_writer_pretty(options.open(output)?, &capture)?;
            println!(
                "PASS: {} OTLP batches; {} normalized series; {} rejected points; real counter rates present",
                metrics.sequence,
                metrics.series.len(),
                metrics.rejected
            );
            for name in [
                "device.cpu.utilization",
                "device.memory.utilization",
                "device.info.name",
                "device.uptime.ticks",
            ] {
                println!(
                    "{name}: {}",
                    if metrics.latest_series(name).is_some() {
                        "available"
                    } else {
                        "not exposed by this device/profile"
                    }
                );
            }
            println!("Owned collection processes: {}", snapshot.process_ids.len());
            for metric in [
                "device.cpu.utilization",
                "device.memory.total",
                "device.memory.free",
                "device.memory.used",
                "device.memory.utilization",
            ] {
                if let Some(series) = metrics.latest_series(metric) {
                    println!(
                        "{metric}: {:?} {} (source: {})",
                        collection::store::numeric(&series.latest),
                        series.latest.unit,
                        series.latest.source_metric
                    );
                }
            }
            println!("Private capture written: {output}");
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!(
                "No successful two-scrape device collection: {}",
                metrics.scrape_state(collection::unix_nanos(), 30)
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
