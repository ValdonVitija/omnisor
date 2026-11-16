//! Drain child stderr without unbounded lines, logs, or secret exposure.
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use tokio::io::AsyncReadExt;

pub(crate) type Log = Arc<Mutex<VecDeque<String>>>;
pub(crate) fn start(
    mut stderr: tokio::process::ChildStderr,
    name: &'static str,
    secrets: Arc<Vec<String>>,
    log: Log,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = [0; 1024];
        let mut line = Vec::new();
        let mut oversized = false;
        loop {
            let count = match stderr.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(count) => count,
            };
            for byte in &buffer[..count] {
                if *byte == b'\n' {
                    let text = if oversized {
                        "Oversized component log line omitted".into()
                    } else {
                        redact(&String::from_utf8_lossy(&line), &secrets)
                    };
                    let mut log = log.lock().unwrap_or_else(|e| e.into_inner());
                    log.push_back(format!(
                        "{name}: {}",
                        text.chars().take(2048).collect::<String>()
                    ));
                    while log.len() > 24 {
                        log.pop_front();
                    }
                    line.clear();
                    oversized = false;
                } else if line.len() < 8192 {
                    line.push(*byte);
                } else {
                    oversized = true;
                }
            }
        }
    })
}
fn redact(line: &str, secrets: &[String]) -> String {
    let mut output = line.to_owned();
    // Longer secrets first; otherwise a short token could expose the suffix of another.
    let mut secrets = secrets.iter().filter(|s| !s.is_empty()).collect::<Vec<_>>();
    secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    for secret in secrets {
        output = output.replace(secret, "[redacted]");
    }
    output
}
#[cfg(test)]
mod tests {
    #[test]
    fn overlapping_credentials_are_redacted_before_bounding_display_text() {
        assert_eq!(
            super::redact("token=abcdefgh abc", &["abc".into(), "abcdefgh".into()]),
            "token=[redacted] [redacted]"
        );
    }
}
