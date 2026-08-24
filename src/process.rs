use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

const MAX_CAPTURED_ERROR_BYTES: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandPlan {
    pub program: String,
    pub args: Vec<String>,
}

impl CommandPlan {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
        }
    }

    pub fn arg(mut self, value: impl Into<String>) -> Self {
        self.args.push(value.into());
        self
    }

    pub fn args<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(values.into_iter().map(Into::into));
        self
    }

    pub fn display_safe(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub fn capture(plan: &CommandPlan) -> Result<String> {
    let output = Command::new(&plan.program)
        .args(&plan.args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("execute {}", plan.display_safe()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{} failed: {}", plan.display_safe(), stderr.trim());
    }
    String::from_utf8(output.stdout).context("command emitted non-UTF-8 output")
}

/// Capture a command whose arguments are too large or sensitive for error
/// diagnostics. Only the caller-supplied safe label and a bounded stderr tail
/// are retained on failure.
pub fn capture_named(plan: &CommandPlan, label: &str) -> Result<String> {
    let output = Command::new(&plan.program)
        .args(&plan.args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("execute {label}"))?;
    if !output.status.success() {
        let start = output.stderr.len().saturating_sub(MAX_CAPTURED_ERROR_BYTES);
        let stderr = String::from_utf8_lossy(&output.stderr[start..]);
        let detail = stderr.trim();
        if detail.is_empty() {
            bail!("{label} failed with {}", output.status);
        }
        bail!("{label} failed: {detail}");
    }
    String::from_utf8(output.stdout).with_context(|| format!("{label} emitted non-UTF-8 output"))
}

pub fn inherit(plan: &CommandPlan) -> Result<()> {
    let status = Command::new(&plan.program)
        .args(&plan.args)
        .stdin(Stdio::null())
        .status()
        .with_context(|| format!("execute {}", plan.display_safe()))?;
    if !status.success() {
        bail!("{} failed with {status}", plan.display_safe());
    }
    Ok(())
}

/// Execute a secret-bearing provider command without inheriting or retaining
/// provider output. Some CLIs echo rejected input in diagnostics, so failures
/// expose only the already-safe command plan.
pub fn with_secret_stdin(plan: &CommandPlan, stdin: &[u8]) -> Result<()> {
    let mut child = Command::new(&plan.program)
        .args(&plan.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("execute {}", plan.display_safe()))?;
    child
        .stdin
        .take()
        .context("open child stdin")?
        .write_all(stdin)?;
    let status = child.wait()?;
    if !status.success() {
        bail!(
            "{} failed; provider output was suppressed because the operation carried secret input",
            plan.display_safe()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_capture_does_not_repeat_command_arguments() {
        let plan = CommandPlan::new("sh").args([
            "-c",
            "printf 'safe-stage-marker\\n' >&2; exit 9",
            "argument-that-must-not-be-reported",
        ]);
        let error = capture_named(&plan, "remote activation")
            .unwrap_err()
            .to_string();
        assert!(error.contains("remote activation failed"));
        assert!(error.contains("safe-stage-marker"));
        assert!(!error.contains("argument-that-must-not-be-reported"));
    }
}
