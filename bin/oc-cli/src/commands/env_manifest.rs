use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use crate::CliError;

pub(crate) const PROJECT_MANIFEST_RELATIVE_PATH: &str = ".onecipher/environments.toml";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct EnvironmentManifest {
    #[serde(default = "default_manifest_version")]
    pub version: u32,
    #[serde(default)]
    pub default_environment: Option<String>,
    #[serde(default)]
    pub environments: BTreeMap<String, BTreeMap<String, String>>,
}

fn default_manifest_version() -> u32 {
    1
}

impl Default for EnvironmentManifest {
    fn default() -> Self {
        Self {
            version: default_manifest_version(),
            default_environment: Some("default".to_string()),
            environments: BTreeMap::new(),
        }
    }
}

impl EnvironmentManifest {
    pub(crate) fn load(path: &Path) -> Result<Self, CliError> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            CliError::InvalidArgs(format!(
                "failed to read environment manifest {}: {e}",
                path.display()
            ))
        })?;
        toml::from_str(&raw).map_err(|e| {
            CliError::InvalidArgs(format!(
                "failed to parse environment manifest {}: {e}",
                path.display()
            ))
        })
    }

    pub(crate) fn save(&self, path: &Path) -> Result<(), CliError> {
        let body = toml::to_string_pretty(self).map_err(|e| {
            CliError::InvalidArgs(format!("failed to render environment manifest: {e}"))
        })?;
        let parent = path.parent().ok_or_else(|| {
            CliError::InvalidArgs(format!(
                "environment manifest path has no parent: {}",
                path.display()
            ))
        })?;
        std::fs::create_dir_all(parent)?;
        oc_core::paths::write_atomic(path, body.as_bytes(), oc_core::paths::MODE_REGULAR_FILE)?;
        Ok(())
    }

    pub(crate) fn selected_environment_name<'a>(
        &'a self,
        requested: Option<&'a str>,
    ) -> Result<&'a str, CliError> {
        if let Some(name) = requested {
            if self.environments.contains_key(name) {
                return Ok(name);
            }
            return Err(CliError::InvalidArgs(format!(
                "environment '{name}' not found in manifest"
            )));
        }
        if let Some(default_environment) = self.default_environment.as_deref() {
            if self.environments.contains_key(default_environment) {
                return Ok(default_environment);
            }
        }
        if self.environments.len() == 1 {
            if let Some(environment) = self.environments.keys().next() {
                return Ok(environment.as_str());
            }
        }
        Err(CliError::InvalidArgs(
            "environment manifest requires --environment (no valid default_environment found)"
                .into(),
        ))
    }

    pub(crate) fn bindings_for(
        &self,
        requested: Option<&str>,
    ) -> Result<Vec<(String, String)>, CliError> {
        let env_name = self.selected_environment_name(requested)?;
        let env = self.environments.get(env_name).ok_or_else(|| {
            CliError::InvalidArgs(format!("environment '{env_name}' not found in manifest"))
        })?;
        Ok(env.iter().map(|(key, value)| (key.clone(), value.clone())).collect())
    }

    pub(crate) fn upsert_bindings(&mut self, environment: &str, bindings: &[(String, String)]) {
        let env = self.environments.entry(environment.to_string()).or_default();
        for (key, value) in bindings {
            env.insert(key.clone(), value.clone());
        }
        if self.default_environment.is_none() {
            self.default_environment = Some(environment.to_string());
        }
    }
}

pub(crate) fn discover_manifest(start_dir: &Path) -> Option<PathBuf> {
    for dir in start_dir.ancestors() {
        let candidate = dir.join(PROJECT_MANIFEST_RELATIVE_PATH);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

pub(crate) fn resolve_manifest_path(explicit: Option<&Path>) -> Result<PathBuf, CliError> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir()?;
    discover_manifest(&cwd).ok_or_else(|| {
        CliError::InvalidArgs(format!(
            "no environment manifest found (expected {} in the current directory or a parent)",
            PROJECT_MANIFEST_RELATIVE_PATH
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_environment_prefers_explicit_then_default() {
        let mut manifest = EnvironmentManifest::default();
        manifest.environments.insert("dev".into(), BTreeMap::new());
        manifest.environments.insert("prod".into(), BTreeMap::new());
        manifest.default_environment = Some("dev".into());

        assert_eq!(manifest.selected_environment_name(Some("prod")).unwrap(), "prod");
        assert_eq!(manifest.selected_environment_name(None).unwrap(), "dev");
    }
}
