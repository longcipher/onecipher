use zeroize::Zeroizing;

use crate::CliError;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct SecretReference {
    pub name: String,
    pub field: SecretReferenceField,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SecretReferenceField {
    Secret,
    Notes,
    Otp,
    Metadata,
}

impl SecretReferenceField {
    pub(crate) fn parse(raw: &str) -> Result<Self, CliError> {
        match raw.trim() {
            "secret" => Ok(Self::Secret),
            "notes" => Ok(Self::Notes),
            "otp" => Ok(Self::Otp),
            "metadata" => Ok(Self::Metadata),
            other => Err(CliError::InvalidArgs(format!(
                "invalid reference field '{other}' (expected: secret, notes, otp, metadata)"
            ))),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Notes => "notes",
            Self::Otp => "otp",
            Self::Metadata => "metadata",
        }
    }
}

pub(crate) fn parse_secret_reference(raw: &str) -> Result<SecretReference, CliError> {
    let rest = raw.strip_prefix("oc://").ok_or_else(|| {
        CliError::InvalidArgs(format!(
            "invalid secret reference '{raw}' (expected oc://secret[?field=...])"
        ))
    })?;
    let (path, query) = rest.split_once('?').map_or((rest, ""), |(path, query)| (path, query));
    let name = path.trim_matches('/').to_string();
    if name.is_empty() {
        return Err(CliError::InvalidArgs(format!(
            "invalid secret reference '{raw}' (missing secret name)"
        )));
    }

    let mut field = SecretReferenceField::Secret;
    for pair in query.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = pair.split_once('=').ok_or_else(|| {
            CliError::InvalidArgs(format!("invalid secret reference query '{pair}' in '{raw}'"))
        })?;
        match key {
            "field" => field = SecretReferenceField::parse(value)?,
            other => {
                return Err(CliError::InvalidArgs(format!(
                    "unsupported secret reference query '{other}' in '{raw}'"
                )));
            }
        }
    }

    Ok(SecretReference { name, field })
}

pub(crate) fn parse_reference_binding(
    pair: &str,
) -> Result<(String, String, SecretReference), CliError> {
    let (key, raw_reference) = pair.split_once('=').ok_or_else(|| {
        CliError::InvalidArgs(format!(
            "invalid --reference (expected KEY=oc://secret[?field=...]): '{pair}'"
        ))
    })?;
    if key.is_empty() || key.contains('\0') {
        return Err(CliError::InvalidArgs(format!("invalid --reference key: '{key}'")));
    }
    let reference = parse_secret_reference(raw_reference)?;
    Ok((key.to_string(), raw_reference.to_string(), reference))
}

pub(crate) fn resolve_reference(
    store: &oc_secret::SecretStore,
    identity: &oc_secret::AgeIdentity,
    reference: &SecretReference,
) -> Result<Zeroizing<String>, CliError> {
    let entry = store.get(&reference.name).map_err(|e| {
        CliError::InvalidArgs(format!("failed to read secret '{}': {e}", reference.name))
    })?;
    let payload = entry.decrypt(identity).map_err(|e| {
        CliError::InvalidArgs(format!("decryption failed for '{}': {e}", reference.name))
    })?;

    let value = match reference.field {
        SecretReferenceField::Secret => payload.secret.clone(),
        SecretReferenceField::Notes => payload.notes.clone().unwrap_or_default(),
        SecretReferenceField::Otp => super::totp_code_from_uri(&payload.secret)?,
        SecretReferenceField::Metadata => serde_json::to_string(&entry.metadata)?,
    };
    Ok(Zeroizing::new(value))
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ReferenceValidation {
    pub key: String,
    pub reference: String,
    pub secret_name: String,
    pub field: SecretReferenceField,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub(crate) fn validate_reference_binding(
    store: &oc_secret::SecretStore,
    identity: &oc_secret::AgeIdentity,
    key: &str,
    raw_reference: &str,
    reference: &SecretReference,
) -> ReferenceValidation {
    match resolve_reference(store, identity, reference) {
        Ok(_) => ReferenceValidation {
            key: key.to_string(),
            reference: raw_reference.to_string(),
            secret_name: reference.name.clone(),
            field: reference.field,
            ok: true,
            error: None,
        },
        Err(error) => ReferenceValidation {
            key: key.to_string(),
            reference: raw_reference.to_string(),
            secret_name: reference.name.clone(),
            field: reference.field,
            ok: false,
            error: Some(error.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reference_binding_supports_fields() {
        let (key, raw, reference) =
            parse_reference_binding("OPENAI_API_KEY=oc://api/openai?field=otp").unwrap();
        assert_eq!(key, "OPENAI_API_KEY");
        assert_eq!(raw, "oc://api/openai?field=otp");
        assert_eq!(reference.name, "api/openai");
        assert_eq!(reference.field, SecretReferenceField::Otp);
    }
}
