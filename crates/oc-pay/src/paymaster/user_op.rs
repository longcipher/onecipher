use serde::{Deserialize, Serialize};

/// ERC-4337 UserOperation (per EIP-4337).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserOperation {
    pub sender: String,
    pub nonce: String,
    pub init_code: String,
    pub call_data: String,
    pub call_gas_limit: String,
    pub verification_gas_limit: String,
    pub pre_verification_gas: String,
    pub max_fee_per_gas: String,
    pub max_priority_fee_per_gas: String,
    pub paymaster_and_data: String,
    pub signature: String,
}

impl UserOperation {
    /// Create a builder for a UserOperation.
    pub fn builder(sender: impl Into<String>) -> UserOperationBuilder {
        UserOperationBuilder::new(sender)
    }

    /// Attach paymaster data to this UserOp.
    pub fn with_paymaster(mut self, paymaster_and_data: String) -> Self {
        self.paymaster_and_data = paymaster_and_data;
        self
    }

    /// Attach a signature to this UserOp.
    pub fn with_signature(mut self, signature: String) -> Self {
        self.signature = signature;
        self
    }
}

/// Builder for UserOperation.
pub struct UserOperationBuilder {
    sender: String,
    nonce: String,
    init_code: String,
    call_data: String,
    call_gas_limit: String,
    verification_gas_limit: String,
    pre_verification_gas: String,
    max_fee_per_gas: String,
    max_priority_fee_per_gas: String,
    paymaster_and_data: String,
    signature: String,
}

impl UserOperationBuilder {
    pub fn new(sender: impl Into<String>) -> Self {
        Self {
            sender: sender.into(),
            nonce: "0x0".to_string(),
            init_code: "0x".to_string(),
            call_data: "0x".to_string(),
            call_gas_limit: "0x".to_string(),
            verification_gas_limit: "0x".to_string(),
            pre_verification_gas: "0x".to_string(),
            max_fee_per_gas: "0x".to_string(),
            max_priority_fee_per_gas: "0x".to_string(),
            paymaster_and_data: "0x".to_string(),
            signature: "0x".to_string(),
        }
    }

    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = nonce.into();
        self
    }

    pub fn init_code(mut self, init_code: impl Into<String>) -> Self {
        self.init_code = init_code.into();
        self
    }

    pub fn call_data(mut self, call_data: impl Into<String>) -> Self {
        self.call_data = call_data.into();
        self
    }

    pub fn call_gas_limit(mut self, gas: impl Into<String>) -> Self {
        self.call_gas_limit = gas.into();
        self
    }

    pub fn verification_gas_limit(mut self, gas: impl Into<String>) -> Self {
        self.verification_gas_limit = gas.into();
        self
    }

    pub fn pre_verification_gas(mut self, gas: impl Into<String>) -> Self {
        self.pre_verification_gas = gas.into();
        self
    }

    pub fn max_fee_per_gas(mut self, fee: impl Into<String>) -> Self {
        self.max_fee_per_gas = fee.into();
        self
    }

    pub fn max_priority_fee_per_gas(mut self, fee: impl Into<String>) -> Self {
        self.max_priority_fee_per_gas = fee.into();
        self
    }

    pub fn build(self) -> UserOperation {
        UserOperation {
            sender: self.sender,
            nonce: self.nonce,
            init_code: self.init_code,
            call_data: self.call_data,
            call_gas_limit: self.call_gas_limit,
            verification_gas_limit: self.verification_gas_limit,
            pre_verification_gas: self.pre_verification_gas,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            paymaster_and_data: self.paymaster_and_data,
            signature: self.signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENDER: &str = "0x1234567890abcdef1234567890abcdef12345678";

    #[test]
    fn builder_sets_defaults() {
        let op = UserOperation::builder(SENDER).build();
        assert_eq!(op.sender, SENDER);
        assert_eq!(op.nonce, "0x0");
        assert_eq!(op.init_code, "0x");
        assert_eq!(op.call_data, "0x");
        assert_eq!(op.paymaster_and_data, "0x");
        assert_eq!(op.signature, "0x");
    }

    #[test]
    fn builder_sets_fields() {
        let op = UserOperation::builder(SENDER)
            .nonce("0x42")
            .call_data("0xdeadbeef")
            .call_gas_limit("0x10000")
            .verification_gas_limit("0x5000")
            .pre_verification_gas("0x1000")
            .max_fee_per_gas("0x1")
            .max_priority_fee_per_gas("0x1")
            .init_code("0xfeedface")
            .build();
        assert_eq!(op.nonce, "0x42");
        assert_eq!(op.call_data, "0xdeadbeef");
        assert_eq!(op.call_gas_limit, "0x10000");
        assert_eq!(op.verification_gas_limit, "0x5000");
        assert_eq!(op.pre_verification_gas, "0x1000");
        assert_eq!(op.max_fee_per_gas, "0x1");
        assert_eq!(op.max_priority_fee_per_gas, "0x1");
        assert_eq!(op.init_code, "0xfeedface");
    }

    #[test]
    fn with_paymaster_attaches_data() {
        let op = UserOperation::builder(SENDER).build().with_paymaster("0xabcd".to_string());
        assert_eq!(op.paymaster_and_data, "0xabcd");
    }

    #[test]
    fn with_signature_attaches_signature() {
        let op = UserOperation::builder(SENDER).build().with_signature("0xdeadbeef".to_string());
        assert_eq!(op.signature, "0xdeadbeef");
    }

    #[test]
    fn serde_roundtrip_preserves_fields() {
        let op = UserOperation::builder(SENDER).nonce("0x1").call_data("0xcafe").build();
        let json = serde_json::to_string(&op).expect("serialize");
        let back: UserOperation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(op, back);
    }

    #[test]
    fn builder_methods_chain() {
        // Confirm builder consumes and returns Self (method chaining compiles).
        let op = UserOperation::builder(SENDER)
            .nonce("0x1")
            .init_code("0x")
            .call_data("0x")
            .call_gas_limit("0x0")
            .verification_gas_limit("0x0")
            .pre_verification_gas("0x0")
            .max_fee_per_gas("0x0")
            .max_priority_fee_per_gas("0x0")
            .build();
        assert_eq!(op.sender, SENDER);
    }

    #[test]
    fn builder_accepts_string_owned() {
        let op = UserOperation::builder(String::from(SENDER)).build();
        assert_eq!(op.sender, SENDER);
    }

    #[test]
    fn with_paymaster_then_with_signature_both_apply() {
        let op = UserOperation::builder(SENDER)
            .build()
            .with_paymaster("0xpm".to_string())
            .with_signature("0xsig".to_string());
        assert_eq!(op.paymaster_and_data, "0xpm");
        assert_eq!(op.signature, "0xsig");
    }

    #[test]
    fn serde_deserialize_missing_fields_fails() {
        let json = r#"{"sender":"0xabc","nonce":"0x0"}"#;
        let result: Result<UserOperation, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn builder_defaults_all_gas_fields_to_0x() {
        let op = UserOperation::builder(SENDER).build();
        assert_eq!(op.call_gas_limit, "0x");
        assert_eq!(op.verification_gas_limit, "0x");
        assert_eq!(op.pre_verification_gas, "0x");
        assert_eq!(op.max_fee_per_gas, "0x");
        assert_eq!(op.max_priority_fee_per_gas, "0x");
    }
}
