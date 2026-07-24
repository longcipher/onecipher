Feature: Policy File Missing or Invalid
  As a wallet Owner
  I want the Policy Engine to deny all signing when the Policy file is missing or corrupt
  So that an Agent cannot sign without an active, valid Policy

  Background:
    Given an Agent holds a session_key_id and attempts a PayX402
    And the Policy Engine attempts to load the Policy for the session_key_id before any signing

  Scenario: Policy file missing on disk
    Given the Policy file for the session_key_id does not exist on disk
    When the Agent calls PayX402
    Then the Policy Engine cannot find a Policy for the session_key_id
    And the response has status DENY and deny_reason "POLICY_INVALID"
    And an audit entry of event_type POLICY_LOOKUP_FAILED is appended
    And no signing is performed

  Scenario: Policy file unparseable
    Given the Policy file for the session_key_id exists on disk
    And the file contents are not valid JSON or fail schema validation
    When the Agent calls PayX402
    Then the Policy Engine fails to parse the Policy
    And the response has status DENY and deny_reason "POLICY_INVALID"
    And an audit entry of event_type POLICY_PARSE_FAILED is appended with the parse error
    And no signing is performed
