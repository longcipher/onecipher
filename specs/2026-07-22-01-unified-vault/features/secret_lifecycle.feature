Feature: Secret lifecycle management
  As a user
  I want to create, read, update, and delete secrets
  So that I can manage all my sensitive data in one unified vault

  Scenario: Create a new password secret
    Given a vault initialized with age encryption
    When I create a secret named "github/personal" of type "password"
    And the secret payload is:
      """
      {"secret": "correct horse battery staple", "notes": "personal github", "extra": {"url": "https://github.com", "username": "alice"}}
      """
    Then the secret "github/personal" should exist in the vault
    And the secret file should be an age envelope
    And the audit log should contain a "SecretWritten" event for "github/personal"

  Scenario: Read a secret
    Given a vault with secret "github/personal" of type "password"
    When I read the secret "github/personal"
    Then the payload secret should be "correct horse battery staple"
    And the audit log should contain a "SecretRead" event for "github/personal"

  Scenario: Update a secret
    Given a vault with secret "github/personal" of type "password"
    When I update the secret "github/personal" with payload:
      """
      {"secret": "new password", "notes": "rotated"}
      """
    Then reading the secret "github/personal" should return "new password"
    And the audit log should contain a new "SecretWritten" event for "github/personal"

  Scenario: Delete a secret
    Given a vault with secret "github/personal" of type "password"
    When I delete the secret "github/personal"
    Then the secret "github/personal" should not exist in the vault
    And the audit log should contain a "SecretDeleted" event for "github/personal"

  Scenario: List secrets with type filter
    Given a vault with secrets of mixed types
    When I list secrets with type filter "password"
    Then the result should contain only secrets of type "password"

  Scenario: Rename a secret
    Given a vault with secret "github/personal" of type "password"
    When I rename "github/personal" to "github/alice"
    Then the secret "github/alice" should exist
    And the secret "github/personal" should not exist
