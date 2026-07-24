Feature: Reproducible Build of the Key-Agent
  As a security-conscious user
  I want to build the Key-Agent from open source and verify it matches the released binary
  So that I can trust the closed source release has no backdoors

  Background:
    Given the open source Key-Agent repository is published with a reproducer script
    And the closed source release package bundles a Key-Agent binary

  Scenario: User builds Key-Agent from open source repo, SHA256 matches closed-source binary
    Given the user clones the open source Key-Agent repository at the released git commit
    And the user has the pinned toolchain from the reproducer script
    When the user runs the reproducer script to build the Key-Agent
    Then the build completes without network access beyond the pinned toolchain
    And the resulting binary is bit-for-bit identical to the Key-Agent binary shipped in the closed source release
    And the SHA256 digest of the user-built binary equals the SHA256 digest published in the release manifest
    And the Cargo.lock used for the build matches the released Cargo.lock
