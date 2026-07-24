Feature: Supply Chain Security
  As a security auditor
  I want the release pipeline to produce SBOMs, SLSA provenance, vet results, and CVE scans
  So that every dependency in the OneCipher release is accounted for and verified

  Background:
    Given the OneCipher release pipeline produces artifacts for oc-crypto, oc-signer, oc-keyagent, and the daemon
    And the pipeline runs in a hermetic build environment

  Scenario: Release produces CycloneDX SBOM
    Given a release build has completed
    When the release artifacts are inspected
    Then a CycloneDX SBOM file is present for each released component
    And the SBOM lists every Rust dependency with name, version, and source
    And the SBOM can be verified via `onecipher sbom verify`

  Scenario: SLSA Level 3 provenance attached
    Given a release build has completed in the hermetic build environment
    When the release artifacts are inspected
    Then a SLSA Level 3 provenance document is attached to each artifact
    And the provenance records the build source, build parameters, and build environment
    And the provenance is signed by the build pipeline's signing key

  Scenario: cargo-vet runs on oc-crypto, oc-signer, and oc-keyagent dependency trees
    Given the source tree contains cargo-vet configuration
    When cargo-vet is invoked on the oc-crypto, oc-signer, and oc-keyagent dependency trees
    Then every third-party dependency in those trees has a recorded vet result
    And any unvetted dependency fails the release gate
    And the vet store records who reviewed each dependency and when

  Scenario: cargo-audit scans for known CVEs
    Given the release pipeline runs cargo-audit
    When cargo-audit scans the workspace Cargo.lock
    Then any dependency with a known CVE fails the release gate
    And a clean cargo-audit report is produced as a release artifact
