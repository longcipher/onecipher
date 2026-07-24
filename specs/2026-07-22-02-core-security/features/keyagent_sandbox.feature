Feature: Key-Agent Sandbox Hard Gates
  As a security auditor
  I want the Key-Agent to be sandboxed with no network access
  So that even a compromised Key-Agent cannot exfiltrate secrets

  Background:
    Given the Key-Agent binary is built for the Linux platform
    And the Key-Agent is launched with seccomp filtering enabled

  Scenario: Key-Agent has no network syscalls on Linux
    Given the Key-Agent is launched under strace tracing only network syscalls
    When the Key-Agent processes a representative signing workload
    Then the strace output for network syscalls is empty
    And no socket, connect, bind, sendto, or recvfrom syscall appears in the trace

  Scenario: Key-Agent dependency tree clean
    Given the oc-keyagent crate is part of the workspace
    When the dependency tree is computed
    Then the tree does not contain tokio, reqwest, tungstenite, hyper, async-std, or smol
    And the only allowed dependencies are oc-crypto, oc-core, oc-signer, oc-policy, oc-session-key, oc-vault, and prost
    And std::os::unix::net is used for Unix Domain Socket I/O instead of any async runtime

  Scenario: Key-Agent binary has no TCP symbols
    Given the release-built oc-keyagent binary
    When the symbol table is inspected via nm
    Then no connect, socket, or bind symbol referring to TCP or AF_INET appears
    And only Unix-domain socket symbols are permitted
