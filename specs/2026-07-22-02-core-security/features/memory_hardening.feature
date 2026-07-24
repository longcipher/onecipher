Feature: Memory Hardening
  As a security engineer
  I want sensitive material protected by memory hardening
  So that secrets cannot be swapped to disk or leaked via core dumps

  Scenario: HardenedBytes mlock + madvise(DONTDUMP) on allocation
    Given the oc-crypto crate provides the HardenedBytes container
    And the Key-Agent uses HardenedBytes for all sensitive material including mnemonics, derived private keys, and Session Keys
    When a new HardenedBytes of 64 bytes is allocated
    Then the underlying memory page is locked via mlock so it cannot be swapped to disk
    And the underlying memory page is marked with madvise(MADV_DONTDUMP) so it is excluded from core dumps
    And on Windows the page is locked via VirtualLock

  Scenario: HardenedBytes zeroize + munlock on Drop
    Given a HardenedBytes instance holds 32 bytes of private key material
    When the instance is dropped
    Then the memory is overwritten with zeros via zeroize before any deallocation
    And the mlock on the page is released via munlock (or VirtualUnlock on Windows)
    And no copy of the original material remains in process memory after Drop returns

  Scenario: Linux Key-Agent memory regions mlock'd via /proc/$pid/maps
    Given the Key-Agent is running on Linux with sufficient RLIMIT_MEMLOCK or CAP_IPC_LOCK
    When the memory map of the Key-Agent process is inspected via /proc/$pid/maps
    Then the regions holding HardenedBytes are marked as locked
    And the regions are marked as dontdump

  Scenario: Key-Agent core dump has no plaintext private keys
    Given the Key-Agent has loaded and dropped several private keys during a signing workload
    When the Key-Agent process is dumped via gcore
    And the core dump is inspected via strings
    Then no mnemonic seed phrase, BIP-32 root key, derived private key, or Session Key private material appears in plaintext
    And the same verification holds after the workload completes and all HardenedBytes instances have been dropped
