# Summary

<!-- What does this change do, and why? One or two short paragraphs. -->

## Checklist

- [ ] `zig build check` compiles every binary.
- [ ] `zig build test` passes; suites touched by this change
      (`test-crash`, `test-cluster`, `test-roles`, `test-gateway`,
      `test-fault-network`, `test-cli`, `test-cabi`) were run locally.
- [ ] The journal stays authoritative: no write is acknowledged before its
      frame is fsynced and its slot commits.
- [ ] Wire or on-disk format changes follow the compatibility policy in
      ZDS 0004 and bump the protocol or format version explicitly.
- [ ] Changes to the security boundary (TLS, PSK, enrollment, sockets) are
      called out in the summary above.
- [ ] The zaxonlite book in [insanai/zxdocs](https://github.com/insanai/zxdocs)
      is updated when behavior, formats, or operations change.
- [ ] Memory and work stay bounded; every error is handled; Zig lines are
      at or below 100 columns (TigerStyle).

## Verification

<!-- Paste the commands you ran and their results, including any fuzz seed
     or cluster-run count that matters for review. -->
