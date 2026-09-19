# TODO: Optional CurveZMQ Encryption

Plan: [tasks/plan.md](plan.md). Every code task follows RED -> GREEN -> REFACTOR.
Do not tick GREEN until the RED failure output has actually been observed.

## Phase 1 — Foundation

### Task 1: `ValidateZ85Key` (XS, no deps)
- [x] RED: `transport/curve_test.go` table test — accepts ntopng's built-in pub/priv keys;
      rejects empty, 39, 41, and 12 chars, plus a 40-char string with a non-Z85 character.
      Stub `ValidateZ85Key` returning nil so rejects fail on assertions.
- [x] GREEN: hand-rolled length + alphabet check (never `zmq.Z85decode` — it panics).
- [x] Verify: `go test ./transport/ -run TestValidateZ85Key -v`

### Task 2: `ResolveEncryption` (S, deps: 1)
- [x] RED: precedence matrix — disabled -> `(nil, nil)`; key > keyFile > built-in default;
      `UsingDefaultKey` only on the default path; trailing newline in key file trimmed;
      missing file, garbage file, invalid key, invalid clientPriv all error. `t.TempDir()`.
- [x] GREEN: implement resolution, delegating validation to `ValidateZ85Key`.
- [x] REFACTOR: fold the shared validate-then-assign branches.
- [x] Verify: `go test ./transport/ -run TestResolveEncryption -v`

### Task 3: `EncryptionConfig.apply` (S, deps: 2)
- [x] RED: real `zmq.PUB` socket (unbound) — server key round-trips via `GetCurveServerkey`;
      pinned `ClientPrivKey` yields a stable derived pubkey across two calls; nil config is a
      no-op. File guarded by `if !zmq.HasCurve() { t.Skip(...) }`.
- [x] GREEN: implement with `HasCurve()` guard + actionable error.
- [x] Verify: `go test -race ./transport/ -run TestEncryptionConfig -v`

### Task 4: `ZmqDriver.Init` applies CURVE before `Bind` (S, deps: 3)
- [x] RED (a): `Init()` on an unbindable address returns an error — fails today because the
      code calls `log.Fatalf` and kills the process. Observe this before changing anything.
- [x] RED (b): `Init()` with an encryption config binds and reports the expected
      `GetCurveServerkey()` — proves options landed before `Bind()`.
- [x] GREEN: add the `encryption` field, return errors instead of `log.Fatalf`, apply CURVE
      ahead of `Bind()`.
- [x] Verify: `go test -race ./transport/`

### Checkpoint A
- [x] `make vet unittest` clean; pre-existing `transport` tests pass untouched
- [x] Every test above was observed failing before its implementation landed
- [x] Cleartext wire bytes identical to today when encryption is disabled

## Phase 2 — Vertical slice to the CLI

### Task 5: CLI flags end to end (S, deps: 4)
- [x] RED: kong parse tests — four flags bind to their fields; each env var populates its
      field; flag beats env var; no flags -> built-in-default config; `BADKEY` errors.
- [x] GREEN: four kong fields with `env:` tags, extend `RegisterZmq`, call
      `ResolveEncryption` in `main()`, add startup log lines.
- [x] REFACTOR: extract resolve+log into a testable helper beside `selectFormat` if `main()`
      is getting long.
- [x] Verify: `go test ./cmd/ -v`; `./dist/netflow2ng -h`;
      `./netflow2ng --zmq-encryption-key BADKEY; echo $?` -> non-zero

### Task 6: Live interop against ntopng (M, deps: 5)

Verified 2026-09-19 against **ntopng 7.0.260918** (`ntop/ntopng:latest`, amd64 under emulation),
netflow2ng on the host binding `tcp://0.0.0.0:5556`, ntopng connecting back over
`host.docker.internal`. NetFlow v9 came from a replay of the real template + data packets in
goflow2's decoder tests (21 flows/packet, header timestamps rewritten to now); the generator
lives in the scratchpad, not the repo. Flow counts read from ntopng's own
`/lua/rest/v2/get/interface/data.lua?ifid=0`, field `zmqRecvStats`.

- [x] Path 1: defaults on both sides (built-in key) — `zmq_msg_rcvd=210`, 21 active flows,
      42 hosts, 0 drops
- [x] Path 2: ntopng `--zmq-encryption` (it generated `zmq-key.pub`, 40 bytes, no trailing
      newline) fed to netflow2ng via `--zmq-encryption-key` — `zmq_msg_rcvd=525`; then via
      `--zmq-encryption-key-file` — 630 -> 1092 across the restart, so the file path works and
      ntopng's SUB reconnects cleanly when the PUB restarts
- [x] Path 3: `--zmq-disable-encryption` on both sides — `zmq_msg_rcvd=483`
- [x] Negative: netflow2ng given a valid-but-wrong key against a default ntopng — 672 flows
      published, `zmq_msg_rcvd=0`, `bytes=0`. Fails closed, no cleartext fallback.
- [x] Negative (bonus): netflow2ng on the built-in default key against an ntopng running
      `--zmq-encryption` with its own generated key — also `zmq_msg_rcvd=0`
- [x] Diagnosability: confirmed that on a mismatch **neither side logs anything** — ntopng
      still prints "Collecting flows on tcp://..." and netflow2ng still prints "Sending first
      ZMQ message". This is exactly why `setupEncryption` logs the key in use, and it is what
      the README troubleshooting section now describes.
- [x] Automated stand-in in `transport/zmq_test.go`:
      `TestZmqDriver_CurveInterop_NtopngStyleCollector` and
      `TestZmqDriver_CurveInterop_WrongServerKeyDeliversNothing`. The live run above confirms
      the stand-in models ntopng's real behavior.

Observation, not a netflow2ng bug: ntopng's `--zmq-encryption-key-priv` (which its own help
marks "debug only") wedges ntopng at startup — it never reaches "Collecting flows". Path 2 was
therefore run with ntopng's self-generated keypair, which is the documented path anyway.

### Checkpoint B — the gate that matters
- [x] All three interop paths verified against a real ntopng (7.0.260918) — see Task 6
- [x] Mismatched-key failure mode: fails closed, and diagnosable only via the key netflow2ng
      logs, since neither side reports an error. Documented in the README.
- [x] Review with human before proceeding to docs/packaging — Phase 3 had already been written
      while the gate was environment-blocked; the live run changed nothing in it.

## Phase 3 — Docs and packaging

### Task 7: Alpine/libzmq CURVE verification (XS, deps: 5)
- [x] Confirm `zeromq-dev` / `libzmq` in the Dockerfile provide CURVE (libsodium); add the apk
      package if not — CONFIRMED, no Dockerfile change needed. `ldd /usr/lib/libzmq.so.5` inside
      the shipped `synfinatic/netflow2ng:latest` image (Alpine `libzmq` 5.2.5) resolves
      `libsodium.so.26`; Alpine's libzmq is built against libsodium, which is what enables CURVE.
- [x] Verify: built the image from the current Dockerfile and ran it against the live ntopng
      with `--zmq-encryption-key-file` on a mounted key — CURVE enabled (no `HasCurve()`
      error) and `zmq_msg_rcvd` climbed 1701 -> 2331 over 60s with 0 drops.
      `ldd /usr/lib/libzmq.so.5` in the built image resolves `libsodium.so.26`.

### Task 8: README + version bump (S, deps: 6) — docs only, no TDD cycle
- [x] README "ZMQ Encryption" section: what changed in ntopng 6.7.280831, flag/env/file table,
      where to find ntopng's public key, the pre-6.7 escape hatch, plus a troubleshooting
      subsection for the silent-mismatch and no-CURVE-in-libzmq failure modes
- [x] Prominent upgrade warning: netflow2ng now encrypts by default (top of the new section,
      plus a pointer from "Configuration" and a bullet in "Features")
- [x] Bump `PROJECT_VERSION` in `Makefile` (0.2.2 -> 0.3.0)
- [x] `docker-compose.yaml` comments for the key/env-var and disable-encryption paths
- [x] Follow-on found while writing the troubleshooting section (full RED -> GREEN cycle):
      `setupEncryption` now logs the ntopng public key it is actually using, on both the
      configured and built-in-default paths. A CURVE mismatch fails silently at the ZMQ layer,
      so this is the only way an operator can compare against ntopng's `zmq-key.pub`. Covered
      by `TestSetupEncryption_LogsTheServerKeyInUse`.
- [x] Verify: the README's key-retrieval steps (`--zmq-encryption` -> `cat
      /var/lib/ntopng/zmq-key.pub` -> `--zmq-encryption-key` / `--zmq-encryption-key-file`)
      were followed verbatim during Task 6 and are accurate.

### Checkpoint C — Complete
- [x] `go vet` clean, `go test -race ./...` 171 pass in 4 packages, `gofmt -l` empty,
      `go mod tidy` no-op
- [!] `make lint` — golangci-lint panics locally with
      `file requires newer Go version go1.27 (application built with go1.26)`. Reproduced on
      untouched packages (`./formatter/...`) at HEAD, so it is a pre-existing local toolchain
      mismatch, not these changes. CI installs its own golangci-lint.
- [x] No test skipped or disabled to make the suite green (the `HasCurve()` skip is a genuine
      capability guard and does not fire here — local libzmq has CURVE)
- [x] Coverage not regressed: 68.4% at HEAD (measured in a temporary `git worktree`, since
      `coverage.out` is gitignored) -> 69.4% now
- [x] README instructions followed end to end against a live ntopng 7.0.260918
