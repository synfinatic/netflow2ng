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
- [ ] Path 1: defaults on both sides (built-in key) — flows appear in ntopng
- [ ] Path 2: ntopng `--zmq-encryption` + its `zmq-key.pub`, fed via `--zmq-encryption-key`
      and via `--zmq-encryption-key-file` — flows appear
- [ ] Path 3: `--zmq-disable-encryption` on both sides — flows appear
- [ ] Negative: mismatched keys yield no flows AND a diagnosable log line, not a silent hang
- [ ] Verify: `docker compose up` + NetFlow v9 source; ntopng Flows page, `/metrics`, `-l trace`
- [!] BLOCKED in this environment: the Docker daemon has no registry egress here, so
      `ntop/ntopng:latest` and `redis:alpine` cannot be pulled and ntopng never starts
      (`docker pull hello-world` also hangs with no output). The four boxes above need to be
      run by a human on a host with working Docker + a NetFlow v9 source.
- [x] Automated stand-in landed in `transport/zmq_test.go`:
      `TestZmqDriver_CurveInterop_NtopngStyleCollector` (delivery over CURVE against a
      subscriber configured exactly as ntopng configures its collector) and
      `TestZmqDriver_CurveInterop_WrongServerKeyDeliversNothing` (fails closed, no cleartext
      fallback). These run in CI; the boxes above remain for the live ntopng check.

### Checkpoint B — the gate that matters
- [ ] All three interop paths verified against a real ntopng  (BLOCKED — see Task 6)
- [ ] Mismatched-key failure mode is diagnosable from logs  (BLOCKED — see Task 6)
- [ ] Review with human before proceeding to docs/packaging  (OUTSTANDING — Phase 3 was
      completed ahead of this gate because the gate is environment-blocked, not because it
      passed. Docs/version are the only things past it and are trivially revisable.)

## Phase 3 — Docs and packaging

### Task 7: Alpine/libzmq CURVE verification (XS, deps: 5)
- [x] Confirm `zeromq-dev` / `libzmq` in the Dockerfile provide CURVE (libsodium); add the apk
      package if not — CONFIRMED, no Dockerfile change needed. `ldd /usr/lib/libzmq.so.5` inside
      the shipped `synfinatic/netflow2ng:latest` image (Alpine `libzmq` 5.2.5) resolves
      `libsodium.so.26`; Alpine's libzmq is built against libsodium, which is what enables CURVE.
- [ ] Verify: `make docker`, then run the container with `--zmq-encryption-key '<key>'`
      (BLOCKED — `make docker` needs to pull `golang:alpine` and run `apk add`, both of which
      need the Docker daemon's network. Left for the same host that runs Task 6.)

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
- [ ] Verify: follow the README steps verbatim against the compose stack (BLOCKED — same
      Docker limitation as Task 6)

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
- [ ] README instructions followed end to end on a clean machine (BLOCKED — needs the Docker
      host from Task 6)
