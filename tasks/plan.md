# Plan: Optional CurveZMQ Encryption for netflow2ng

## Context

As of ntopng 6.7.280831 (Sept 2026), ntop enabled **ZMQ CURVE encryption by default** across
ntopng, nProbe and Cento. An ntopng collector now refuses cleartext ZMQ flows — they silently
never appear in the UI. netflow2ng publishes cleartext only, so current netflow2ng + current
ntopng is a broken pairing unless the user runs ntopng with `--zmq-disable-encryption`.

This adds CURVE support to netflow2ng's ZMQ publisher so it interoperates with a default
ntopng install out of the box, while keeping a documented escape hatch for older ntopng.

### How the handshake actually works (verified against ntopng source)

`src/ZMQCollectorInterface.cpp` calls `ZMQUtils::setServerEncryptionKeys()` on its SUB socket
**unconditionally** — ntopng sets `ZMQ_CURVE_SERVER=1` + its own secret key whether it binds
or connects. CURVE roles are independent of bind/connect, so:

- **ntopng = CURVE server** (owns the keypair, publishes its public key)
- **netflow2ng = CURVE client** (must set `ZMQ_CURVE_SERVERKEY` to ntopng's public key, plus
  its own client keypair) — the same role nProbe plays via `--zmq-encryption-key '<pub key>'`

ntopng installs **no ZAP handler**, so client public keys are not authenticated. nProbe just
generates a throwaway client keypair per start (`ZMQUtils::setClientEncryptionKeys`).

Three ntopng key sources, in ntopng's own precedence order:
1. `--zmq-encryption-key-priv <key>` (explicit private key)
2. `$datadir/zmq-key.pub` / `.priv`, auto-generated under `--zmq-encryption` (public key is
   also shown on ntopng's interface status page)
3. Built-in fallback pair when the user configured nothing — from `include/ntop_defines.h`:
   - pub: `+hO@^5%GQ]^H6=fim{?$i-eu^Qcgi0l1}I:dYFN{`
   - priv: `=m8rLxEcVs:*!M6x0iWW{)i$uwN9.:[5-3:NCIDY`

Keys are 40-char Z85 (32 raw bytes). `pebbe/zmq4` v1.4.0 already provides everything needed:
`HasCurve()`, `NewCurveKeypair()`, `AuthCurvePublic()`, `SetCurveServerkey/Publickey/Secretkey`.

## Decisions (confirmed with user)

| Decision | Choice |
|---|---|
| Default behavior | **Encrypt by default** using ntopng's built-in public key; `--zmq-disable-encryption` opts out |
| ntopng key source | CLI flag, env var, and key file — flag > file > built-in default |
| netflow2ng client key | Ephemeral per start, with optional `--zmq-client-priv-key` override |

Encrypting by default mirrors ntop's own change. It **is a breaking change** for users on
ntopng < 6.7.280831, who must add `--zmq-disable-encryption` to netflow2ng. This is called out
loudly in the README, in a startup log line, and warrants a minor version bump.

Assumption: the Q2 answer ("env var + file path") means *not flag-only*, not *no flag*. Kong's
`env:` tag hangs off a flag anyway, and the selected Q1 option's preview shows
`--zmq-encryption-key '...'`, so the plan implements flag + env + file.

## Design

New file **`transport/curve.go`** holding all CURVE logic, keeping `zmq.go` focused on framing:

```go
// DefaultNtopngPublicKey mirrors DEFAULT_ZMQ_ENCRYPTION_PUB_KEY in ntopng's ntop_defines.h
const DefaultNtopngPublicKey = "+hO@^5%GQ]^H6=fim{?$i-eu^Qcgi0l1}I:dYFN{"

type EncryptionConfig struct {
    ServerKey       string // ntopng's public key, Z85
    ClientPrivKey   string // "" => ephemeral keypair
    UsingDefaultKey bool   // true => log the "configure a dedicated key" warning
}

func ValidateZ85Key(key string) error                                  // pure, 40 chars, Z85 alphabet
func ResolveEncryption(disable bool, key, keyFile, clientPriv string) (*EncryptionConfig, error)
func (e *EncryptionConfig) apply(sock *zmq.Socket) error                // must run before Bind()
```

- `ValidateZ85Key` is hand-rolled rather than calling `zmq.Z85decode`, which **panics** on a
  length that isn't a multiple of 5 — bad input must produce a clean CLI error.
- `ResolveEncryption` returns `(nil, nil)` when disabled. Precedence: explicit key > key file >
  built-in default (`UsingDefaultKey = true`). The key file is read and whitespace-trimmed —
  ntopng writes `zmq-key.pub` with no trailing newline, but other tooling may not.
- `apply()` checks `zmq.HasCurve()` first and errors with an actionable message if libzmq was
  built without libsodium. Derives the client public key via `zmq.AuthCurvePublic()` when
  `ClientPrivKey` is set, otherwise `zmq.NewCurveKeypair()`.

**`transport/zmq.go`**: `ZmqDriver` gains an `encryption *EncryptionConfig` field. `Init()`
calls `d.encryption.apply(d.publisher)` *before* `Bind()`, and — since
`transport.FindTransport` already propagates `Init()`'s error to `main`, which does
`log.Fatal` — `Init()` now **returns** errors instead of the current `log.Fatalf` on bind
failure (a small drive-by correctness fix; it also lets `Init()` be unit tested).
`transport.go`'s `RegisterZmq` takes the config as a new final parameter.

**`cmd/netflow2ng.go`**: four new kong fields on `CLI`, each with an `env:` tag:

| Flag | Env | Notes |
|---|---|---|
| `--zmq-encryption-key` | `NETFLOW2NG_ZMQ_ENCRYPTION_KEY` | ntopng's 40-char Z85 public key |
| `--zmq-encryption-key-file` | `NETFLOW2NG_ZMQ_ENCRYPTION_KEY_FILE` | path to ntopng's `zmq-key.pub` |
| `--zmq-disable-encryption` | `NETFLOW2NG_ZMQ_DISABLE_ENCRYPTION` | cleartext, pre-6.7 ntopng |
| `--zmq-client-priv-key` | `NETFLOW2NG_ZMQ_CLIENT_PRIV_KEY` | pin client identity (rarely needed) |

`main()` calls `ResolveEncryption` right before `RegisterZmq` and `log.Fatal`s on error.
Startup logging mirrors ntopng's own messages: default-key → warn to configure a dedicated
key; disabled → warn that flows are cleartext; explicit key → info.

## Tasks (TDD)

Every code task runs **RED → GREEN → REFACTOR**. Go-specific convention for RED: write the
test first, then add a stub with the final signature returning `errors.New("not implemented")`
(or a zero value) so the package compiles and the test fails on an *assertion*, not on a
missing symbol. A compile error is a weaker red — it doesn't prove the assertion is right.
Do not move to GREEN until the failure output has actually been seen.

Existing test style to follow: table-driven, stdlib `testing` only, no assertion library —
see `TestSourceId_Validate_Valid` in `cmd/netflow2ng_test.go` and `newTestDriver` in
`transport/zmq_test.go`. Package loggers are set in `init()` in both test files.

### Phase 1 — Foundation

**Task 1: `ValidateZ85Key`** — XS, no deps
- RED: `transport/curve_test.go` — table test over valid ntopng-format keys (including the
  built-in default pub and priv keys as literals), plus rejects: empty, 39 chars, 41 chars,
  12 chars (the length that makes `zmq.Z85decode` panic), and a 40-char string containing a
  character outside the Z85 alphabet. Stub `ValidateZ85Key` returning nil → rejection cases
  fail.
- GREEN: implement length + alphabet check by hand (never call `zmq.Z85decode` — it panics).
- AC: valid keys pass; every reject case returns a non-nil error; no test panics.
- Verify: `go test ./transport/ -run TestValidateZ85Key -v`
- Files: `transport/curve_test.go`, `transport/curve.go`

**Task 2: `ResolveEncryption`** — S, deps: 1
- RED: table test over the precedence matrix — disabled → `(nil, nil)`; explicit key wins over
  key file; key file wins over built-in default; no input → built-in default with
  `UsingDefaultKey == true`; key file containing a trailing newline is trimmed; missing file →
  error; file with garbage contents → error; invalid explicit key → error; invalid
  `clientPriv` → error. Use `t.TempDir()` for the file cases. Stub returns `(nil, nil)`.
- GREEN: implement resolution + delegation to `ValidateZ85Key`.
- REFACTOR: fold the shared "validate then assign" branches together.
- AC: `UsingDefaultKey` true *only* on the built-in path; every error case names which input
  was bad.
- Verify: `go test ./transport/ -run TestResolveEncryption -v`
- Files: `transport/curve_test.go`, `transport/curve.go`

**Task 3: `EncryptionConfig.apply` on a live socket** — S, deps: 2
- RED: medium-size test that creates a real `zmq.PUB` socket (no bind), calls `apply()`, and
  asserts via `GetCurveServerkey()` / `GetCurvePublickeykeyZ85()` that the server key matches
  the input and a client public key is present. Second case: `ClientPrivKey` set → derived
  public key is stable across two `apply()` calls (proves `AuthCurvePublic`, not a fresh
  keypair). Third case: nil config → socket has no CURVE mechanism. Guard the whole file with
  `if !zmq.HasCurve() { t.Skip(...) }`. Stub `apply` returning nil → assertions fail.
- GREEN: implement with the `HasCurve()` guard and an actionable error message.
- AC: server key round-trips; ephemeral vs pinned client key both behave as specified; nil
  config is a no-op.
- Verify: `go test -race ./transport/ -run TestEncryptionConfig -v`
- Files: `transport/curve_test.go`, `transport/curve.go`

**Task 4: `ZmqDriver.Init` applies CURVE before `Bind`** — S, deps: 3
- RED: two tests. (a) `Init()` on a driver with an unbindable address returns a non-nil error —
  fails today because the code calls `log.Fatalf` and the process exits, so this test must be
  written before the change and observed failing. (b) `Init()` with an encryption config on a
  free port succeeds and the bound socket reports the expected `GetCurveServerkey()` — proves
  the options landed *before* `Bind()`, since libzmq ignores them afterwards.
- GREEN: add the `encryption` field, replace `log.Fatalf` with a returned error, call
  `apply()` ahead of `Bind()`.
- AC: cleartext path unchanged when `encryption == nil`; `Init()` never terminates the process.
- Verify: `go test -race ./transport/`
- Files: `transport/zmq_test.go`, `transport/zmq.go`

### Checkpoint A
- [ ] `make vet unittest` clean; pre-existing `transport` tests pass untouched
- [ ] Every test above was observed failing before its implementation landed
- [ ] Cleartext wire bytes identical to today when encryption is disabled

### Phase 2 — Vertical slice to the CLI

**Task 5: CLI flags end to end** — S, deps: 4
- RED: `cmd/netflow2ng_test.go` — parse `CLI` through kong (`kong.Must(...).Parse([]string{...})`)
  and assert: all four flags bind to the expected fields; each env var populates its field when
  the flag is absent; the flag beats the env var. Then a test that the resolved config for "no
  flags at all" is the built-in-default config, and that `--zmq-encryption-key BADKEY` produces
  an error rather than a bound socket. Stubs: the fields don't exist yet, so add them empty —
  the assertions fail on zero values.
- GREEN: add the four kong fields with `env:` tags, extend `RegisterZmq`, call
  `ResolveEncryption` in `main()` before `RegisterZmq`, add the startup log lines.
- REFACTOR: if `main()` is getting long, extract the resolve+log step into a small testable
  helper next to `selectFormat`, matching that function's error-returning style.
- AC: `netflow2ng -h` lists all four with clear help; invalid key exits non-zero *before* any
  socket is bound; no flags → CURVE with built-in key + "configure a dedicated key" warning.
- Verify: `go test ./cmd/ -v`; `go build ./... && ./dist/netflow2ng -h`;
  `./netflow2ng --zmq-encryption-key BADKEY; echo $?` → non-zero
- Files: `cmd/netflow2ng_test.go`, `cmd/netflow2ng.go`, `transport/transport.go`

**Task 6: Live interop against ntopng** — M, deps: 5
- The one thing unit tests cannot prove. `docker-compose.yaml` already runs ntopng with
  `--interface tcp://localhost:5556`, i.e. ntopng *connects* and netflow2ng binds — exactly the
  topology the CURVE client/server split assumes.
- AC — flows visible in ntopng for all three paths:
  1. Defaults on both sides (built-in key).
  2. ntopng `--zmq-encryption` + its generated `zmq-key.pub` fed to netflow2ng, once via
     `--zmq-encryption-key` and once via `--zmq-encryption-key-file`.
  3. `--zmq-disable-encryption` on both sides.
- Plus the negative case: mismatched keys yield no flows *and* a diagnosable log line, not a
  silent hang.
- Verify: `docker compose up`, feed NetFlow v9 (device or replay), check ntopng's Flows page
  alongside netflow2ng `/metrics` and `-l trace`.
- Files: `docker-compose.yaml` (comments/examples only)

### Checkpoint B — the gate that matters
- [ ] All three interop paths verified against a real ntopng
- [ ] Mismatched-key failure mode is diagnosable from logs
- [ ] Review with human before proceeding to docs/packaging

### Phase 3 — Docs and packaging

**Task 7: Alpine/libzmq CURVE verification** — XS, deps: 5
- Confirm the Dockerfile's `zeromq-dev` / `libzmq` provide CURVE (libsodium). If not, add the
  needed apk package.
- AC: `docker run <image> --zmq-encryption-key '<key>'` starts and logs CURVE enabled, not the
  `HasCurve()` error.
- Verify: `make docker` (single-arch is enough) then run the container.
- Files: `Dockerfile` (only if a package is missing)

**Task 8: README + version bump** — S, deps: 6
- Docs/config only — no behavioral change, so no TDD cycle (per the skill's "when NOT to use").
- New "ZMQ Encryption" section: what changed in ntopng 6.7.280831, the flag/env/file table, how
  to get ntopng's public key (status page or `$datadir/zmq-key.pub`), the pre-6.7 ntopng
  escape hatch, and a **prominent upgrade warning** that netflow2ng now encrypts by default.
- Bump `PROJECT_VERSION` in `Makefile` (minor — behavior change).
- AC: a reader on old ntopng knows exactly which flag to add; a reader on new ntopng needs no
  flags at all.
- Verify: follow the README steps verbatim against the compose stack.
- Files: `README.md`, `Makefile`, `docker-compose.yaml`

### Checkpoint C — Complete
- [ ] `make precheck` passes (vet, unittest, lint, fmt, tidy)
- [ ] No test skipped or disabled to make the suite green (the `HasCurve()` skip is a genuine
      capability guard and must not fire on CI, where `libzmq3-dev` provides CURVE)
- [ ] Coverage for `transport/` not regressed (current project baseline ~75%)
- [ ] README instructions followed end to end on a clean machine

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Default-on encryption breaks users on ntopng < 6.7 | **High** | README upgrade warning + a startup log line naming `--zmq-disable-encryption`; minor version bump |
| libzmq built without libsodium (no CURVE) | Med | `zmq.HasCurve()` guard with an actionable error; Task 5 verifies the shipped image |
| `zmq.Z85decode` panics on malformed keys | Med | Hand-rolled `ValidateZ85Key`; explicit bad-input tests |
| ntopng changes its built-in default key pair | Low | Constant is documented with its ntopng source location; explicit key flags are the supported production path |
| CURVE options applied after `Bind()` silently no-op | Med | `apply()` called before `Bind()` in `Init()`; test asserts via `GetCurveServerkey` |

## Verification summary

```
go test ./transport/ -run 'ValidateZ85Key|ResolveEncryption' -v   # Tasks 1-2 (small, pure)
go test -race ./transport/                                        # Tasks 3-4 (real sockets)
go test ./cmd/ -v                                                 # Task 5 (flag/env parsing)
make vet unittest lint                                            # full suite + static
./dist/netflow2ng -h                                              # flag surface
docker compose up                                                 # Task 6 — the real gate
```

Test-pyramid shape: Tasks 1–2 are small unit tests (no I/O beyond `t.TempDir()`), Tasks 3–5 are
medium (localhost sockets, kong parsing), Task 6 is the single large end-to-end check.

## Deliverables note

The slash command asked for `tasks/plan.md` and `tasks/todo.md`; plan mode only permits
writing this plan file. On approval, step 0 is to write this plan to `tasks/plan.md` and the
eight tasks + three checkpoints as a checkbox list in `tasks/todo.md`, with each code task
split into its RED / GREEN / REFACTOR boxes so the cycle is visibly tracked.
