# Kenshi-Online Security Audit — 2026-06-03

## Executive Summary

This audit consolidates 38 independently verified findings against the Kenshi-Online multiplayer mod (KenshiMP.Core injected client, KenshiMP.Server authoritative server, KenshiMP.Common protocol, KenshiMP.MasterServer matchmaking). The threat model treats the **client as hostile** (a player controlling a modified Core DLL or a hand-crafted ENet client) and the **server as the authoritative trust boundary**.

After deduplication, the 38 findings collapse to **24 distinct issues** tracing to **6 root causes**. The picture is sharp:

- **The server has no authentication of any kind.** A configured password is loaded from disk but never compared; host/admin privilege is granted to whoever connects first; entity ownership is reclaimed on a self-reported display name with no secret. Any attacker who reaches the UDP port owns the session.
- **Several C2S handlers grant authority the server should reserve to itself.** A single crafted packet can kill any character (`C2S_CombatDeath`), godmode or remote-KO via attacker-supplied health (`C2S_CombatKO`), rewrite global faction standings (`C2S_FactionRelation` with `causerEntityId=0`), or remotely unlock any base door (`C2S_DoorInteract`).
- **Attacker-controlled values are stored, broadcast, and persisted without validation.** Unvalidated floats (NaN/Inf health) and invalid-UTF-8 template names reach the JSON world-save path and **crash the server or permanently wipe the saved world** on the next autosave/restart.
- **The DoS surface is wide because the rate-limiting / ban / per-player-cap infrastructure is fully implemented but never wired in.** `PlayerManager` (rate limit, IP ban, unique-name, per-player entity cap) is defined in the server tree but **never instantiated in `GameServer`** — its methods have zero call sites. This single fact explains the spawn-flood, build-flood, chat-flood, zone-flood, IP-ban-bypass, and saved-player-leak findings.

A large secondary cluster of client-side thread-safety and pointer-lifetime races is **real but not attacker-reachable** under this threat model (they require a hostile/compromised server, which is outside scope). They are tracked at the bottom as latent robustness work.

**Priority:** Fix authentication (Root Cause 1) first — it gates the severity of everything else, because today there is no notion of an authorized actor at all. Then close the authority bypasses (RC2) and the persistence-crash/wipe validation gaps (RC3), which are critical/high and trivially reachable.

---

## Severity Table (deduplicated, by verified severity + attacker-reachability)

| # | Issue | Verified Severity | Attacker-Reachable | Root Cause | Primary Location |
|---|-------|-------------------|--------------------|-----------|------------------|
| I-01 | One-shot kill any entity via `C2S_CombatDeath` | critical | yes | RC2 | server.cpp:1855 |
| I-02 | Godmode / remote-KO via attacker health in `C2S_CombatKO` | high | yes | RC2 | server.cpp:1810 |
| I-03 | Server password loaded but never checked at handshake | high | yes | RC1 | server.cpp:520 |
| I-04 | Host/admin privilege granted by connection order, no credential | high | yes | RC1 | server.cpp:609-611 |
| I-05 | Name-based reconnect entity takeover (no token) | high | yes | RC1 | server.cpp:592-593 |
| I-06 | Global faction standings rewrite via `causerEntityId=0` bypass | high | yes | RC2 | server.cpp:1681 |
| I-07 | No per-player spawn cap / rate limit (dead `PlayerManager`) | high | yes | RC5 | server.cpp:1097 |
| I-08 | Pipeline relay forwards unbounded attacker payload (amplification) | high | yes | RC5 | server.cpp:508 |
| I-09 | Invalid-UTF-8 `templateName` crashes server on autosave | high | yes | RC3 | world_persistence.cpp:80 |
| I-10 | NaN/Inf health persists as JSON null → permanent world wipe | high | yes | RC3 | world_persistence.cpp:190 |
| I-11 | `MsgAdminCommand.textParam` unterminated → stack over-read broadcast | high | yes | RC4 | server.cpp:2098 |
| I-12 | Remote door unlock/open, no ownership or proximity check | medium | yes | RC2 | server.cpp:2009 |
| I-13 | `C2S_LimbHealth` unvalidated float (NaN/Inf) store + broadcast | medium | yes | RC3 | server.cpp:1898 |
| I-14 | `HandleBuildRequest` inserts without entity-limit check | medium | yes | RC5 | server.cpp:936 |
| I-15 | No maximum incoming packet size enforcement | medium | yes | RC5 | server.cpp:304 |
| I-16 | Pre-handshake peer-slot exhaustion (no per-IP limit / short timeout) | medium | yes | RC5 | server.cpp:70 |
| I-17 | IP ban list is dead code — kicked clients reconnect freely | medium | yes | RC5 | player_manager.cpp:76 |
| I-18 | Master server unauthenticated register + spoofed externalIP + serverName over-read | medium | yes | RC1/RC4/RC5 | MasterServer/main.cpp:62-84 |
| I-19 | `m_savedPlayers` grows without bound (no cap/TTL) | low | yes | RC5 | server.cpp:264 |
| I-20 | `HandleZoneRequest` full-map scan, no per-player rate limit | low | yes | RC5 | server.cpp:1213 |
| I-21 | Chat broadcast at sender rate, no per-player rate limit | low | yes | RC5 | server.cpp:885 |
| I-22 | Server password stored cleartext on disk | low | no | RC3-adj | Common/config.cpp:161 |
| I-23 | Docker runtime runs as root (no USER directive) | low | no | (deploy) | Dockerfile:21 |
| I-24 | Latent client-side thread-safety / pointer-lifetime races (cluster) | low | no | RC6 | (see RC6) |

---

## Root-Cause Analysis

### RC1 — No authentication or identity verification at the trust boundary

The server has no concept of an authorized actor. Three distinct expressions, all on the handshake path, all attacker-reachable:

- **Password never checked (I-03).** `ServerConfig::password` is loaded (config.cpp:133) and saved (config.cpp:161), but `MsgHandshake` (messages.h:13-20) has no password field and `HandleHandshake` (server.cpp:520-615) never references `m_config.password`. An operator who sets a password gets no protection.
- **Host/admin by connection order (I-04).** `if (m_hostPlayerId == 0) { m_hostPlayerId = id; }` (server.cpp:609-611) grants host — which gates `C2S_AdminCommand` kick/time/weather/announce (server.cpp:2078) and building dismantle/repair — to the first connector, with no credential. On host disconnect the role passes to `m_players.begin()->first` (server.cpp:285-289), again unauthenticated.
- **Name-based reconnect takeover (I-05).** On disconnect, entities are saved under the sanitized display name with `owner=0` (server.cpp:261-265). On the next handshake, `m_savedPlayers.find(sanitizedName)` (server.cpp:592-606) reassigns all those entities to the new connection with **no token**. Names are public via `S2C_PlayerJoined`. After restart, `LoadWorld` resets every `owner=0`, making the whole world trivially claimable.

Master-server registration (I-18) shares this cause: `HandleRegister` (MasterServer/main.cpp:62) authenticates nothing beyond a public protocol-version constant.

**Architectural note:** fixing this requires a **breaking wire-format decision** (add a credential and a session token to `MsgHandshake`) and a policy decision on how host status is designated. Flagged in remediation Phase 1 — do not guess the scheme.

### RC2 — C2S handlers grant authority the server must reserve to itself (missing or bypassable ownership/authorization checks)

The core security property of an authoritative server — a client may only affect entities it owns, with physically possible values — is violated in four handlers:

- **`C2S_CombatDeath` (I-01, critical).** Ownership gate passes when the *killer* entity is owned by the sender (server.cpp:1879), which is always true for the attacker's own character. No distance, no health, no prior-combat check. `it->second.alive = false` executes on any target (server.cpp:1882) and is broadcast. Any entity on the map can be killed with one packet, bypassing the authoritative `HandleAttackIntent`/`ResolveCombat` path.
- **`C2S_CombatKO` (I-02, high).** Writes attacker-supplied `chestHealth` directly to `health[0]` (server.cpp:1837) with no clamp/NaN check; the gate accepts both victim-owner (godmode: set own health to 100) and attacker-owner (forced KO: set victim to -999).
- **`C2S_FactionRelation` (I-06, high).** Ownership is only checked when `causerEntityId != 0` (server.cpp:1692); setting it to 0 ("system") bypasses the check entirely and lets any client rewrite global faction standings, broadcast to all.
- **`C2S_DoorInteract` (I-12, medium).** Checks actor ownership and building existence but not building ownership or proximity (server.cpp:2014-2036) — any door/gate on the map can be remotely unlocked, defeating base defense.

### RC3 — Attacker-controlled values stored, broadcast, and persisted without finite/range/encoding validation

Position floats are validated (`std::isnan`/`isinf`/bounds at server.cpp:762-768) but the same discipline is not applied to health floats, status fields, or string content:

- **Invalid-UTF-8 `templateName` (I-09, high).** Spawn names are length-checked (≤255) but not content-validated (server.cpp:1067-1072), stored raw, then serialized via `j.dump(2)` with the default strict error handler (world_persistence.cpp:80), which throws `type_error::316` on invalid UTF-8 with **no try/catch in the autosave/shutdown stack** — terminating the server within 60 s.
- **NaN/Inf health → world wipe (I-10, high).** Spawn health floats are unvalidated (server.cpp:1082-1089), persist as JSON `null`, and on the next load throw `type_error::302`, which `LoadWorldFromFile` swallows as `return false`, making `LoadWorld` "start fresh" — **permanently erasing all saved progress** on every subsequent restart.
- **`C2S_LimbHealth` floats (I-13, medium)** stored and rebroadcast verbatim (server.cpp:1907-1919); clients write them into game memory (packet_handler.cpp:1203), risking NaN propagation / client crash.
- Related: cleartext password on disk (I-22, low, not network-reachable) is a secrets-at-rest gap in the same config/persistence layer.

### RC4 — Fixed network buffers used as C-strings without forced null-termination

`pack(1)` char arrays are filled verbatim by `ReadRaw` and then passed to `std::string`'s implicit `const char*` constructor (strlen), reading past the buffer if the attacker omits a null byte:

- **`MsgAdminCommand.textParam[128]` (I-11, high).** server.cpp:2098/2150 over-read the server stack and broadcast the result to all clients. The client side already force-terminates the same fixed buffers (packet_handler.cpp:302/323/1528) — the server does not.
- **Master `serverName[64]` (part of I-18).** `srv.serverName = msg.serverName` (MasterServer/main.cpp:84) reads into the adjacent `externalIP[46]` field when unterminated.

### RC5 — No resource limits or rate limiting; the limiter/ban/cap infrastructure is dead code

The unifying insight: **`PlayerManager` is fully implemented but never instantiated in `GameServer`.** `CheckRateLimit`/`RecordMessage` (player_manager.cpp:111-128), `WouldExceedLimit` (entity_manager.cpp:112), `BanIP`/`IsIPBanned` (player_manager.cpp:76), and `MakeUniqueName`/`IsNameTaken` have **zero call sites** in server.cpp. `GameServer` has no `PlayerManager` member. This single gap produces:

- Per-player spawn cap absent — only global cap checked (I-07, high; server.cpp:1097).
- Pipeline relay forwards unbounded payload (I-08, high; server.cpp:508) — ENet default max packet is 32 MB, amplified to every peer.
- Build insert with no entity cap (I-14, medium; server.cpp:936).
- No max incoming packet size (I-15, medium; server.cpp:304).
- Pre-handshake peer-slot exhaustion, no per-IP limit (I-16, medium; server.cpp:70).
- IP ban is inoperable; kicked clients reconnect (I-17, medium; player_manager.cpp:76).
- Unbounded `m_savedPlayers` growth (I-19, low; server.cpp:264).
- Zone-request full-map scan, no cooldown (I-20, low; server.cpp:1213).
- Chat flood, no per-player rate limit (I-21, low; server.cpp:885).
- Master-server unbounded `g_servers` growth (part of I-18).

### RC6 — Latent client-side thread-safety and pointer-lifetime races (NOT attacker-reachable)

A cluster of real C++ memory-model / lifetime defects inside the injected Core DLL. Under this threat model the **server is trusted**, so these require a hostile/compromised server to trigger and are therefore **not attacker-reachable** by the in-scope adversary (a hostile client peer cannot inject S2C messages into another client's ENet session). Tracked as I-24, severity low. Members:

- Dangling game-object pointer in S2C combat/stat handlers (packet_handler.cpp:693, no CharacterDestroy hook).
- Stale raw game-object pointer after lock release (sync_orchestrator.cpp:461, :510, :863).
- S2C handlers mutate game memory on the network thread concurrently with the game tick (packet_handler.cpp:40).
- `GetPing` reads `m_serverPeer` without `m_enetMutex` (client.cpp:193).
- `m_isHost` non-atomic cross-thread (core.h:295); `m_initialized` non-atomic (pipeline_orchestrator.h:119).
- Background workers read live character memory concurrent with game tick (core.cpp:3318).
- `KenshiSDK::Update()` reads `m_previous` outside mutex (kenshi_sdk.cpp:100).
- `native_hud` holds `m_chatMutex` across MyGUI calls (native_hud.cpp:379); `DecodeUString` reinterpret_cast layout assumption (mygui_bridge.cpp:401).
- Inline char_tracker hook hardcodes RBX assumption (char_tracker_hooks.cpp:109).

---

## Deduplicated Issue List (with file:line and attacker-reachability)

**Merges applied:**
- Pipeline relay `server.cpp:498` + `server.cpp:508` → **I-08**. Conflicting verified severities (low vs high) reconciled to **high**: the high verifier confirmed the concrete 32 MB ENet default ceiling (`enet.h:211`, `host.c:104`) that makes the amplification real; the low verifier missed it.
- Name-based reconnect `server.cpp:592` + `server.cpp:593` → **I-05**.
- Host/admin by connection order `server.cpp:609` + `server.cpp:610` → **I-04**.
- Master-server registration `main.cpp:80` (spoofed externalIP) + `main.cpp:62` (unauth register, serverName over-read, unbounded growth) → **I-18**.

**Kept separate (different defects despite proximity):** I-22 (cleartext password on disk, config.cpp:161) vs I-03 (password never checked at handshake, server.cpp:520).

| ID | Title | File:Line(s) | Verified Sev | Reachable |
|----|-------|--------------|--------------|-----------|
| I-01 | One-shot kill via `C2S_CombatDeath` | server.cpp:1855-1893 | critical | yes |
| I-02 | Godmode / remote-KO via `C2S_CombatKO` | server.cpp:1810-1850 (write :1837) | high | yes |
| I-03 | Password loaded but never checked | server.cpp:520-615; config.h:31; messages.h:13-20 | high | yes |
| I-04 | Host/admin by connection order | server.cpp:609-611, :285-289, :2078 | high | yes |
| I-05 | Name-based reconnect entity takeover | server.cpp:592-607, :261-265; messages.h:13-20 | high | yes |
| I-06 | Faction rewrite via `causerEntityId=0` | server.cpp:1681-1708 (bypass :1692) | high | yes |
| I-07 | No per-player spawn cap / rate limit | server.cpp:1097-1102; entity_manager.cpp:112; player_manager.cpp:111-128 | high | yes |
| I-08 | Pipeline relay unbounded payload amplification | server.cpp:498-513 (relay :508) | high | yes |
| I-09 | Invalid-UTF-8 templateName crashes autosave | world_persistence.cpp:80; server.cpp:1067-1072, :1116 | high | yes |
| I-10 | NaN/Inf health → permanent world wipe | world_persistence.cpp:190, :230; server.cpp:1082-1089, :1119; :1441-1449 | high | yes |
| I-11 | `textParam` unterminated stack over-read | server.cpp:2098, :2150 (read :2075) | high | yes |
| I-12 | Remote door unlock, no ownership/proximity | server.cpp:2009-2037 | medium | yes |
| I-13 | `C2S_LimbHealth` unvalidated float store/broadcast | server.cpp:1898-1920; packet_handler.cpp:1203 | medium | yes |
| I-14 | Build insert with no entity cap | server.cpp:936 | medium | yes |
| I-15 | No max incoming packet size | server.cpp:304 | medium | yes |
| I-16 | Pre-handshake peer-slot exhaustion | server.cpp:70-71, :229-244 | medium | yes |
| I-17 | IP ban list dead code | player_manager.cpp:76-88; server.cpp:229-243 | medium | yes |
| I-18 | Master register unauth + spoofed IP + serverName over-read + growth | MasterServer/main.cpp:62-103, :80, :84, :95 | medium | yes |
| I-19 | `m_savedPlayers` unbounded growth | server.cpp:264, :188-211 | low | yes |
| I-20 | Zone-request scan, no rate limit | server.cpp:1213-1264 | low | yes |
| I-21 | Chat flood, no rate limit | server.cpp:885-896 | low | yes |
| I-22 | Cleartext password on disk | Common/src/config.cpp:161; config.h:31 | low | no |
| I-23 | Docker runs as root | Dockerfile:21-39; docs/LINUX-SERVER.md:29 | low | no |
| I-24 | Client-side thread-safety / lifetime races (cluster) | packet_handler.cpp:40,:693; sync_orchestrator.cpp:461; client.cpp:193; core.h:295; pipeline_orchestrator.h:119; core.cpp:3318; kenshi_sdk.cpp:100; native_hud.cpp:379; mygui_bridge.cpp:401; char_tracker_hooks.cpp:109 | low | no |

---

## Phased Remediation Plan

Each phase fixes one root cause across all its locations with a single authoritative mechanism (DRY), rather than patching sites individually.

### Phase 1 — Authentication & identity (RC1) — **requires architectural decision**
Addresses I-03, I-04, I-05, and the auth half of I-18.

**Decision to make first (do not guess):**
1. Wire format: add a credential field and a server-issued **session token** to `MsgHandshake` (breaking change — bump `KMP_PROTOCOL_VERSION` and update all consumers in one commit).
2. Identity source: session token vs. a stable platform identity (e.g. Steam ID) for entity persistence.
3. Host-designation policy: operator password / host token vs. server-console-only designation (replace connection-order assignment).

**Implementation once decided:**
- `KenshiMP.Common/include/kmp/messages.h` — extend `MsgHandshake`; add a wrong-password reject reason; bump protocol version (`constants.h`).
- `KenshiMP.Server/server.cpp` `HandleHandshake` — constant-time compare against `m_config.password`; issue and store a per-session token; require the token (not the display name) for entity reclaim; gate host status on the chosen credential.
- `KenshiMP.Server/server.h` — add token field to `SavedPlayer`.
- `KenshiMP.MasterServer/main.cpp` — require a shared registration secret; always use the peer's real IP as the key (ignore self-reported `externalIP`).

**Files:** messages.h, constants.h, server.cpp, server.h, MasterServer/main.cpp, config.h/config.cpp.

### Phase 2 — Server-side ownership/authorization on C2S handlers (RC2)
Addresses I-01, I-02, I-06, I-12.

- Add one authoritative ownership-assertion helper in `KenshiMP.Server` (e.g. `EntityManager::IsOwnedBy`, already declared) and apply it uniformly.
- `HandleCombatDeath` (server.cpp:1855): remove client death authority or restrict to victim-self-reports; derive deaths from `ResolveCombat` only.
- `HandleCombatKO` (server.cpp:1810): remove client health authority or require victim-owner + value ≤ current server health + clamp/NaN-reject.
- `HandleFactionRelation` (server.cpp:1681): reject `causerEntityId == 0`; require an owned causer entity (or host-only).
- `HandleDoorInteract` (server.cpp:2009): add building-ownership and proximity checks (`GetEntitiesInRadius` exists).

**Files:** KenshiMP.Server/server.cpp, entity_manager.{h,cpp}, combat_resolver.cpp (if death/KO derivation moves there).

### Phase 3 — Single ingress validator for finite/range/UTF-8 + persistence hardening (RC3)
Addresses I-09, I-10, I-13; defense-in-depth for I-22.

- Add one authoritative value-validation module at C2S ingress (`KenshiMP.Server`): a `validateFinite(float, min, max)` helper applied to all health/status floats (LimbHealth server.cpp:1898, CombatKO health, spawn health server.cpp:1082-1089), and a UTF-8 sanitize/reject for `templateName` at server.cpp:1067-1072.
- `world_persistence.cpp`: wrap `j.dump(2)` (line 80) in try/catch and/or pass `error_handler_t::replace`; add a symmetric finite-check repair pass in `LoadWorldFromFile` (mirror the position check) so a corrupt save is repaired, not wiped.
- (I-22) store the password hashed and/or document `chmod 600` for server.json.

**Files:** KenshiMP.Server/server.cpp, world_persistence.cpp, Common/config.cpp.

### Phase 4 — Null-terminating bounded reader for fixed char buffers (RC4)
Addresses I-11 and the serverName half of I-18.

- Introduce one helper that force-terminates fixed char arrays immediately after `ReadRaw` (the pattern the client already uses at packet_handler.cpp:302), and apply it before any `std::string` construction from a network buffer.
- `server.cpp:2075` (textParam), `MasterServer/main.cpp:84` (serverName).

**Files:** KenshiMP.Server/server.cpp, KenshiMP.MasterServer/main.cpp (optionally a shared helper in Common/protocol.h).

### Phase 5 — Wire in `PlayerManager`, add caps and a packet-size gate (RC5)
Addresses I-07, I-08, I-14, I-15, I-16, I-17, I-19, I-20, I-21, and the growth half of I-18.

- **Instantiate a `PlayerManager` member in `GameServer`** and call its existing methods:
  - `RecordMessage` on every C2S handler; `CheckRateLimit` for burst-sensitive handlers (spawn, attack, chat, zone) — fixes I-07, I-20, I-21.
  - `WouldExceedLimit` before each entity insert in `HandleEntitySpawnReq` and `HandleBuildRequest` — fixes I-07, I-14.
  - `IsIPBanned` in `HandleConnect`; `BanIP` in the kick path; persist the ban list — fixes I-17.
- Add `KMP_MAX_PACKET_SIZE` gate in `HandlePacket` (server.cpp:304) and a per-message ceiling on the pipeline relay (server.cpp:508) — fixes I-08, I-15.
- Reduce pre-handshake dwell time and/or add per-IP connect rate limiting in `HandleConnect`; reduce `peerSlots` — fixes I-16.
- Cap/TTL `m_savedPlayers`; purge in orphan cleanup — fixes I-19.
- Master server: per-peer registration cap + total cap — fixes I-18 growth.

**Files:** KenshiMP.Server/server.h, server.cpp, player_manager.{h,cpp}, entity_manager.{h,cpp}, Common/constants.h, MasterServer/main.cpp.

### Phase 6 — Client-side thread-safety / lifetime hardening (RC6) — lowest priority (not attacker-reachable)
Addresses I-24 (and I-23 deployment hardening as a parallel quick win).

- Make `m_isHost` and `m_initialized` `std::atomic<bool>` (core.h:295, pipeline_orchestrator.h:119).
- Snapshot-then-render for chat (native_hud.cpp:379); cache `roundTripTime` atomically for `GetPing` (client.cpp:193).
- Install the CharacterDestroy hook (body exists at entity_hooks.cpp:988) so the registry invalidates freed objects; add a deferred-mutation queue so S2C handlers mutate game memory on the game thread (mirror `ApplyRemotePositionsDirect`); add generation-counter validation in the registry for the raw-pointer race (sync_orchestrator.cpp).
- (I-23) add a non-root `USER` directive to the Dockerfile runtime stage.

**Files:** KenshiMP.Core/core.h, core.cpp, sync/pipeline_orchestrator.h, ui/native_hud.cpp, net/client.cpp, hooks/entity_hooks.cpp, net/packet_handler.cpp, sync/sync_orchestrator.cpp; Dockerfile.

---

*Report generated 2026-06-03. Read-only audit; no source files were modified.*

---

# Remediation & Verification Addendum — 2026-06-03

All phases were implemented on the Linux-buildable tree (Common + Server + MasterServer) plus the
Core client handshake match. A scoped re-audit (independent verifiers per root cause + Opus synthesis)
then checked each finding and hunted regressions. Server-side auth was verified **at runtime** with a
throwaway protocol-v2 ENet client against the live server.

## Closure status (after fixes + regression pass)

| ID | Status | Note |
|----|--------|------|
| I-03 password check | **closed** | runtime: wrong/empty password → reject code 4; correct → ack |
| I-04 host designation | **closed** | runtime: host granted only by matching host token; first-connector path gone when token set |
| I-05 reconnect takeover | **closed** | reclaim keyed on secret session token; **SaveWorld** also fixed to key by token (regression R1); runtime: name-as-token → no reclaim, valid token → reclaim 1/1; save on disk keyed by token |
| I-06 faction causer=0 | **closed** | host-only for system changes; NaN relation also rejected (R7) |
| I-07/I-14 per-player caps | **closed** | `EntityManager::WouldExceedLimit` wired into spawn + build |
| I-08/I-15 packet size / relay amplification | **closed** | 64 KB ingress gate before relay |
| I-09 UTF-8 templateName | **closed** | ingress reject + `error_handler::replace` on dump |
| I-10 NaN/Inf → world wipe | **closed** | health sanitized + defensive load; **spawn position** NaN also guarded (regression R2) |
| I-11 admin textParam over-read | **closed** | force-NUL before use |
| I-12 remote door | **partially-closed** | proximity + owner/host gate added; residual = teleport vector (see below); NaN-coord fail-open closed by R2 |
| I-13 limb health NaN | **closed** | per-limb sanitize in place |
| I-16 peer-slot exhaustion | **closed** | per-IP connection cap + shorter pre-handshake timeout (generous timeout restored post-handshake, R8) |
| I-17 IP ban | **closed** | `IsIPBanned` at connect, `BanIP` on admin ban (in-memory; not persisted across restart) |
| I-18 master register | **partially-closed** | real-IP keying (anti-spoof), serverName null-term, total+per-peer caps. Shared registration secret deliberately omitted (public registry, operator friction) |
| I-19 saved-player growth | **closed** | `KMP_MAX_SAVED_PLAYERS` cap |
| I-20/I-21 zone/chat flood | **closed** | `PlayerManager` rate-limit wired into burst-prone handlers |
| I-01 one-shot kill | **partially-closed** | combat-range gate added; **reduced not eliminated** (see below) |
| I-02 godmode/remote-KO | **partially-closed** | NaN reject + clamp + cross-player range gate; residuals below |
| I-22 cleartext password | open (pre-existing) | secrets-at-rest; not addressed |
| I-23 docker root | **closed** | non-root `USER` in Dockerfile |
| I-24 client races (RC6) | deferred | not attacker-reachable; needs a Windows build+test loop |

## Residual / partially-closed (documented, not silently shipped)

1. **Combat & door teleport vector (I-01, I-02, I-12).** The distance/proximity gates use server-tracked
   positions, but `HandlePositionUpdate` validates finiteness/range only — it has **no speed/teleport cap**.
   An attacker can move an owned entity to the victim/door coordinate, then report the kill/KO/interaction
   at distance 0. The gates change "one-shot anything anywhere" into "must co-locate an owned entity first"
   (visible, constrained) — a real reduction, not elimination. **Keystone follow-up: a movement-delta speed
   cap in `HandlePositionUpdate`** (deferred here: a mis-tuned cap breaks legitimate movement and needs
   playtesting). I-02 also has a minor residual: a client may report KO on its own entity at clamped
   health (bleed-out suppression) — low impact in a host-authoritative combat model.

2. **Combat is client-authoritative by design.** The client never sends `C2S_AttackIntent`; the server's
   `ResolveCombat` is effectively dead. Each client's Kenshi engine computes and reports KO/death. Fully
   server-authoritative combat would require simulating Kenshi's engine server-side — out of scope.

3. **MasterServer (I-18):** no registration secret (public browser); CGNAT/multi-homed servers are listed
   under their outbound IP because self-reported `externalIP` is now ignored (anti-spoof tradeoff).

4. **RC6 client thread/lifetime races (I-24):** not attacker-reachable (needs a hostile server). The trivial
   atomics and the heavier CharacterDestroy-hook / deferred-mutation-queue / generation-counter work were
   **not** auto-applied — they sit in a working Windows-only injection hot path that can't be compiled or
   tested here. Recommended for a dedicated Windows build+test pass.

5. **I-22 cleartext secrets at rest:** server password (and now host token / per-server tokens client-side)
   are stored in plaintext JSON. Recommend `chmod 600` and/or hashing.

## Behavioral changes operators must know

- **Host/admin now requires a `hostToken`.** Set matching `hostToken` in the server `server.json` **and**
  the host player's `client.json` to designate an in-game admin. If no `hostToken` is configured, the
  server falls back to first-connector-host (casual/LAN), and system (`causer=0`) faction changes work.
- **Breaking protocol change (v1→v2).** The client DLL (`KenshiMP.Core`) must be rebuilt on Windows to
  speak v2; the prebuilt `dist/KenshiMP.Core.dll` will be rejected with a version-mismatch.
- **World save format v3** (token-keyed players). Old v2 saves still load (name-keys become dead tokens).

*Verification: Linux build green; server auth (password accept/reject, host-token, token reclaim, NaN/flood
rejection) confirmed at runtime with a protocol-v2 test client. Core client + RC6 are Windows-only and were
verified by inspection only.*

## Convergence round (second adversarial pass over the regression fixes)

A second scoped verification reviewed the regression-fix code itself (R1–R8) and swept **every** C2S
float handler for the parallel-path class that R2 belonged to. Verdict: **CONVERGED**.

- **Parallel-path float sweep: clean** — after fixing **R9** (`HandleMoveCommand` rebroadcast NaN/Inf move
  targets unvalidated — same class as the spawn-position miss), every C2S handler that stores/broadcasts/
  persists an attacker float now validates finiteness/range.
- **R3 follow-up fixed** — `PlayerManager::m_rateLimits` map entries were never evicted on disconnect
  (connect→message→disconnect churn grew the map unbounded, ~26 MB/day). Added `RemoveRateLimit`, called in
  `HandleDisconnect`.
- **Host-authority split (R5 resolution)** — admin commands (kick/ban/time/weather) now require a
  **token-authenticated** host (`m_hostAuthenticated`). A first-connector gameplay host (no `hostToken`
  configured) gets gameplay coordination only, **not** admin authority — so I-04 stays closed even on a
  password-but-no-hostToken server. Host state is also rolled back on the OOM packet-create failure path.
- **Teleport keystone now CLOSED.** `HandlePositionUpdate` enforces `KMP_MAX_MOVE_SPEED` (200 m/s):
  a jump faster than that is rejected and the entity keeps its last valid server position. Runtime-verified
  (84 km jump in 0.2 s rejected; legit short move accepted). This closes the vector that undermined
  **I-01, I-02, I-12** — a cheater can no longer teleport an owned entity onto a victim/door to satisfy the
  distance gate; they must physically approach (slow, visible). Residual: combat remains client-authoritative
  by design (a cheater genuinely adjacent can still fast-report a kill), and a client may self-report KO on
  its own entity — both inherent to the host-authoritative model, low impact.
- **Remaining non-blocking residuals** (at/below the accepted bar): RC6 client races (Windows-only, not
  attacker-reachable); master registration secret (omitted by design); I-22 secrets-at-rest; world-load
  throw-on-hand-edited-save (operator-only filesystem path, not attacker-reachable — all network ingress
  paths reject NaN/Inf before persistence).
