#pragma once
#include <cstdint>
#include <cstddef>

namespace kmp {

// Protocol
// v2: breaking handshake change — adds password / host-token / session-token
// authentication fields (server security hardening, audit 2026-06-03).
constexpr uint32_t KMP_PROTOCOL_VERSION = 2;
constexpr uint16_t KMP_DEFAULT_PORT     = 27800;
constexpr int      KMP_MAX_PLAYERS      = 16;
constexpr int      KMP_MAX_NAME_LENGTH  = 31;

// Authentication (handshake)
constexpr int      KMP_MAX_PASSWORD_LENGTH = 63;  // operator server password
constexpr int      KMP_SESSION_TOKEN_LENGTH = 32; // hex string (16 random bytes); secret identity token

// Resource limits (DoS hardening — audit 2026-06-03)
constexpr uint32_t    KMP_MAX_PACKET_SIZE     = 64 * 1024; // reject incoming packets larger than this
constexpr std::size_t KMP_MAX_ENTITIES_PER_PLAYER = 64;    // per-player entity/build cap
constexpr std::size_t KMP_MAX_SAVED_PLAYERS   = 256;       // cap on persisted reconnect records
constexpr int         KMP_MAX_CONNECTIONS_PER_IP = 4;      // simultaneous connections from one address
constexpr int         KMP_RATE_LIMIT_MAX_MSGS = 15;        // burst-sensitive C2S messages per second
constexpr float       KMP_RATE_LIMIT_WINDOW_SEC = 1.0f;
// Anti-teleport: max plausible movement speed for a position update (m/s). Kenshi
// foot speed tops out ~15 m/s; this is generous (≈13×) to absorb 5× game-speed and
// lag catch-up without false-rejecting legit movement, while still blocking the
// instant cross-map teleport that defeats the combat/door distance gates (I-01/02/12).
// Tunable — lower it if cheating teleports stay viable, raise it if legit moves are dropped.
constexpr float       KMP_MAX_MOVE_SPEED      = 200.0f;

// Tick rates
constexpr int   KMP_TICK_RATE           = 20;      // 20 Hz state sync
constexpr int   KMP_TICK_INTERVAL_MS    = 1000 / KMP_TICK_RATE; // 50ms
constexpr float KMP_TICK_INTERVAL_SEC   = 1.0f / KMP_TICK_RATE;

// Interpolation
constexpr float KMP_INTERP_DELAY_SEC    = 0.1f;    // 100ms default interpolation buffer
constexpr int   KMP_MAX_SNAPSHOTS       = 8;        // Ring buffer per entity (spec: 8)
constexpr float KMP_INTERP_DELAY_MIN    = 0.05f;   // 50ms minimum adaptive delay
constexpr float KMP_INTERP_DELAY_MAX    = 0.2f;    // 200ms maximum adaptive delay

// Extrapolation & snap correction
constexpr float KMP_EXTRAP_MAX_SEC      = 0.25f;   // 250ms max extrapolation beyond last snapshot
constexpr float KMP_SNAP_THRESHOLD_MIN  = 5.0f;    // Below this: smooth blend correction
constexpr float KMP_SNAP_THRESHOLD_MAX  = 50.0f;   // Above this: instant teleport
constexpr float KMP_SNAP_CORRECT_SEC    = 0.15f;   // 150ms snap correction blend duration
constexpr float KMP_JITTER_EMA_ALPHA    = 0.1f;    // EMA smoothing factor for jitter estimation

// Networking
constexpr int   KMP_CHANNEL_COUNT       = 3;
constexpr int   KMP_CHANNEL_RELIABLE_ORDERED   = 0;
constexpr int   KMP_CHANNEL_RELIABLE_UNORDERED = 1;
constexpr int   KMP_CHANNEL_UNRELIABLE_SEQ     = 2;

// Bandwidth limits (sized for 16 players × 20 Hz position updates)
constexpr uint32_t KMP_UPSTREAM_LIMIT   = 2 * 1024 * 1024; // 2 MB/s (server→client fan-out)
constexpr uint32_t KMP_DOWNSTREAM_LIMIT = 2 * 1024 * 1024; // 2 MB/s (client→server headroom)

// Timeouts
constexpr uint32_t KMP_CONNECT_TIMEOUT_MS  = 5000;
constexpr uint32_t KMP_KEEPALIVE_INTERVAL  = 1000;  // 1 second
constexpr uint32_t KMP_TIMEOUT_MS          = 10000;  // 10 seconds

// Zone system
constexpr float KMP_ZONE_SIZE           = 750.f;   // Meters per zone (estimated)
constexpr int   KMP_INTEREST_RADIUS     = 1;       // ±1 zone (3x3 grid)
constexpr float KMP_AUTHORITY_HYSTERESIS = 64.0f;  // Units before zone authority transfer

// Position sync thresholds
constexpr float KMP_POS_CHANGE_THRESHOLD = 0.1f;   // Minimum movement to send update
constexpr float KMP_ROT_CHANGE_THRESHOLD = 0.01f;  // Minimum rotation change

// Entity limits
constexpr int KMP_MAX_ENTITIES_PER_ZONE  = 512;
constexpr int KMP_MAX_SYNC_ENTITIES      = 2048;   // Total synced entities per client

// ID range partitioning (spec §3.6)
constexpr uint32_t KMP_ID_PLAYER_MIN     = 1;
constexpr uint32_t KMP_ID_PLAYER_MAX     = 255;
constexpr uint32_t KMP_ID_NPC_MIN        = 256;
constexpr uint32_t KMP_ID_NPC_MAX        = 8191;
constexpr uint32_t KMP_ID_BUILDING_MIN   = 8192;
constexpr uint32_t KMP_ID_BUILDING_MAX   = 16383;
constexpr uint32_t KMP_ID_CONTAINER_MIN  = 16384;
constexpr uint32_t KMP_ID_CONTAINER_MAX  = 24575;
constexpr uint32_t KMP_ID_SQUAD_MIN      = 24576;
constexpr uint32_t KMP_ID_SQUAD_MAX      = 32767;

} // namespace kmp
