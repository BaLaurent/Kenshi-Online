#include "server.h"
#include "entity_manager.h"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <thread>
#include <random>

namespace kmp {

// ── Authentication helpers (protocol v2) ──

// Treat a fixed network char buffer as a C-string safely: force a NUL at the
// final byte before any strlen/std::string conversion (RC4 hardening). Returns
// a std::string bounded by the buffer.
template <size_t N>
static std::string SafeCStr(char (&buf)[N]) {
    buf[N - 1] = '\0';
    return std::string(buf);
}

// Length-independent equality for short auth secrets. Avoids early-out on the
// first mismatching byte. On UDP the timing channel is largely illusory, but
// this costs nothing and documents intent.
static bool SecretEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    return diff == 0;
}

// ── Value validation at ingress (RC3) ──

// Clamp an attacker-supplied health float to a finite, sane range. A NaN/Inf
// health, if stored, propagates into clients' game memory and serializes as
// JSON null — which throws on the next world load and wipes the save (I-10/I-13).
static float SanitizeHealth(float h) {
    if (!std::isfinite(h)) return 100.f;
    return std::clamp(h, -1000.f, 100.f);
}

// Reject strings that are not well-formed UTF-8. nlohmann::json::dump throws on
// invalid UTF-8; an attacker-supplied templateName containing raw bytes would
// otherwise crash the autosave (I-09). (Persistence also uses error_handler::replace
// as a second layer; this stops the bad name from being stored/broadcast at all.)
static bool IsValidUtf8(const std::string& s) {
    size_t i = 0, n = s.size();
    while (i < n) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        size_t extra;
        if (c < 0x80) { extra = 0; }
        else if ((c >> 5) == 0x6) { extra = 1; }
        else if ((c >> 4) == 0xE) { extra = 2; }
        else if ((c >> 3) == 0x1E) { extra = 3; }
        else return false;
        if (i + extra >= n) return false;
        for (size_t k = 1; k <= extra; ++k) {
            if ((static_cast<unsigned char>(s[i + k]) & 0xC0) != 0x80) return false;
        }
        i += extra + 1;
    }
    return true;
}

std::string GameServer::GenerateSessionToken() {
    // Draw 16 bytes straight from the platform CSPRNG (std::random_device is
    // backed by /dev/urandom on glibc Linux and RtlGenRandom on MSVC). We do
    // NOT seed a PRNG and read its stream: a hostile client collecting issued
    // tokens could otherwise reconstruct the generator and derive other
    // players' tokens. Each token is independent CSPRNG output.
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 255);
    static const char* hex = "0123456789abcdef";
    std::string token;
    token.reserve(KMP_SESSION_TOKEN_LENGTH);
    for (int i = 0; i < KMP_SESSION_TOKEN_LENGTH / 2; ++i) {
        int byte = dist(rd);
        token += hex[(byte >> 4) & 0xF];
        token += hex[byte & 0xF];
    }
    return token;
}

// Forward declaration from combat_resolver.cpp
struct CombatResult {
    BodyPart hitPart;
    float cutDamage;
    float bluntDamage;
    float pierceDamage;
    float resultHealth;
    bool wasBlocked;
    bool wasKO;
    bool wasDeath;
};
CombatResult ResolveCombat(const ServerEntity& attacker, ServerEntity& target, uint8_t attackType);

bool GameServer::Start(const ServerConfig& config) {
    m_config = config;

    if (enet_initialize() != 0) {
        spdlog::error("GameServer: ENet initialization failed");
        return false;
    }

    // ── UPnP / Firewall: do this BEFORE listening ──
    // The server doesn't accept any connections until the port is mapped.
    spdlog::info("GameServer: Setting up port forwarding for port {}...", config.port);
    if (m_upnp.AddMapping(config.port, config.port, "UDP", "KenshiMP Server")) {
        std::string extIP = m_upnp.GetExternalIP();
        if (!extIP.empty()) {
            spdlog::info("GameServer: UPnP mapped! Others can join at {}:{}", extIP, config.port);
        } else {
            spdlog::info("GameServer: UPnP mapped port {} successfully", config.port);
        }
    } else {
#ifdef _WIN32
        spdlog::info("GameServer: UPnP unavailable — adding Windows Firewall rule instead...");

        std::string deleteCmd = "netsh advfirewall firewall delete rule name=\"KenshiMP Server\" >nul 2>&1";
        std::system(deleteCmd.c_str());

        std::string addCmd = "netsh advfirewall firewall add rule name=\"KenshiMP Server\" "
                             "dir=in action=allow protocol=UDP localport=" + std::to_string(config.port);
        int result = std::system(addCmd.c_str());
        if (result == 0) {
            spdlog::info("GameServer: Firewall rule added — port {} UDP is open", config.port);
        } else {
            spdlog::warn("GameServer: Failed to add firewall rule (need admin?). "
                         "Port {} may need manual forwarding.", config.port);
        }
#else
        spdlog::info("GameServer: Linux dedicated server — ensure port {} UDP is open in firewall", config.port);
#endif
    }

    // ── Now start listening — port is mapped (or we tried our best) ──
    ENetAddress address;
    address.host = ENET_HOST_ANY;
    address.port = config.port;

    // Use extra ENet peer slots beyond maxPlayers to handle transitional
    // peer states during rapid connect/disconnect cycles. The logical player
    // limit is enforced by m_players.size() in HandleConnect/HandleHandshake.
    int peerSlots = config.maxPlayers * 4;
    m_host = enet_host_create(&address, peerSlots, KMP_CHANNEL_COUNT,
                              KMP_DOWNSTREAM_LIMIT, KMP_UPSTREAM_LIMIT);
    if (!m_host) {
        spdlog::error("GameServer: Failed to create ENet host on port {}", config.port);
        enet_deinitialize();
        return false;
    }

    spdlog::info("GameServer: Listening on port {} — ready for connections", config.port);

    // Auto-save interval from config (default 60s)
    m_autoSaveInterval = 60.f;

    // Connect to master server for server browser registration
    ConnectToMaster();

    return true;
}

void GameServer::Stop() {
    // Deregister from master server
    SendMasterDeregister();
    if (m_masterPeer) {
        enet_peer_disconnect_now(m_masterPeer, 0);
        m_masterPeer = nullptr;
    }
    if (m_masterHost) {
        enet_host_destroy(m_masterHost);
        m_masterHost = nullptr;
    }
    m_masterConnected = false;

    // Remove UPnP port mapping
    if (m_upnp.IsMapped()) {
        m_upnp.RemoveMapping(m_config.port, "UDP");
    }

    // Disconnect all players
    for (auto& [id, player] : m_players) {
        if (player.peer) {
            enet_peer_disconnect(player.peer, 0);
        }
    }

    // Flush
    ENetEvent event;
    while (enet_host_service(m_host, &event, 1000) > 0) {
        if (event.type == ENET_EVENT_TYPE_RECEIVE) {
            enet_packet_destroy(event.packet);
        }
    }

    if (m_host) {
        enet_host_destroy(m_host);
        m_host = nullptr;
    }
    enet_deinitialize();
    m_players.clear();
}

void GameServer::Update(float deltaTime) {
    std::lock_guard lock(m_mutex);
    m_serverTick++;
    m_uptime += deltaTime;

    // Pump ENet events
    ENetEvent event;
    while (enet_host_service(m_host, &event, 0) > 0) {
        switch (event.type) {
        case ENET_EVENT_TYPE_CONNECT:
            HandleConnect(event.peer);
            break;
        case ENET_EVENT_TYPE_RECEIVE:
            HandlePacket(event.peer, event.packet->data, event.packet->dataLength,
                        event.channelID);
            enet_packet_destroy(event.packet);
            break;
        case ENET_EVENT_TYPE_DISCONNECT:
            HandleDisconnect(event.peer);
            break;
        default:
            break;
        }
    }

    // Update game time
    m_timeOfDay += deltaTime * m_config.gameSpeed / 86400.f; // 24h cycle
    if (m_timeOfDay >= 1.f) m_timeOfDay -= 1.f;

    // Broadcast positions every tick
    BroadcastPositions();

    // Time sync every 5 seconds
    m_timeSinceTimeSync += deltaTime;
    if (m_timeSinceTimeSync >= 5.0f) {
        BroadcastTimeSync();
        m_timeSinceTimeSync = 0.f;
    }

    // Entity heartbeat every 5 seconds — clients detect and clean up ghost entities
    m_timeSinceHeartbeat += deltaTime;
    if (m_timeSinceHeartbeat >= 5.0f && !m_entities.empty()) {
        BroadcastEntityHeartbeat();
        m_timeSinceHeartbeat = 0.f;
    }

    // Update player pings
    for (auto& [id, player] : m_players) {
        if (player.peer) {
            player.ping = player.peer->roundTripTime;
        }
    }

    // Periodic orphan entity cleanup — remove entities whose owner is no longer
    // connected (e.g., stale entries loaded from world save files). These are
    // filtered from snapshots but accumulate in m_entities if not cleaned.
    m_timeSinceOrphanCleanup += deltaTime;
    if (m_timeSinceOrphanCleanup >= 30.0f && !m_entities.empty()) {
        std::vector<EntityID> orphans;
        for (const auto& [eid, entity] : m_entities) {
            // owner == 0 means server-owned (world entity), skip those
            if (entity.owner != 0 && !GetPlayer(entity.owner)) {
                orphans.push_back(eid);
            }
        }
        if (!orphans.empty()) {
            for (EntityID eid : orphans) {
                // Broadcast despawn to all remaining players so they remove the ghost
                PacketWriter despawnWriter;
                despawnWriter.WriteHeader(MessageType::S2C_EntityDespawn);
                despawnWriter.WriteU32(eid);
                despawnWriter.WriteU8(2); // reason: orphan cleanup
                Broadcast(despawnWriter.Data(), despawnWriter.Size(),
                         KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
                m_entities.erase(eid);
            }
            spdlog::info("GameServer: Orphan cleanup removed {} entities with no connected owner",
                         orphans.size());
        }
        m_timeSinceOrphanCleanup = 0.f;
        // Trim old rate-limit timestamps so the per-player vectors don't grow
        // unbounded over a long session (RC5).
        m_playerManager.CleanupRateLimits(m_uptime);
    }

    // Auto-save periodically
    m_timeSinceAutoSave += deltaTime;
    if (m_timeSinceAutoSave >= m_autoSaveInterval && !m_entities.empty()) {
        SaveWorld();
        m_timeSinceAutoSave = 0.f;
    }

    // Master server heartbeat
    UpdateMasterConnection(deltaTime);

    // Flush all queued outgoing packets immediately so clients
    // receive responses within the same tick rather than waiting
    // for the next enet_host_service call.
    enet_host_flush(m_host);
}

void GameServer::HandleConnect(ENetPeer* peer) {
    char addrStr[64];
    enet_address_get_host_ip(&peer->address, addrStr, sizeof(addrStr));
    spdlog::info("GameServer: Incoming connection from {}:{}", addrStr, peer->address.port);

    // Enforce IP bans at the door (RC5/I-17 — the ban list was previously dead code).
    if (m_playerManager.IsIPBanned(addrStr)) {
        spdlog::warn("GameServer: Rejecting banned IP {}", addrStr);
        enet_peer_disconnect_now(peer, 0);
        return;
    }

    // Per-IP simultaneous-connection cap (RC5/I-16): blunt pre-handshake peer-slot
    // exhaustion by limiting how many sockets a single address can hold open.
    if (m_host) {
        int sameIp = 0;
        for (size_t i = 0; i < m_host->peerCount; ++i) {
            ENetPeer* p = &m_host->peers[i];
            if (p != peer && p->state == ENET_PEER_STATE_CONNECTED &&
                p->address.host == peer->address.host) {
                sameIp++;
            }
        }
        if (sameIp >= KMP_MAX_CONNECTIONS_PER_IP) {
            spdlog::warn("GameServer: Too many connections from {} ({}), rejecting", addrStr, sameIp);
            enet_peer_disconnect_now(peer, 0);
            return;
        }
    }

    if (m_players.size() >= static_cast<size_t>(m_config.maxPlayers)) {
        spdlog::warn("GameServer: Server full, rejecting connection");
        enet_peer_disconnect(peer, 0);
        return;
    }

    // Connection accepted, wait for handshake.
    // Shorter timeout (5s min / 8s max) so un-authenticated / crashed peers free
    // their slot quickly, limiting pre-handshake slot squatting (I-16).
    enet_peer_timeout(peer, 0, 5000, 8000);
    peer->data = nullptr;
}

void GameServer::HandleDisconnect(ENetPeer* peer) {
    ConnectedPlayer* player = GetPlayer(peer);
    if (player) {
        spdlog::info("GameServer: Player '{}' (ID: {}) disconnected", player->name, player->id);

        // Preserve entities for reconnection — mark them as unowned and record
        // the player→entity mapping so the player can reclaim them later.
        std::vector<EntityID> ownedIds;
        for (auto& [eid, entity] : m_entities) {
            if (entity.owner == player->id) {
                entity.owner = 0; // Unowned until reconnect
                ownedIds.push_back(eid);
            }
        }
        if (!ownedIds.empty() && !player->sessionToken.empty()) {
            // Persist keyed by the secret session token, so only a reconnecting
            // client presenting that token can reclaim these entities (RC1 fix).
            SavedPlayer sp;
            sp.token = player->sessionToken;
            sp.name = player->name;
            sp.entityIds = ownedIds;
            m_savedPlayers[player->sessionToken] = std::move(sp);
            spdlog::info("GameServer: Preserved {} entities for player '{}' (reconnectable via token)",
                         ownedIds.size(), player->name);

            // Cap the saved-player table so a churn of disconnects can't grow it
            // without bound (RC5 / I-19). Evict oldest-by-iteration when over cap.
            while (m_savedPlayers.size() > KMP_MAX_SAVED_PLAYERS) {
                auto victim = m_savedPlayers.begin();
                if (victim->first == player->sessionToken) { ++victim; if (victim == m_savedPlayers.end()) break; }
                m_savedPlayers.erase(victim);
            }
        }

        // Notify others that player left
        PacketWriter writer;
        writer.WriteHeader(MessageType::S2C_PlayerLeft);
        MsgPlayerLeft msg;
        msg.playerId = player->id;
        msg.reason = 0; // disconnect
        writer.WriteRaw(&msg, sizeof(msg));
        BroadcastExcept(player->id, writer.Data(), writer.Size(),
                       KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);

        // Erase player FIRST so host reassignment loop doesn't see them
        PlayerID leavingId = player->id;
        std::string leavingName = player->name;
        m_players.erase(leavingId);
        m_playerManager.RemoveRateLimit(leavingId); // don't leak the rate-limit entry under churn (R3 follow-up)

        // Host left: clear host. Do NOT auto-promote by connection/iterator order
        // (RC1 fix — that granted admin to an arbitrary client with no credential).
        // Host is regained only when a client reconnects with the configured host token.
        if (leavingId == m_hostPlayerId) {
            m_hostPlayerId = 0;
            m_hostAuthenticated = false;
            spdlog::info("GameServer: Host disconnected — host is now unassigned "
                         "(reconnect with the host token to reclaim)");
        }

        // Broadcast system message
        BroadcastSystemMessage(leavingName + " left the game");
    }
    peer->data = nullptr;
}

void GameServer::HandlePacket(ENetPeer* peer, const uint8_t* data, size_t size, int channel) {
    if (size < sizeof(PacketHeader)) return;
    // Reject oversized packets up front. This bounds memory/CPU per message and,
    // because the pipeline-relay handler forwards reader.Remaining() verbatim,
    // also caps the relay amplification at this ceiling (I-08 / I-15) — far below
    // ENet's 32 MB default packet limit.
    if (size > KMP_MAX_PACKET_SIZE) {
        spdlog::warn("GameServer: Dropping oversized packet ({} bytes) on channel {}", size, channel);
        return;
    }

    // Note: m_mutex is already held by Update() which calls this method.
    // Using recursive_mutex so public methods (KickPlayer, etc.) can also lock safely.

    // Channel validation: reject messages arriving on the wrong channel.
    // Position updates must use the unreliable channel; all other gameplay
    // messages must arrive on a reliable channel (ordered or unordered).
    PacketReader peekReader(data, size);
    PacketHeader peekHeader;
    if (peekReader.ReadHeader(peekHeader)) {
        bool isPositionUpdate = (peekHeader.type == MessageType::C2S_PositionUpdate);
        if (isPositionUpdate && channel != KMP_CHANNEL_UNRELIABLE_SEQ) {
            spdlog::debug("GameServer: Position update on wrong channel {} (expected {})",
                         channel, KMP_CHANNEL_UNRELIABLE_SEQ);
            return;
        }
        if (!isPositionUpdate && channel == KMP_CHANNEL_UNRELIABLE_SEQ &&
            peekHeader.type != MessageType::C2S_Keepalive) {
            spdlog::debug("GameServer: Reliable message 0x{:02X} on unreliable channel",
                         static_cast<uint8_t>(peekHeader.type));
            return;
        }
    }

    PacketReader reader(data, size);
    PacketHeader header;
    if (!reader.ReadHeader(header)) return;

    // Per-player rate limiting for burst-prone, state-changing messages (RC5).
    // Position/move/keepalive are intentionally excluded — they are high-frequency
    // by design (20 Hz). PlayerManager was implemented but never wired in; this is
    // the single call site that activates it (fixes spawn/build/chat/zone floods).
    switch (header.type) {
    case MessageType::C2S_EntitySpawnReq:
    case MessageType::C2S_BuildRequest:
    case MessageType::C2S_ChatMessage:
    case MessageType::C2S_ZoneRequest:
    case MessageType::C2S_FactionRelation:
    case MessageType::C2S_TradeRequest:
    case MessageType::C2S_SquadCreate:
    case MessageType::C2S_SquadAddMember:
    case MessageType::C2S_AdminCommand: {
        if (auto* sender = GetPlayer(peer)) {
            m_playerManager.RecordMessage(sender->id, m_uptime);
            if (m_playerManager.CheckRateLimit(sender->id, m_uptime,
                                               KMP_RATE_LIMIT_WINDOW_SEC, KMP_RATE_LIMIT_MAX_MSGS)) {
                spdlog::warn("GameServer: Rate-limiting player '{}' (msg 0x{:02X})",
                             sender->name, static_cast<uint8_t>(header.type));
                return;
            }
        }
        break;
    }
    default:
        break;
    }

    switch (header.type) {
    case MessageType::C2S_Handshake:
        HandleHandshake(peer, reader);
        break;
    case MessageType::C2S_PositionUpdate: {
        auto* player = GetPlayer(peer);
        if (player) HandlePositionUpdate(*player, reader);
        break;
    }
    case MessageType::C2S_MoveCommand: {
        auto* player = GetPlayer(peer);
        if (player) HandleMoveCommand(*player, reader);
        break;
    }
    case MessageType::C2S_AttackIntent: {
        auto* player = GetPlayer(peer);
        if (player) HandleAttackIntent(*player, reader);
        break;
    }
    case MessageType::C2S_ChatMessage: {
        auto* player = GetPlayer(peer);
        if (player) HandleChatMessage(*player, reader);
        break;
    }
    case MessageType::C2S_BuildRequest: {
        auto* player = GetPlayer(peer);
        if (player) HandleBuildRequest(*player, reader);
        break;
    }
    case MessageType::C2S_EntitySpawnReq: {
        auto* player = GetPlayer(peer);
        if (player) HandleEntitySpawnReq(*player, reader);
        break;
    }
    case MessageType::C2S_EntityDespawnReq: {
        auto* player = GetPlayer(peer);
        if (player) HandleEntityDespawnReq(*player, reader);
        break;
    }
    case MessageType::C2S_EquipmentUpdate: {
        auto* player = GetPlayer(peer);
        if (player) HandleEquipmentUpdate(*player, reader);
        break;
    }
    case MessageType::C2S_ZoneRequest: {
        auto* player = GetPlayer(peer);
        if (player) HandleZoneRequest(*player, reader);
        break;
    }
    case MessageType::C2S_ItemPickup: {
        auto* player = GetPlayer(peer);
        if (player) HandleItemPickup(*player, reader);
        break;
    }
    case MessageType::C2S_ItemDrop: {
        auto* player = GetPlayer(peer);
        if (player) HandleItemDrop(*player, reader);
        break;
    }
    case MessageType::C2S_TradeRequest: {
        auto* player = GetPlayer(peer);
        if (player) HandleTradeRequest(*player, reader);
        break;
    }
    case MessageType::C2S_SquadCreate: {
        auto* player = GetPlayer(peer);
        if (player) HandleSquadCreate(*player, reader);
        break;
    }
    case MessageType::C2S_SquadAddMember: {
        auto* player = GetPlayer(peer);
        if (player) HandleSquadAddMember(*player, reader);
        break;
    }
    case MessageType::C2S_FactionRelation: {
        auto* player = GetPlayer(peer);
        if (player) HandleFactionRelation(*player, reader);
        break;
    }
    case MessageType::C2S_BuildDismantle: {
        auto* player = GetPlayer(peer);
        if (player) HandleBuildDismantle(*player, reader);
        break;
    }
    case MessageType::C2S_BuildRepair: {
        auto* player = GetPlayer(peer);
        if (player) HandleBuildRepair(*player, reader);
        break;
    }
    case MessageType::C2S_CombatStance: {
        auto* player = GetPlayer(peer);
        if (player) HandleCombatStance(*player, reader);
        break;
    }
    case MessageType::C2S_CombatKO: {
        auto* player = GetPlayer(peer);
        if (player) HandleCombatKO(*player, reader);
        break;
    }
    case MessageType::C2S_CombatDeath: {
        auto* player = GetPlayer(peer);
        if (player) HandleCombatDeath(*player, reader);
        break;
    }
    case MessageType::C2S_LimbHealth: {
        auto* player = GetPlayer(peer);
        if (player) HandleLimbHealth(*player, reader);
        break;
    }
    case MessageType::C2S_StatusEffect: {
        auto* player = GetPlayer(peer);
        if (player) HandleStatusEffect(*player, reader);
        break;
    }
    case MessageType::C2S_ItemTransfer: {
        auto* player = GetPlayer(peer);
        if (player) HandleItemTransfer(*player, reader);
        break;
    }
    case MessageType::C2S_DoorInteract: {
        auto* player = GetPlayer(peer);
        if (player) HandleDoorInteract(*player, reader);
        break;
    }
    case MessageType::C2S_AdminCommand: {
        auto* player = GetPlayer(peer);
        if (player) HandleAdminCommand(*player, reader);
        break;
    }
    case MessageType::C2S_LobbyReady: {
        auto* player = GetPlayer(peer);
        if (player) HandleLobbyReady(*player, reader);
        break;
    }
    case MessageType::C2S_Keepalive: {
        // Reset activity timer and send ack
        auto* player = GetPlayer(peer);
        if (player) {
            player->lastUpdate = m_uptime;
            PacketWriter ackWriter;
            ackWriter.WriteHeader(MessageType::S2C_KeepaliveAck);
            ENetPacket* pkt = enet_packet_create(ackWriter.Data(), ackWriter.Size(), ENET_PACKET_FLAG_RELIABLE);
            if (!pkt) {
                spdlog::error("Failed to create packet ({} bytes)", ackWriter.Size());
                break;
            }
            enet_peer_send(peer, KMP_CHANNEL_RELIABLE_ORDERED, pkt);
        }
        break;
    }
    case MessageType::C2S_Disconnect: {
        // Graceful disconnect requested by client.
        // Don't call HandleDisconnect here — just tell ENet to disconnect.
        // The ENET_EVENT_TYPE_DISCONNECT event will fire and call HandleDisconnect
        // exactly once, preventing double-cleanup and peer slot reuse races.
        auto* player = GetPlayer(peer);
        if (player) {
            spdlog::info("GameServer: Player '{}' sent graceful disconnect", player->name);
        }
        enet_peer_disconnect(peer, 0);
        break;
    }
    case MessageType::C2S_ServerQuery:
        HandleServerQuery(peer, reader);
        break;
    case MessageType::C2S_PipelineSnapshot:
    case MessageType::C2S_PipelineEvent: {
        // Pipeline debug: pure relay — server doesn't interpret, just forwards to all other clients
        auto* player = GetPlayer(peer);
        if (player) {
            MessageType fwdType = (header.type == MessageType::C2S_PipelineSnapshot)
                ? MessageType::S2C_PipelineSnapshot : MessageType::S2C_PipelineEvent;
            PacketWriter fwd;
            fwd.WriteHeader(fwdType);
            fwd.WriteU32(player->id);  // Prepend sender player ID
            fwd.WriteRaw(reader.Current(), reader.Remaining());
            BroadcastExcept(player->id, fwd.Data(), fwd.Size(),
                            KMP_CHANNEL_RELIABLE_UNORDERED, ENET_PACKET_FLAG_RELIABLE);
        }
        break;
    }
    default:
        spdlog::debug("GameServer: Unknown message type 0x{:02X}", static_cast<uint8_t>(header.type));
        break;
    }
}

void GameServer::HandleHandshake(ENetPeer* peer, PacketReader& reader) {
    MsgHandshake msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) return;

    // Duplicate connection check: reject if this peer already has a player
    if (peer->data != nullptr) {
        uintptr_t existingId = reinterpret_cast<uintptr_t>(peer->data);
        spdlog::warn("GameServer: Peer already has player ID {} — rejecting duplicate handshake", existingId);
        return;
    }

    // Check if server is full
    if (m_players.size() >= static_cast<size_t>(m_config.maxPlayers)) {
        PacketWriter writer;
        writer.WriteHeader(MessageType::S2C_HandshakeReject);
        MsgHandshakeReject reject{};
        reject.reasonCode = 0; // full
        snprintf(reject.reasonText, sizeof(reject.reasonText), "Server is full (%d/%d)",
                 (int)m_players.size(), m_config.maxPlayers);
        writer.WriteRaw(&reject, sizeof(reject));
        ENetPacket* pkt = enet_packet_create(writer.Data(), writer.Size(), ENET_PACKET_FLAG_RELIABLE);
        if (!pkt) {
            spdlog::error("Failed to create packet ({} bytes)", writer.Size());
            enet_peer_disconnect_later(peer, 0);
            return;
        }
        enet_peer_send(peer, KMP_CHANNEL_RELIABLE_ORDERED, pkt);
        enet_peer_disconnect_later(peer, 0);
        return;
    }

    // Verify protocol version
    if (msg.protocolVersion != KMP_PROTOCOL_VERSION) {
        PacketWriter writer;
        writer.WriteHeader(MessageType::S2C_HandshakeReject);
        MsgHandshakeReject reject{};
        reject.reasonCode = 1;
        snprintf(reject.reasonText, sizeof(reject.reasonText),
                "Version mismatch: server=%d, client=%d", KMP_PROTOCOL_VERSION, msg.protocolVersion);
        writer.WriteRaw(&reject, sizeof(reject));

        ENetPacket* pkt = enet_packet_create(writer.Data(), writer.Size(), ENET_PACKET_FLAG_RELIABLE);
        if (!pkt) {
            spdlog::error("Failed to create packet ({} bytes)", writer.Size());
            enet_peer_disconnect_later(peer, 0);
            return;
        }
        enet_peer_send(peer, KMP_CHANNEL_RELIABLE_ORDERED, pkt);
        enet_peer_disconnect_later(peer, 0);
        return;
    }

    // ── Password check (protocol v2) ──
    // Force-terminate the fixed network buffers before treating them as strings.
    if (!m_config.password.empty()) {
        std::string suppliedPassword = SafeCStr(msg.password);
        if (!SecretEquals(suppliedPassword, m_config.password)) {
            char addrStr[64];
            enet_address_get_host_ip(&peer->address, addrStr, sizeof(addrStr));
            spdlog::warn("GameServer: Rejected connection from {} — wrong password", addrStr);
            PacketWriter writer;
            writer.WriteHeader(MessageType::S2C_HandshakeReject);
            MsgHandshakeReject reject{};
            reject.reasonCode = 4; // bad password
            snprintf(reject.reasonText, sizeof(reject.reasonText), "Incorrect server password");
            writer.WriteRaw(&reject, sizeof(reject));
            ENetPacket* pkt = enet_packet_create(writer.Data(), writer.Size(), ENET_PACKET_FLAG_RELIABLE);
            if (pkt) enet_peer_send(peer, KMP_CHANNEL_RELIABLE_ORDERED, pkt);
            enet_peer_disconnect_later(peer, 0);
            return;
        }
    }

    // Sanitize player name: strip non-printable ASCII, enforce length
    std::string sanitizedName;
    for (int i = 0; i < KMP_MAX_NAME_LENGTH && msg.playerName[i] != '\0'; i++) {
        char c = msg.playerName[i];
        if (c >= 32 && c < 127) sanitizedName += c;
    }
    if (sanitizedName.empty()) sanitizedName = "Player";

    // Create player
    PlayerID id = NextPlayerId();
    ConnectedPlayer player;
    player.id = id;
    player.name = sanitizedName;
    player.peer = peer;
    player.ping = peer->roundTripTime;
    player.lastUpdate = m_uptime;

    // Issue a fresh secret session token for this connection. The client must
    // persist it (per-server) and present it on reconnect to reclaim entities.
    player.sessionToken = GenerateSessionToken();
    char joinAddr[64];
    enet_address_get_host_ip(&peer->address, joinAddr, sizeof(joinAddr));
    player.ipAddress = joinAddr;

    peer->data = reinterpret_cast<void*>(static_cast<uintptr_t>(id));
    m_players[id] = player;

    // Now authenticated: restore a generous timeout so high-latency players
    // aren't dropped (R8). The short 5s/8s set at connect only needs to apply
    // while the peer is un-handshaken (squatting a slot).
    enet_peer_timeout(peer, 0, 10000, 15000);

    // Reconnect: reclaim entities only if the client presents the SECRET token
    // from its prior session (not a public display name — RC1 fix). The token
    // is the map key, so a forged/empty token simply finds nothing.
    std::string suppliedToken = SafeCStr(msg.sessionToken);
    if (!suppliedToken.empty()) {
        auto savedIt = m_savedPlayers.find(suppliedToken);
        if (savedIt != m_savedPlayers.end()) {
            int reclaimed = 0;
            for (EntityID eid : savedIt->second.entityIds) {
                auto entIt = m_entities.find(eid);
                if (entIt != m_entities.end() && entIt->second.owner == 0) {
                    entIt->second.owner = id;
                    m_players[id].ownedEntities.push_back(eid);
                    reclaimed++;
                }
            }
            spdlog::info("GameServer: Player '{}' reconnected via token — reclaimed {}/{} entities",
                         sanitizedName, reclaimed, savedIt->second.entityIds.size());
            m_savedPlayers.erase(savedIt);
        } else {
            spdlog::warn("GameServer: Player '{}' presented an unknown session token (no reclaim)",
                         sanitizedName);
        }
    }

    // Host designation (RC1 fix). Two modes, by operator config:
    //  - hostToken SET   → host granted ONLY to the client presenting that secret
    //                      (secure; defeats the original "first connector is admin").
    //  - hostToken EMPTY → operator opted out of secure designation (casual/LAN):
    //                      fall back to first-connector host so self-hosted/solo
    //                      sessions still have an admin and system faction changes
    //                      (causer=0, host-only) keep working. Set a hostToken to
    //                      require a credential. (R5: the strict-only version left
    //                      default servers with no host at all.)
    if (m_hostPlayerId == 0) {
        if (m_config.hostToken.empty()) {
            // Gameplay host only — NOT admin-authenticated. Gets faction(causer=0)
            // and build coordination, but kick/ban/time/weather stay denied (I-04).
            m_hostPlayerId = id;
            m_hostAuthenticated = false;
            spdlog::info("GameServer: No host token configured — '{}' is gameplay host by connection "
                         "order (ID {}); admin commands disabled (set hostToken to enable)", player.name, id);
        } else {
            std::string suppliedHostToken = SafeCStr(msg.hostToken);
            if (SecretEquals(suppliedHostToken, m_config.hostToken)) {
                m_hostPlayerId = id;
                m_hostAuthenticated = true;
                spdlog::info("GameServer: Player '{}' authenticated as HOST + ADMIN (ID: {})", player.name, id);
            }
        }
    }

    spdlog::info("GameServer: Player '{}' joined (ID: {}, {} players now)",
                 player.name, id, m_players.size());

    // Send handshake ack
    {
        PacketWriter writer;
        writer.WriteHeader(MessageType::S2C_HandshakeAck);
        MsgHandshakeAck ack{};
        ack.playerId = id;
        ack.serverTick = m_serverTick;
        ack.timeOfDay = m_timeOfDay;
        ack.weatherState = m_weatherState;
        ack.maxPlayers = static_cast<uint8_t>(m_config.maxPlayers);
        ack.currentPlayers = static_cast<uint8_t>(m_players.size());
        ack.isHost = (id == m_hostPlayerId) ? 1 : 0;
        strncpy(ack.sessionToken, player.sessionToken.c_str(), sizeof(ack.sessionToken) - 1);
        ack.sessionToken[sizeof(ack.sessionToken) - 1] = '\0';
        writer.WriteRaw(&ack, sizeof(ack));

        ENetPacket* pkt = enet_packet_create(writer.Data(), writer.Size(), ENET_PACKET_FLAG_RELIABLE);
        if (!pkt) {
            spdlog::error("Failed to create packet ({} bytes)", writer.Size());
            m_players.erase(id);
            peer->data = nullptr;
            // Roll back host state if this aborted player had just claimed it,
            // else a null-alloc would permanently lock out admin until restart.
            if (id == m_hostPlayerId) { m_hostPlayerId = 0; m_hostAuthenticated = false; }
            return;
        }
        enet_peer_send(peer, KMP_CHANNEL_RELIABLE_ORDERED, pkt);
    }

    // Send faction assignment to the new player
    // Each player gets a unique faction string from kenshi-online.mod.
    // Player 1 → slot 0 ("10-kenshi-online"), Player 2 → slot 1 ("12-kenshi-online"), etc.
    // The client patches this string in .rdata before save load to determine
    // which faction's characters they control.
    {
        // Faction strings must match the FCS IDs in kenshi-online.mod
        // Format: "{numId}-{modFilename}" — the .mod extension IS part of the reference.
        static const char* factionStrings[] = {
            "10-kenshi-online.mod",   // Slot 0 (Player 1)
            "12-kenshi-online.mod",   // Slot 1 (Player 2)
        };
        static const int numFactions = sizeof(factionStrings) / sizeof(factionStrings[0]);

        int slot = (id - 1) % numFactions;
        if (slot < 0) slot = 0;
        const char* factionStr = factionStrings[slot];
        size_t factionLen = strlen(factionStr);

        PacketWriter factionWriter;
        factionWriter.WriteHeader(MessageType::S2C_FactionAssignment);
        factionWriter.WriteU16(static_cast<uint16_t>(factionLen));
        factionWriter.WriteRaw(factionStr, factionLen);
        factionWriter.WriteI32(slot);

        ENetPacket* factionPkt = enet_packet_create(factionWriter.Data(), factionWriter.Size(),
                                                     ENET_PACKET_FLAG_RELIABLE);
        if (!factionPkt) {
            spdlog::error("Failed to create packet ({} bytes)", factionWriter.Size());
            m_players.erase(id);
            peer->data = nullptr;
            // Roll back host state if this aborted player had just claimed it,
            // else a null-alloc would permanently lock out admin until restart.
            if (id == m_hostPlayerId) { m_hostPlayerId = 0; m_hostAuthenticated = false; }
            return;
        }
        enet_peer_send(peer, KMP_CHANNEL_RELIABLE_ORDERED, factionPkt);
        spdlog::info("GameServer: Assigned faction '{}' (slot {}) to player {}",
                     factionStr, slot, id);
    }

    // Notify existing players about the new player (use sanitized name)
    {
        PacketWriter writer;
        writer.WriteHeader(MessageType::S2C_PlayerJoined);
        MsgPlayerJoined joined{};
        joined.playerId = id;
        strncpy(joined.playerName, sanitizedName.c_str(), KMP_MAX_NAME_LENGTH - 1);
        joined.playerName[KMP_MAX_NAME_LENGTH - 1] = '\0';
        writer.WriteRaw(&joined, sizeof(joined));
        BroadcastExcept(id, writer.Data(), writer.Size(), KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
    }

    // Send existing players to the new player
    for (auto& [existingId, existingPlayer] : m_players) {
        if (existingId == id) continue;

        PacketWriter writer;
        writer.WriteHeader(MessageType::S2C_PlayerJoined);
        MsgPlayerJoined joined{};
        joined.playerId = existingId;
        strncpy(joined.playerName, existingPlayer.name.c_str(), KMP_MAX_NAME_LENGTH - 1);
        joined.playerName[KMP_MAX_NAME_LENGTH - 1] = '\0';
        writer.WriteRaw(&joined, sizeof(joined));

        ENetPacket* pkt = enet_packet_create(writer.Data(), writer.Size(), ENET_PACKET_FLAG_RELIABLE);
        if (!pkt) {
            spdlog::error("Failed to create packet ({} bytes)", writer.Size());
            continue;
        }
        enet_peer_send(peer, KMP_CHANNEL_RELIABLE_ORDERED, pkt);
    }

    // Send world snapshot to new player
    SendWorldSnapshot(m_players[id]);

    BroadcastSystemMessage(player.name + " joined the game");
}

void GameServer::HandleServerQuery(ENetPeer* peer, PacketReader& reader) {
    // Lightweight query — respond with server info without requiring handshake.
    // This lets the server browser show real player counts.
    // Note: m_mutex must be held (acquired by HandlePacket caller)
    MsgServerQuery query;
    if (!reader.ReadRaw(&query, sizeof(query))) return;

    spdlog::debug("GameServer: Server query from peer (protocol={})", query.protocolVersion);

    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_ServerInfo);

    MsgServerInfo info{};
    info.protocolVersion = KMP_PROTOCOL_VERSION;
    info.currentPlayers = static_cast<uint8_t>(m_players.size());
    info.maxPlayers = static_cast<uint8_t>(m_config.maxPlayers);
    info.port = m_config.port;
    info.timeOfDay = m_timeOfDay;
    info.pvpEnabled = m_config.pvpEnabled ? 1 : 0;
    strncpy(info.serverName, m_config.serverName.c_str(), sizeof(info.serverName) - 1);
    info.serverName[sizeof(info.serverName) - 1] = '\0';
    writer.WriteRaw(&info, sizeof(info));

    ENetPacket* pkt = enet_packet_create(writer.Data(), writer.Size(), ENET_PACKET_FLAG_RELIABLE);
    if (!pkt) {
        spdlog::error("Failed to create packet ({} bytes)", writer.Size());
        enet_peer_disconnect_later(peer, 0);
        return;
    }
    enet_peer_send(peer, KMP_CHANNEL_RELIABLE_ORDERED, pkt);

    // Disconnect the query peer after responding (they're not joining)
    enet_peer_disconnect_later(peer, 0);
}

void GameServer::HandlePositionUpdate(ConnectedPlayer& player, PacketReader& reader) {
    uint8_t count;
    if (!reader.ReadU8(count)) return;

    bool playerPosUpdated = false;
    for (uint8_t i = 0; i < count; i++) {
        CharacterPosition pos;
        if (!reader.ReadRaw(&pos, sizeof(pos))) break;

        // Validate coordinates — reject NaN/inf/extreme values to prevent client crashes
        if (std::isnan(pos.posX) || std::isnan(pos.posY) || std::isnan(pos.posZ) ||
            std::isinf(pos.posX) || std::isinf(pos.posY) || std::isinf(pos.posZ) ||
            std::abs(pos.posX) > 1000000.f || std::abs(pos.posY) > 1000000.f ||
            std::abs(pos.posZ) > 1000000.f) {
            spdlog::warn("GameServer: Rejected invalid position from '{}' entity {} ({},{},{})",
                         player.name, pos.entityId, pos.posX, pos.posY, pos.posZ);
            continue;
        }

        // Update server-side entity position
        auto it = m_entities.find(pos.entityId);
        if (it != m_entities.end() && it->second.owner == player.id) {
            // Anti-teleport (I-01/02/12 keystone): reject a jump faster than
            // KMP_MAX_MOVE_SPEED. Without this, an attacker teleports an owned
            // entity onto a victim/door and the combat/proximity distance gates
            // (which trust this server-side position) pass at distance 0. Skip the
            // first update per entity (no baseline); floor dt to avoid div blow-up.
            if (it->second.lastPosTime > 0.f) {
                float dt = m_uptime - it->second.lastPosTime;
                if (dt < 0.02f) dt = 0.02f;
                float ddx = pos.posX - it->second.position.x;
                float ddy = pos.posY - it->second.position.y;
                float ddz = pos.posZ - it->second.position.z;
                float dist = std::sqrt(ddx * ddx + ddy * ddy + ddz * ddz);
                if (dist > KMP_MAX_MOVE_SPEED * dt) {
                    spdlog::warn("GameServer: Rejected teleport-speed move from '{}' entity {} ({:.0f}m in {:.2f}s)",
                                 player.name, pos.entityId, dist, dt);
                    continue;
                }
            }
            it->second.position = Vec3(pos.posX, pos.posY, pos.posZ);
            it->second.rotation = Quat::Decompress(pos.compressedQuat);
            it->second.zone = ZoneCoord::FromWorldPos(it->second.position);
            it->second.animState = pos.animStateId;
            it->second.moveSpeed = pos.moveSpeed;
            it->second.flags = pos.flags;
            it->second.lastPosTime = m_uptime;

            // Use the first owned entity's position for zone tracking
            if (!playerPosUpdated) {
                player.position = Vec3(pos.posX, pos.posY, pos.posZ);
                player.zone = ZoneCoord::FromWorldPos(player.position);
                playerPosUpdated = true;
            }
        }
    }
}

void GameServer::HandleMoveCommand(ConnectedPlayer& player, PacketReader& reader) {
    MsgMoveCommand msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) return;

    // Validate entity ownership
    auto it = m_entities.find(msg.entityId);
    if (it == m_entities.end() || it->second.owner != player.id) return;

    // Reject non-finite / extreme move targets before rebroadcast. This message
    // is relayed verbatim to all other clients, so an unvalidated NaN/Inf target
    // would propagate straight into their game memory (R9 — same class as the
    // spawn/limb-health NaN guards).
    if (std::isnan(msg.targetX) || std::isnan(msg.targetY) || std::isnan(msg.targetZ) ||
        std::isinf(msg.targetX) || std::isinf(msg.targetY) || std::isinf(msg.targetZ) ||
        std::abs(msg.targetX) > 1000000.f || std::abs(msg.targetY) > 1000000.f ||
        std::abs(msg.targetZ) > 1000000.f) {
        spdlog::warn("GameServer: Rejected invalid move target from '{}' entity {}",
                     player.name, msg.entityId);
        return;
    }

    // Broadcast to other players
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_MoveCommand);
    writer.WriteRaw(&msg, sizeof(msg));
    BroadcastExcept(player.id, writer.Data(), writer.Size(),
                   KMP_CHANNEL_RELIABLE_UNORDERED, ENET_PACKET_FLAG_RELIABLE);
}

void GameServer::HandleAttackIntent(ConnectedPlayer& player, PacketReader& reader) {
    MsgAttackIntent msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) return;

    // Validate attacker ownership
    auto it = m_entities.find(msg.attackerId);
    if (it == m_entities.end() || it->second.owner != player.id) return;

    // Validate target exists and is alive
    auto targetIt = m_entities.find(msg.targetId);
    if (targetIt == m_entities.end() || !targetIt->second.alive) return;

    // Distance validation: melee < 15m, ranged < 150m
    float dx = it->second.position.x - targetIt->second.position.x;
    float dy = it->second.position.y - targetIt->second.position.y;
    float dz = it->second.position.z - targetIt->second.position.z;
    float distSq = dx*dx + dy*dy + dz*dz;
    float maxDist = (msg.attackType == 1) ? 150.f : 15.f;
    if (distSq > maxDist * maxDist) return;

    // Delegate to combat resolver (single source of truth for combat logic)
    auto result = ResolveCombat(it->second, targetIt->second, msg.attackType);

    // Build and broadcast hit
    MsgCombatHit hit{};
    hit.attackerId = msg.attackerId;
    hit.targetId = msg.targetId;
    hit.bodyPart = static_cast<uint8_t>(result.hitPart);
    hit.cutDamage = result.cutDamage;
    hit.bluntDamage = result.bluntDamage;
    hit.pierceDamage = result.pierceDamage;
    hit.resultHealth = result.resultHealth;
    hit.wasBlocked = result.wasBlocked ? 1 : 0;
    hit.wasKO = result.wasKO ? 1 : 0;

    // Broadcast hit to ALL players (including attacker) for authoritative sync.
    // The attacker already applied local damage, but the server's result is
    // authoritative — the client will reconcile using the server values.
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_CombatHit);
    writer.WriteRaw(&hit, sizeof(hit));
    Broadcast(writer.Data(), writer.Size(), KMP_CHANNEL_RELIABLE_UNORDERED, ENET_PACKET_FLAG_RELIABLE);

    if (result.wasDeath) {
        // Mark entity as dead BEFORE broadcast (server is authoritative)
        targetIt->second.alive = false;

        PacketWriter deathWriter;
        deathWriter.WriteHeader(MessageType::S2C_CombatDeath);
        MsgCombatDeath death{};
        death.entityId = msg.targetId;
        death.killerId = msg.attackerId;
        deathWriter.WriteRaw(&death, sizeof(death));
        Broadcast(deathWriter.Data(), deathWriter.Size(),
                 KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);

        spdlog::info("GameServer: Entity {} killed by {} (owned by {})",
                     msg.targetId, msg.attackerId, player.name);
    } else if (result.wasKO) {
        PacketWriter koWriter;
        koWriter.WriteHeader(MessageType::S2C_CombatKO);
        MsgCombatKO ko{};
        ko.entityId = msg.targetId;
        ko.attackerId = msg.attackerId;
        ko.bodyPart = static_cast<uint8_t>(result.hitPart);
        ko.resultHealth = result.resultHealth;
        koWriter.WriteRaw(&ko, sizeof(ko));
        Broadcast(koWriter.Data(), koWriter.Size(),
                 KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
    }
}

void GameServer::HandleChatMessage(ConnectedPlayer& player, PacketReader& reader) {
    // Client sends: U32(senderId) + U16(len) + Raw(text).
    // Read and discard senderId — use player.id from the connection instead (trusted).
    uint32_t senderId;
    if (!reader.ReadU32(senderId)) return;
    std::string message;
    if (!reader.ReadString(message)) return;
    if (message.empty()) return;

    spdlog::info("[Chat] {}: {}", player.name, message);

    // Broadcast to all OTHER players (don't echo back to sender)
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_ChatMessage);
    writer.WriteU32(player.id);
    writer.WriteString(message);
    BroadcastExcept(player.id, writer.Data(), writer.Size(), KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
}

void GameServer::HandleBuildRequest(ConnectedPlayer& player, PacketReader& reader) {
    MsgBuildRequest msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) return;

    // Validate build coordinates — reject NaN/inf/extreme values
    if (std::isnan(msg.posX) || std::isnan(msg.posY) || std::isnan(msg.posZ) ||
        std::isinf(msg.posX) || std::isinf(msg.posY) || std::isinf(msg.posZ) ||
        std::abs(msg.posX) > 1000000.f || std::abs(msg.posY) > 1000000.f ||
        std::abs(msg.posZ) > 1000000.f) {
        spdlog::warn("GameServer: Rejected invalid build position from '{}' ({},{},{})",
                     player.name, msg.posX, msg.posY, msg.posZ);
        return;
    }

    // Validate build position is within reasonable distance of player's known position
    // (prevents building across the map via modified client)
    constexpr float MAX_BUILD_DISTANCE = 500.f;
    float dx = msg.posX - player.position.x;
    float dy = msg.posY - player.position.y;
    float dz = msg.posZ - player.position.z;
    float distSq = dx*dx + dy*dy + dz*dz;
    if (distSq > MAX_BUILD_DISTANCE * MAX_BUILD_DISTANCE) {
        spdlog::warn("GameServer: Rejected build from '{}' too far from player ({:.0f}m away)",
                     player.name, std::sqrt(distSq));
        return;
    }

    // Enforce per-player entity cap (RC5/I-14) — buildings count toward the budget.
    if (EntityManager::WouldExceedLimit(m_entities, player.id, KMP_MAX_ENTITIES_PER_PLAYER)) {
        spdlog::warn("GameServer: Player '{}' hit per-player entity cap ({}) — rejecting build",
                     player.name, KMP_MAX_ENTITIES_PER_PLAYER);
        return;
    }

    // Create building entity
    EntityID buildId = m_nextEntityId++;
    ServerEntity building;
    building.id = buildId;
    building.type = EntityType::Building;
    building.owner = player.id;
    building.position = Vec3(msg.posX, msg.posY, msg.posZ);
    building.rotation = Quat::Decompress(msg.compressedQuat);
    building.zone = ZoneCoord::FromWorldPos(building.position);
    building.templateId = msg.templateId;
    building.alive = true;
    m_entities[buildId] = building;

    // Broadcast placement
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_BuildPlaced);
    MsgBuildPlaced placed{};
    placed.entityId = buildId;
    placed.templateId = msg.templateId;
    placed.posX = msg.posX;
    placed.posY = msg.posY;
    placed.posZ = msg.posZ;
    placed.compressedQuat = msg.compressedQuat;
    placed.builderId = player.id;
    writer.WriteRaw(&placed, sizeof(placed));
    BroadcastExcept(player.id, writer.Data(), writer.Size(),
                    KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);

    spdlog::info("GameServer: Player '{}' placed building {} at ({:.1f}, {:.1f}, {:.1f})",
                 player.name, buildId, msg.posX, msg.posY, msg.posZ);
}

void GameServer::BroadcastPositions() {
    // Collect all entity positions and broadcast to relevant players
    // (zone-based interest management)
    for (auto& [playerId, player] : m_players) {
        PacketWriter writer;
        writer.WriteHeader(MessageType::S2C_PositionUpdate);

        // Collect all non-owned entities (zone filtering disabled for small
        // player counts — 16-slot server doesn't need spatial culling, and
        // zone mismatch was preventing players from ever seeing each other).
        std::vector<const ServerEntity*> nearby;
        for (auto& [entityId, entity] : m_entities) {
            if (entity.owner == playerId) continue; // Don't send own entities back
            nearby.push_back(&entity);
        }

        if (nearby.empty()) continue;

        writer.WriteU32(0); // sourcePlayer = server
        size_t sendCount = std::min(nearby.size(), size_t(255));
        writer.WriteU8(static_cast<uint8_t>(sendCount));

        for (size_t i = 0; i < sendCount; i++) {
            auto* entity = nearby[i];
            CharacterPosition pos;
            pos.entityId = entity->id;
            pos.posX = entity->position.x;
            pos.posY = entity->position.y;
            pos.posZ = entity->position.z;
            pos.compressedQuat = entity->rotation.Compress();
            pos.animStateId = entity->animState;
            pos.moveSpeed = entity->moveSpeed;
            pos.flags = entity->flags;
            writer.WriteRaw(&pos, sizeof(pos));
        }

        ENetPacket* pkt = enet_packet_create(writer.Data(), writer.Size(), 0);
        if (!pkt) {
            spdlog::error("Failed to create packet ({} bytes)", writer.Size());
            continue;
        }
        enet_peer_send(player.peer, KMP_CHANNEL_UNRELIABLE_SEQ, pkt);
    }
}

void GameServer::BroadcastTimeSync() {
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_TimeSync);
    MsgTimeSync msg;
    msg.serverTick = m_serverTick;
    msg.timeOfDay = m_timeOfDay;
    msg.weatherState = m_weatherState;
    msg.gameSpeed = static_cast<uint8_t>(m_config.gameSpeed);
    writer.WriteRaw(&msg, sizeof(msg));
    Broadcast(writer.Data(), writer.Size(), KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
}

void GameServer::BroadcastEntityHeartbeat() {
    // Send per-player heartbeat: each client gets the list of entity IDs that
    // should exist in their interest zone. Client compares against local registry
    // and cleans up entities the server no longer knows about (ghost entities from
    // silent disconnects, zone changes, or missed despawn messages).
    for (auto& [playerId, player] : m_players) {
        PacketWriter writer;
        writer.WriteHeader(MessageType::S2C_EntityHeartbeat);
        writer.WriteU32(m_serverTick);

        // Collect entity IDs relevant to this player
        std::vector<EntityID> relevantIds;
        for (const auto& [entityId, entity] : m_entities) {
            if (entity.state != EntityState::Active) continue;

            // Include: entities owned by this player, or in nearby zones
            if (entity.owner == playerId ||
                entity.zone.IsAdjacent(player.zone) ||
                entity.owner == 0) {
                relevantIds.push_back(entityId);
            }
        }

        writer.WriteU16(static_cast<uint16_t>(relevantIds.size()));
        for (EntityID id : relevantIds) {
            writer.WriteU32(id);
        }

        SendTo(playerId, writer.Data(), writer.Size(),
               KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
    }
}

void GameServer::HandleEntitySpawnReq(ConnectedPlayer& player, PacketReader& reader) {
    // Host client reports a character was created in-game. Server assigns a server
    // entity ID, stores it, and broadcasts S2C_EntitySpawn to all clients.
    uint32_t clientEntityId, templateId, factionId;
    uint8_t type;
    uint32_t ownerId;
    float px, py, pz;
    uint32_t compQuat;

    if (!reader.ReadU32(clientEntityId)) return;
    if (!reader.ReadU8(type)) return;
    if (!reader.ReadU32(ownerId)) return;
    if (!reader.ReadU32(templateId)) return;
    if (!reader.ReadVec3(px, py, pz)) return;
    if (!reader.ReadU32(compQuat)) return;
    if (!reader.ReadU32(factionId)) return;

    // Validate spawn coordinates — reject NaN/Inf/extreme (R2 fix, mirrors
    // HandleBuildRequest). A NaN position would serialize as JSON null and throw
    // on the next world load → permanent world wipe (I-10), and would also defeat
    // the door proximity gate (NaN distance comparison is always false → I-12).
    if (std::isnan(px) || std::isnan(py) || std::isnan(pz) ||
        std::isinf(px) || std::isinf(py) || std::isinf(pz) ||
        std::abs(px) > 1000000.f || std::abs(py) > 1000000.f || std::abs(pz) > 1000000.f) {
        spdlog::warn("GameServer: Rejected spawn with invalid position from '{}' ({},{},{})",
                     player.name, px, py, pz);
        return;
    }

    // Read optional template name
    std::string templateName;
    uint16_t nameLen = 0;
    if (reader.Remaining() >= 2) {
        reader.ReadU16(nameLen);
        if (nameLen > 0 && nameLen <= 255 && reader.Remaining() >= nameLen) {
            templateName.resize(nameLen);
            reader.ReadRaw(templateName.data(), nameLen);
            // Reject invalid UTF-8 so it can't crash the JSON autosave (I-09).
            if (!IsValidUtf8(templateName)) {
                spdlog::warn("GameServer: Player '{}' sent non-UTF-8 templateName — dropping name",
                             player.name);
                templateName.clear();
            }
        }
    }

    // Read optional extended state (health + alive flag, appended after template name)
    bool hasExtended = false;
    float healthData[7] = {100.f, 100.f, 100.f, 100.f, 100.f, 100.f, 100.f};
    bool isAlive = true;
    if (reader.Remaining() >= 1) {
        uint8_t extFlag = 0;
        reader.ReadU8(extFlag);
        if (extFlag == 1 && reader.Remaining() >= 7 * 4 + 1) {
            hasExtended = true;
            for (int i = 0; i < 7; i++) reader.ReadF32(healthData[i]);
            // Reject NaN/Inf so it never reaches the world save (I-10).
            for (int i = 0; i < 7; i++) healthData[i] = SanitizeHealth(healthData[i]);
            uint8_t aliveFlag = 1;
            reader.ReadU8(aliveFlag);
            isAlive = (aliveFlag != 0);
        }
    }

    // Validate entity type
    if (type > static_cast<uint8_t>(EntityType::Turret)) {
        spdlog::warn("GameServer: Invalid entity type {} from player '{}'", type, player.name);
        return;
    }

    // Enforce global entity limit
    if (m_entities.size() >= KMP_MAX_SYNC_ENTITIES) {
        spdlog::warn("GameServer: Entity limit reached ({}) — rejecting spawn from '{}'",
                      m_entities.size(), player.name);
        return;
    }

    // Enforce per-player entity cap (RC5/I-07) — one client can't exhaust the
    // global budget on its own. PlayerManager/EntityManager were unused until now.
    if (EntityManager::WouldExceedLimit(m_entities, player.id, KMP_MAX_ENTITIES_PER_PLAYER)) {
        spdlog::warn("GameServer: Player '{}' hit per-player entity cap ({}) — rejecting spawn",
                     player.name, KMP_MAX_ENTITIES_PER_PLAYER);
        return;
    }

    // Assign server entity ID
    EntityID serverId = m_nextEntityId++;

    // Store in server entity list
    ServerEntity entity;
    entity.id = serverId;
    entity.type = static_cast<EntityType>(type);
    entity.owner = player.id;
    entity.position = Vec3(px, py, pz);
    entity.rotation = Quat::Decompress(compQuat);
    entity.templateId = templateId;
    entity.factionId = factionId;
    entity.templateName = templateName;
    entity.zone = ZoneCoord::FromWorldPos(entity.position, KMP_ZONE_SIZE);
    if (hasExtended) {
        for (int i = 0; i < 7; i++) entity.health[i] = healthData[i];
        entity.alive = isAlive;
    }
    m_entities[serverId] = entity;

    // Initialize player position/zone from their first entity so zone-based
    // interest management works before the player sends any position updates
    if (player.zone == ZoneCoord(0, 0)) {
        player.position = entity.position;
        player.zone = entity.zone;
    }

    spdlog::info("GameServer: Entity spawn req from '{}': serverID={} template='{}' at ({:.1f},{:.1f},{:.1f})",
                 player.name, serverId, templateName, px, py, pz);

    // Broadcast S2C_EntitySpawn to ALL clients (including the host, so they get the server ID)
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_EntitySpawn);
    writer.WriteU32(serverId);
    writer.WriteU8(type);
    writer.WriteU32(player.id);
    writer.WriteU32(templateId);
    writer.WriteF32(px);
    writer.WriteF32(py);
    writer.WriteF32(pz);
    writer.WriteU32(compQuat);
    writer.WriteU32(factionId);
    uint16_t broadcastNameLen = static_cast<uint16_t>(templateName.size());
    writer.WriteU16(broadcastNameLen);
    if (broadcastNameLen > 0) {
        writer.WriteRaw(templateName.data(), broadcastNameLen);
    }

    // Always relay extended state (health + alive) so packet format is consistent
    // across HandleEntitySpawnReq, SendWorldSnapshot, and HandleZoneRequest
    writer.WriteU8(1); // hasExtendedState
    for (int i = 0; i < 7; i++) writer.WriteF32(healthData[i]);
    writer.WriteU8(isAlive ? 1 : 0);

    Broadcast(writer.Data(), writer.Size(), KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
}

void GameServer::HandleEntityDespawnReq(ConnectedPlayer& player, PacketReader& reader) {
    uint32_t entityId;
    uint8_t reason;
    if (!reader.ReadU32(entityId)) return;
    reader.ReadU8(reason); // optional

    // Validate: entity must exist and be owned by this player
    auto it = m_entities.find(entityId);
    if (it == m_entities.end()) return;
    if (it->second.owner != player.id) {
        spdlog::warn("GameServer: Player '{}' tried to despawn entity {} they don't own", player.name, entityId);
        return;
    }

    spdlog::info("GameServer: Entity {} despawned by '{}' (reason={})", entityId, player.name, reason);

    // Remove from server
    m_entities.erase(it);

    // Broadcast despawn to all clients
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_EntityDespawn);
    writer.WriteU32(entityId);
    writer.WriteU8(reason);
    Broadcast(writer.Data(), writer.Size(), KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
}

void GameServer::HandleEquipmentUpdate(ConnectedPlayer& player, PacketReader& reader) {
    MsgEquipmentUpdate msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) return;

    // Validate entity exists and is owned by this player
    auto it = m_entities.find(msg.entityId);
    if (it == m_entities.end() || it->second.owner != player.id) return;

    // Validate slot
    if (msg.slot >= 14) return;

    // Update server state
    it->second.equipment[msg.slot] = msg.itemTemplateId;

    spdlog::debug("GameServer: Equipment update from '{}': entity={} slot={} item={}",
                  player.name, msg.entityId, msg.slot, msg.itemTemplateId);

    // Broadcast to all other players
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_EquipmentUpdate);
    writer.WriteRaw(&msg, sizeof(msg));
    BroadcastExcept(player.id, writer.Data(), writer.Size(),
                   KMP_CHANNEL_RELIABLE_UNORDERED, ENET_PACKET_FLAG_RELIABLE);
}

void GameServer::HandleZoneRequest(ConnectedPlayer& player, PacketReader& reader) {
    int32_t zoneX, zoneY;
    if (!reader.ReadI32(zoneX) || !reader.ReadI32(zoneY)) return;

    // Zone bounds validation: Kenshi's world is roughly -100km to +100km.
    // At 750m per zone, that's about ±133 zones. Clamp to ±500 to be safe.
    constexpr int32_t ZONE_MAX = 500;
    if (zoneX < -ZONE_MAX || zoneX > ZONE_MAX || zoneY < -ZONE_MAX || zoneY > ZONE_MAX) {
        spdlog::warn("GameServer: Player '{}' sent invalid zone ({}, {}) — out of bounds", player.name, zoneX, zoneY);
        return;
    }

    spdlog::debug("GameServer: Player '{}' requested zone ({}, {})", player.name, zoneX, zoneY);

    ZoneCoord requestedZone(zoneX, zoneY);

    // Send all entities in the requested zone (and adjacent zones) to this player
    for (auto& [entityId, entity] : m_entities) {
        if (entity.owner == player.id) continue; // Don't send own entities
        if (!requestedZone.IsAdjacent(entity.zone) && !(entity.zone.x == zoneX && entity.zone.y == zoneY))
            continue;

        PacketWriter writer;
        writer.WriteHeader(MessageType::S2C_EntitySpawn);
        writer.WriteU32(entity.id);
        writer.WriteU8(static_cast<uint8_t>(entity.type));
        writer.WriteU32(entity.owner);
        writer.WriteU32(entity.templateId);
        writer.WriteF32(entity.position.x);
        writer.WriteF32(entity.position.y);
        writer.WriteF32(entity.position.z);
        writer.WriteU32(entity.rotation.Compress());
        writer.WriteU32(entity.factionId);
        uint16_t nameLen = static_cast<uint16_t>(
            std::min<size_t>(entity.templateName.size(), 255));
        writer.WriteU16(nameLen);
        if (nameLen > 0) {
            writer.WriteRaw(entity.templateName.data(), nameLen);
        }

        // Include health state
        writer.WriteU8(1); // hasExtendedState
        for (int i = 0; i < 7; i++) writer.WriteF32(entity.health[i]);
        writer.WriteU8(entity.alive ? 1 : 0);

        ENetPacket* pkt = enet_packet_create(writer.Data(), writer.Size(), ENET_PACKET_FLAG_RELIABLE);
        if (!pkt) {
            spdlog::error("Failed to create packet ({} bytes)", writer.Size());
            continue;
        }
        enet_peer_send(player.peer, KMP_CHANNEL_RELIABLE_ORDERED, pkt);
    }
}

void GameServer::SendWorldSnapshot(ConnectedPlayer& player) {
    int sent = 0;
    int skippedOrphan = 0;
    int skippedPosition = 0;

    for (auto& [entityId, entity] : m_entities) {
        // Skip entities owned by disconnected players (orphans from stale saves)
        if (entity.owner != 0 && !GetPlayer(entity.owner)) {
            skippedOrphan++;
            continue;
        }

        // Skip entities with garbage positions (NaN, inf, or extreme values)
        if (std::isnan(entity.position.x) || std::isnan(entity.position.y) || std::isnan(entity.position.z) ||
            std::isinf(entity.position.x) || std::isinf(entity.position.y) || std::isinf(entity.position.z) ||
            std::abs(entity.position.x) > 1000000.f || std::abs(entity.position.y) > 1000000.f ||
            std::abs(entity.position.z) > 1000000.f) {
            skippedPosition++;
            continue;
        }

        PacketWriter writer;
        writer.WriteHeader(MessageType::S2C_EntitySpawn);
        writer.WriteU32(entity.id);
        writer.WriteU8(static_cast<uint8_t>(entity.type));
        writer.WriteU32(entity.owner);
        writer.WriteU32(entity.templateId);
        writer.WriteF32(entity.position.x);
        writer.WriteF32(entity.position.y);
        writer.WriteF32(entity.position.z);
        writer.WriteU32(entity.rotation.Compress());
        writer.WriteU32(entity.factionId);
        // Append template name so the client can spawn via SpawnManager
        uint16_t nameLen = static_cast<uint16_t>(
            std::min<size_t>(entity.templateName.size(), 255));
        writer.WriteU16(nameLen);
        if (nameLen > 0) {
            writer.WriteRaw(entity.templateName.data(), nameLen);
        }

        // Include health state so joining clients see correct limb damage
        writer.WriteU8(1); // hasExtendedState
        for (int i = 0; i < 7; i++) writer.WriteF32(entity.health[i]);
        writer.WriteU8(entity.alive ? 1 : 0);

        ENetPacket* pkt = enet_packet_create(writer.Data(), writer.Size(), ENET_PACKET_FLAG_RELIABLE);
        if (!pkt) {
            spdlog::error("Failed to create packet ({} bytes)", writer.Size());
            continue;
        }
        enet_peer_send(player.peer, KMP_CHANNEL_RELIABLE_ORDERED, pkt);

        // Send equipment for each non-zero slot
        for (int slot = 0; slot < 14; slot++) {
            if (entity.equipment[slot] != 0) {
                PacketWriter equipWriter;
                equipWriter.WriteHeader(MessageType::S2C_EquipmentUpdate);
                MsgEquipmentUpdate equipMsg{};
                equipMsg.entityId = entity.id;
                equipMsg.slot = static_cast<uint8_t>(slot);
                equipMsg.itemTemplateId = entity.equipment[slot];
                equipWriter.WriteRaw(&equipMsg, sizeof(equipMsg));

                ENetPacket* equipPkt = enet_packet_create(equipWriter.Data(), equipWriter.Size(), ENET_PACKET_FLAG_RELIABLE);
                if (!equipPkt) {
                    spdlog::error("Failed to create packet ({} bytes)", equipWriter.Size());
                    break;
                }
                enet_peer_send(player.peer, KMP_CHANNEL_RELIABLE_UNORDERED, equipPkt);
            }
        }
        sent++;
    }

    if (skippedOrphan > 0 || skippedPosition > 0) {
        spdlog::warn("GameServer: SendWorldSnapshot filtered {}/{} entities (orphan={}, badPos={})",
                     skippedOrphan + skippedPosition, m_entities.size(), skippedOrphan, skippedPosition);
    }
    spdlog::info("GameServer: Sent {} valid entities to player '{}'", sent, player.name);
}

// ── Broadcasting ──

void GameServer::Broadcast(const uint8_t* data, size_t len, int channel, uint32_t flags) {
    ENetPacket* pkt = enet_packet_create(data, len, flags);
    if (!pkt) {
        spdlog::error("Failed to create packet ({} bytes)", len);
        return;
    }
    enet_host_broadcast(m_host, channel, pkt);
}

void GameServer::BroadcastExcept(PlayerID exclude, const uint8_t* data, size_t len,
                                  int channel, uint32_t flags) {
    int sent = 0;
    for (auto& [id, player] : m_players) {
        if (id == exclude) continue;
        if (!player.peer) continue;
        ENetPacket* pkt = enet_packet_create(data, len, flags);
        if (!pkt) {
            spdlog::error("Failed to create packet ({} bytes)", len);
            continue;
        }
        enet_peer_send(player.peer, channel, pkt);
        sent++;
    }
    spdlog::debug("GameServer: BroadcastExcept(exclude={}) sent to {} peers ({} bytes, ch={})",
                  exclude, sent, len, channel);
}

void GameServer::SendTo(PlayerID id, const uint8_t* data, size_t len, int channel, uint32_t flags) {
    auto it = m_players.find(id);
    if (it != m_players.end()) {
        ENetPacket* pkt = enet_packet_create(data, len, flags);
        if (!pkt) {
            spdlog::error("Failed to create packet ({} bytes)", len);
            return;
        }
        enet_peer_send(it->second.peer, channel, pkt);
    }
}

// ── Helpers ──

ConnectedPlayer* GameServer::GetPlayer(ENetPeer* peer) {
    if (!peer || !peer->data) return nullptr;
    PlayerID id = static_cast<PlayerID>(reinterpret_cast<uintptr_t>(peer->data));
    auto it = m_players.find(id);
    return it != m_players.end() ? &it->second : nullptr;
}

ConnectedPlayer* GameServer::GetPlayer(PlayerID id) {
    auto it = m_players.find(id);
    return it != m_players.end() ? &it->second : nullptr;
}

PlayerID GameServer::NextPlayerId() {
    return m_nextPlayerId++;
}

// ── Admin Commands ──

void GameServer::KickPlayer(PlayerID id, const std::string& reason) {
    std::lock_guard lock(m_mutex);
    auto* player = GetPlayer(id);
    if (!player) {
        spdlog::warn("GameServer: Player {} not found", id);
        return;
    }

    spdlog::info("GameServer: Kicking player '{}' ({})", player->name, reason);
    BroadcastSystemMessage(player->name + " was kicked: " + reason);
    enet_peer_disconnect(player->peer, 0);
}

void GameServer::BroadcastSystemMessage(const std::string& message) {
    std::lock_guard lock(m_mutex);
    spdlog::info("[System] {}", message);

    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_SystemMessage);
    writer.WriteU32(0); // system
    writer.WriteString(message);
    Broadcast(writer.Data(), writer.Size(), KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
}

void GameServer::LoadWorld() {
    std::string savePath = m_config.savePath.empty()
        ? "kenshi_mp_world.json" : m_config.savePath;

    float loadedTime = m_timeOfDay;
    int loadedWeather = m_weatherState;
    EntityID loadedNextId = m_nextEntityId;

    if (LoadWorldFromFile(savePath, m_entities, m_savedPlayers, loadedTime, loadedWeather, loadedNextId)) {
        m_timeOfDay = loadedTime;
        m_weatherState = loadedWeather;
        m_nextEntityId = loadedNextId;
        spdlog::info("GameServer: Loaded world from '{}' ({} entities, {} saved players, time={:.2f})",
                     savePath, m_entities.size(), m_savedPlayers.size(), m_timeOfDay);
    } else {
        spdlog::info("GameServer: No saved world at '{}', starting fresh", savePath);
    }
}

void GameServer::SaveWorld() {
    std::lock_guard lock(m_mutex);
    spdlog::info("GameServer: Saving world... ({} entities, {} players)",
                 m_entities.size(), m_players.size());

    std::string savePath = m_config.savePath.empty()
        ? "kenshi_mp_world.json" : m_config.savePath;

    // Build a combined saved-players map: merge currently-connected players
    // (their live entity ownership) with previously-saved offline players.
    auto savedForWrite = m_savedPlayers;
    for (auto& [pid, cp] : m_players) {
        // Key live players by their SECRET session token, not the public display
        // name (R1 fix). Keying by name re-opened I-05: after autosave+restart the
        // map key became the public name and any client could reclaim by sending
        // that name as its session token.
        if (cp.sessionToken.empty()) continue;
        SavedPlayer sp;
        sp.token = cp.sessionToken;
        sp.name = cp.name;
        for (auto& [eid, entity] : m_entities) {
            if (entity.owner == pid) sp.entityIds.push_back(eid);
        }
        if (!sp.entityIds.empty()) {
            savedForWrite[cp.sessionToken] = std::move(sp);
        }
    }

    if (SaveWorldToFile(savePath, m_entities, savedForWrite, m_timeOfDay, m_weatherState)) {
        spdlog::info("GameServer: World saved to '{}'", savePath);
    } else {
        spdlog::error("GameServer: Failed to save world to '{}'", savePath);
    }
}

void GameServer::PrintStatus() {
    std::lock_guard lock(m_mutex);
    spdlog::info("=== Server Status ===");
    spdlog::info("Players: {}/{}", m_players.size(), m_config.maxPlayers);
    spdlog::info("Entities: {}", m_entities.size());
    spdlog::info("Tick: {} | Time: {:.2f} | Uptime: {:.0f}s", m_serverTick, m_timeOfDay, m_uptime);
}

void GameServer::PrintPlayers() {
    std::lock_guard lock(m_mutex);
    spdlog::info("=== Connected Players ({}) ===", m_players.size());
    for (auto& [id, player] : m_players) {
        spdlog::info("  [{}] {} - ping: {}ms - zone: ({},{})",
                     id, player.name, player.ping, player.zone.x, player.zone.y);
    }
}

// ── Inventory Handlers ──

void GameServer::HandleItemPickup(ConnectedPlayer& player, PacketReader& reader) {
    MsgItemPickup msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) {
        spdlog::error("GameServer: HandleItemPickup ReadRaw failed for player '{}'", player.name);
        return;
    }

    // Validate entity ownership
    auto it = m_entities.find(msg.entityId);
    if (it == m_entities.end()) {
        spdlog::warn("GameServer: HandleItemPickup entity {} not found (player '{}')",
                     msg.entityId, player.name);
        return;
    }
    if (it->second.owner != player.id) {
        spdlog::warn("GameServer: HandleItemPickup entity {} owner mismatch: entity.owner={} player.id={} (player '{}')",
                     msg.entityId, it->second.owner, player.id, player.name);
        return;
    }

    spdlog::info("GameServer: Player '{}' picked up item {} x{} (entity {})",
                 player.name, msg.itemTemplateId, msg.quantity, msg.entityId);

    // Broadcast inventory update to all other players
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_InventoryUpdate);
    MsgInventoryUpdate update{};
    update.entityId = msg.entityId;
    update.action = 0; // add
    update.itemTemplateId = msg.itemTemplateId;
    update.quantity = msg.quantity;
    writer.WriteRaw(&update, sizeof(update));
    BroadcastExcept(player.id, writer.Data(), writer.Size(),
                   KMP_CHANNEL_RELIABLE_UNORDERED, ENET_PACKET_FLAG_RELIABLE);
}

void GameServer::HandleItemDrop(ConnectedPlayer& player, PacketReader& reader) {
    MsgItemDrop msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) {
        spdlog::error("GameServer: HandleItemDrop ReadRaw failed for player '{}'", player.name);
        return;
    }

    auto it = m_entities.find(msg.entityId);
    if (it == m_entities.end()) {
        spdlog::warn("GameServer: HandleItemDrop entity {} not found (player '{}')",
                     msg.entityId, player.name);
        return;
    }
    if (it->second.owner != player.id) {
        spdlog::warn("GameServer: HandleItemDrop entity {} owner mismatch: entity.owner={} player.id={} (player '{}')",
                     msg.entityId, it->second.owner, player.id, player.name);
        return;
    }

    spdlog::info("GameServer: Player '{}' dropped item {} at ({:.1f},{:.1f},{:.1f})",
                 player.name, msg.itemTemplateId, msg.posX, msg.posY, msg.posZ);

    // Broadcast to others
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_InventoryUpdate);
    MsgInventoryUpdate update{};
    update.entityId = msg.entityId;
    update.action = 1; // remove
    update.itemTemplateId = msg.itemTemplateId;
    update.quantity = 1;
    writer.WriteRaw(&update, sizeof(update));
    BroadcastExcept(player.id, writer.Data(), writer.Size(),
                   KMP_CHANNEL_RELIABLE_UNORDERED, ENET_PACKET_FLAG_RELIABLE);
}

void GameServer::HandleTradeRequest(ConnectedPlayer& player, PacketReader& reader) {
    MsgTradeRequest msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) return;

    // Validate buyer ownership
    auto buyerIt = m_entities.find(msg.buyerEntityId);
    if (buyerIt == m_entities.end() || buyerIt->second.owner != player.id) return;

    // Basic trade validation
    if (msg.quantity <= 0 || msg.quantity > 10000 || msg.price < 0) {
        spdlog::warn("GameServer: Invalid trade from '{}': qty={} price={}",
                     player.name, msg.quantity, msg.price);
        PacketWriter writer;
        writer.WriteHeader(MessageType::S2C_TradeResult);
        MsgTradeResult result{};
        result.buyerEntityId = msg.buyerEntityId;
        result.itemTemplateId = msg.itemTemplateId;
        result.quantity = msg.quantity;
        result.success = 0; // denied
        writer.WriteRaw(&result, sizeof(result));
        SendTo(player.id, writer.Data(), writer.Size(),
               KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
        return;
    }

    // Validate seller entity exists (0 = NPC shop, which is OK)
    if (msg.sellerEntityId != 0) {
        auto sellerIt = m_entities.find(msg.sellerEntityId);
        if (sellerIt == m_entities.end()) {
            spdlog::warn("GameServer: Trade seller entity {} not found", msg.sellerEntityId);
            PacketWriter writer;
            writer.WriteHeader(MessageType::S2C_TradeResult);
            MsgTradeResult result{};
            result.buyerEntityId = msg.buyerEntityId;
            result.itemTemplateId = msg.itemTemplateId;
            result.quantity = msg.quantity;
            result.success = 0;
            writer.WriteRaw(&result, sizeof(result));
            SendTo(player.id, writer.Data(), writer.Size(),
                   KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
            return;
        }
    }

    spdlog::info("GameServer: Trade from '{}': buyer={} seller={} item={} qty={} price={}",
                 player.name, msg.buyerEntityId, msg.sellerEntityId,
                 msg.itemTemplateId, msg.quantity, msg.price);

    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_TradeResult);
    MsgTradeResult result{};
    result.buyerEntityId = msg.buyerEntityId;
    result.itemTemplateId = msg.itemTemplateId;
    result.quantity = msg.quantity;
    result.success = 1;
    writer.WriteRaw(&result, sizeof(result));
    Broadcast(writer.Data(), writer.Size(),
             KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
}

// ── Squad Handlers ──

void GameServer::HandleSquadCreate(ConnectedPlayer& player, PacketReader& reader) {
    uint32_t creatorEntityId;
    if (!reader.ReadU32(creatorEntityId)) return;
    std::string squadName;
    if (!reader.ReadString(squadName)) return;

    // Validate creator ownership
    auto it = m_entities.find(creatorEntityId);
    if (it == m_entities.end() || it->second.owner != player.id) return;

    // Assign server-side squad ID (separate ID space to avoid entity collisions)
    uint32_t squadNetId = m_nextSquadId++;

    spdlog::info("GameServer: Player '{}' created squad '{}' (netId={})",
                 player.name, squadName, squadNetId);

    // Broadcast to all players
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_SquadCreated);
    writer.WriteU32(creatorEntityId);
    writer.WriteU32(squadNetId);
    writer.WriteString(squadName);
    Broadcast(writer.Data(), writer.Size(),
             KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
}

void GameServer::HandleSquadAddMember(ConnectedPlayer& player, PacketReader& reader) {
    MsgSquadMemberUpdate msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) return;

    // Validate member ownership
    auto it = m_entities.find(msg.memberEntityId);
    if (it == m_entities.end() || it->second.owner != player.id) return;

    spdlog::info("GameServer: Player '{}' {} member {} to/from squad {}",
                 player.name, msg.action == 0 ? "added" : "removed",
                 msg.memberEntityId, msg.squadNetId);

    // Broadcast to all other players
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_SquadMemberUpdate);
    writer.WriteRaw(&msg, sizeof(msg));
    BroadcastExcept(player.id, writer.Data(), writer.Size(),
                   KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
}

// ── Faction Handlers ──

void GameServer::HandleFactionRelation(ConnectedPlayer& player, PacketReader& reader) {
    MsgFactionRelation msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) return;

    // Validate relation bounds. isfinite first: NaN fails BOTH comparisons below
    // (IEEE-754 unordered), so without this a NaN relation would slip through and
    // be broadcast to all clients (R7).
    if (!std::isfinite(msg.relation) || msg.relation < -100.f || msg.relation > 100.f) {
        spdlog::warn("GameServer: Player '{}' sent invalid relation value {:.1f}", player.name, msg.relation);
        return;
    }

    // Authorize the faction change. Previously causerEntityId==0 ("system")
    // bypassed the ownership check entirely, letting any client rewrite global
    // faction standings (I-06). Now: causer 0 is host-only; any other causer
    // must be an entity owned by the sender.
    if (msg.causerEntityId == 0) {
        if (player.id != m_hostPlayerId) {
            spdlog::warn("GameServer: Non-host player '{}' tried a system (causer=0) faction change",
                         player.name);
            return;
        }
    } else {
        auto it = m_entities.find(msg.causerEntityId);
        if (it == m_entities.end() || it->second.owner != player.id) {
            spdlog::warn("GameServer: Player '{}' sent faction relation with invalid causer {}",
                         player.name, msg.causerEntityId);
            return;
        }
    }

    spdlog::info("GameServer: Faction relation change from '{}': faction {} <-> {} = {:.1f}",
                 player.name, msg.factionIdA, msg.factionIdB, msg.relation);

    // Broadcast to ALL players (including sender) to ensure consistency
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_FactionRelation);
    writer.WriteRaw(&msg, sizeof(msg));
    Broadcast(writer.Data(), writer.Size(),
             KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
}

// ── Building Handlers ──

void GameServer::HandleBuildDismantle(ConnectedPlayer& player, PacketReader& reader) {
    MsgBuildDismantle msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) {
        spdlog::error("GameServer: HandleBuildDismantle ReadRaw failed for player '{}'", player.name);
        return;
    }

    // Find building
    auto it = m_entities.find(msg.buildingId);
    if (it == m_entities.end()) {
        spdlog::warn("GameServer: HandleBuildDismantle building {} not found (player '{}', m_entities size={})",
                     msg.buildingId, player.name, m_entities.size());
        return;
    }

    // Ownership check: only the building owner (or host) can dismantle
    if (it->second.owner != player.id && player.id != m_hostPlayerId) {
        spdlog::warn("GameServer: Player '{}' tried to dismantle building {} owned by player {}",
                     player.name, msg.buildingId, it->second.owner);
        return;
    }

    spdlog::info("GameServer: Player '{}' dismantled building {} (owner={})",
                 player.name, msg.buildingId, it->second.owner);

    // Remove building from server state
    m_entities.erase(it);

    // Broadcast destruction to all
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_BuildDestroyed);
    writer.WriteU32(msg.buildingId);
    writer.WriteU8(2); // reason: dismantled
    BroadcastExcept(player.id, writer.Data(), writer.Size(),
                    KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
}

void GameServer::HandleBuildRepair(ConnectedPlayer& player, PacketReader& reader) {
    MsgBuildRepair msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) return;

    auto it = m_entities.find(msg.buildingId);
    if (it == m_entities.end()) return;

    // Ownership check: only the building owner (or host) can repair
    if (it->second.owner != player.id && player.id != m_hostPlayerId) {
        spdlog::warn("GameServer: Player '{}' tried to repair building {} owned by player {}",
                     player.name, msg.buildingId, it->second.owner);
        return;
    }

    // Validate repair amount (reject negative, NaN, or unreasonably large values)
    if (msg.amount <= 0.f || std::isnan(msg.amount) || msg.amount > 1.f) return;

    // Update server-side building progress
    it->second.buildProgress = std::clamp(it->second.buildProgress + msg.amount, 0.f, 1.f);

    spdlog::debug("GameServer: Building {} repair +{:.2f} -> {:.2f} by '{}'",
                  msg.buildingId, msg.amount, it->second.buildProgress, player.name);

    // Broadcast progress update
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_BuildProgress);
    MsgBuildProgress progress{};
    progress.entityId = msg.buildingId;
    progress.progress = it->second.buildProgress;
    writer.WriteRaw(&progress, sizeof(progress));
    BroadcastExcept(player.id, writer.Data(), writer.Size(),
                   KMP_CHANNEL_RELIABLE_UNORDERED, ENET_PACKET_FLAG_RELIABLE);
}

// ── Combat Stance Handler ──

void GameServer::HandleCombatStance(ConnectedPlayer& player, PacketReader& reader) {
    MsgCombatStance msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) return;

    // Validate entity ownership
    auto it = m_entities.find(msg.entityId);
    if (it == m_entities.end() || it->second.owner != player.id) return;

    // Validate stance value
    if (msg.stance > 3) return;

    spdlog::debug("GameServer: Player '{}' set entity {} stance to {}", player.name, msg.entityId, msg.stance);

    // Broadcast to other players
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_CombatBlock); // Reuse CombatBlock for stance sync (no dedicated S2C type)
    writer.WriteRaw(&msg, sizeof(msg));
    BroadcastExcept(player.id, writer.Data(), writer.Size(),
                   KMP_CHANNEL_RELIABLE_UNORDERED, ENET_PACKET_FLAG_RELIABLE);
}

// ── Combat authority helpers (RC2) ──
//
// IMPORTANT ARCHITECTURAL NOTE: combat in this mod is client-authoritative by
// design — the Kenshi engine on each client computes KO/death locally (via the
// hooked CharacterDeath/CharacterKO functions) and REPORTS the result; the
// attacker's machine reports the victim's death. The server's ResolveCombat is
// a parallel model that is never driven (the client never sends C2S_AttackIntent).
// We therefore cannot make combat fully server-authoritative without simulating
// Kenshi's engine server-side (out of scope). Instead we bound the report model:
// reject non-finite values and require the reporter's entity to actually be
// within combat range of the target — turning "one-shot any entity anywhere"
// into "must be in combat range", mirroring HandleAttackIntent's own gate.
static constexpr float KMP_MAX_COMBAT_REPORT_DISTANCE = 150.f; // generous (ranged) bound

static bool WithinCombatRange(const ServerEntity& a, const ServerEntity& b) {
    float dx = a.position.x - b.position.x;
    float dy = a.position.y - b.position.y;
    float dz = a.position.z - b.position.z;
    float distSq = dx * dx + dy * dy + dz * dz;
    return distSq <= KMP_MAX_COMBAT_REPORT_DISTANCE * KMP_MAX_COMBAT_REPORT_DISTANCE;
}

// ── Combat KO Handler ──

void GameServer::HandleCombatKO(ConnectedPlayer& player, PacketReader& reader) {
    // Client sends: entityId(u32), attackerId(u32), reason(u8), chestHealth(f32)
    uint32_t entityId = 0, attackerId = 0;
    uint8_t reason = 0;
    float chestHealth = 0.f;
    if (!reader.ReadU32(entityId) || !reader.ReadU32(attackerId) ||
        !reader.ReadU8(reason) || !reader.ReadF32(chestHealth)) return;

    // Reject non-finite health: a NaN/Inf would be written to server state,
    // rebroadcast into clients' game memory, and crash the JSON autosave (I-02/I-13).
    if (!std::isfinite(chestHealth)) {
        spdlog::warn("GameServer: Player '{}' sent non-finite KO health for entity {}", player.name, entityId);
        return;
    }
    chestHealth = std::clamp(chestHealth, -1000.f, 100.f);

    // Validate entity exists and is alive (reject KO on dead entities)
    auto it = m_entities.find(entityId);
    if (it == m_entities.end() || !it->second.alive) return;

    // Cross-player combat: accept KO reports from entity owner or attacker owner
    bool victimIsReporter = (it->second.owner == player.id);
    bool attackerIsReporter = false;
    if (attackerId != 0) {
        auto attackerIt = m_entities.find(attackerId);
        attackerIsReporter = (attackerIt != m_entities.end() && attackerIt->second.owner == player.id);
    }
    if (!victimIsReporter && !attackerIsReporter) return;

    // Cross-player KO (reporter is the attacker, not the victim's owner): require
    // the attacker entity to actually be within combat range of the victim, so a
    // modified client cannot KO arbitrary entities anywhere on the map (RC2/I-02).
    if (attackerIsReporter && !victimIsReporter) {
        auto attackerIt = m_entities.find(attackerId);
        if (attackerIt == m_entities.end() || !WithinCombatRange(attackerIt->second, it->second)) {
            spdlog::warn("GameServer: Rejected out-of-range KO from '{}' (attacker {} vs victim {})",
                         player.name, attackerId, entityId);
            return;
        }
    }

    spdlog::info("GameServer: Player '{}' reports entity {} KO (attacker={}, reason={}, health={:.1f})",
                 player.name, entityId, attackerId, reason, chestHealth);

    // Update server-side health — 'reason' is the KO cause (0=blood loss,
    // 1=head trauma, 2=other), NOT a body part index. The health value is
    // always chest health, so write to health[0] (chest).
    it->second.health[0] = chestHealth;

    // Broadcast KO to ALL players (including reporter for consistency)
    MsgCombatKO koMsg{};
    koMsg.entityId = entityId;
    koMsg.attackerId = attackerId;
    koMsg.bodyPart = reason;
    koMsg.resultHealth = chestHealth;

    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_CombatKO);
    writer.WriteRaw(&koMsg, sizeof(koMsg));
    Broadcast(writer.Data(), writer.Size(),
                   KMP_CHANNEL_RELIABLE_UNORDERED, ENET_PACKET_FLAG_RELIABLE);
}

// ── Combat Death Handler ──

void GameServer::HandleCombatDeath(ConnectedPlayer& player, PacketReader& reader) {
    MsgCombatDeath msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) return;

    // Validate entity exists
    auto it = m_entities.find(msg.entityId);
    if (it == m_entities.end()) return;

    // Reject duplicate death reports — both players may report the same kill
    if (!it->second.alive) {
        spdlog::debug("GameServer: Ignoring duplicate death report for entity {} from '{}'",
                      msg.entityId, player.name);
        return;
    }

    // Cross-player combat: accept death reports from either the entity owner
    // or the killer's owner. When player A kills player B's character, player A
    // reports the death with killerId pointing to their own entity.
    bool victimIsReporter = (it->second.owner == player.id);
    bool killerIsReporter = false;
    if (msg.killerId != 0) {
        auto killerIt = m_entities.find(msg.killerId);
        killerIsReporter = (killerIt != m_entities.end() && killerIt->second.owner == player.id);
    }
    if (!victimIsReporter && !killerIsReporter) return;

    // Cross-player kill (reporter owns the killer, not the victim): require the
    // killer entity to be within combat range of the victim. This is the fix for
    // the critical one-shot-any-entity exploit (I-01): a modified client can no
    // longer mark an arbitrary character anywhere on the map as dead — it must
    // own a killer entity that is physically next to the victim.
    if (killerIsReporter && !victimIsReporter) {
        auto killerIt = m_entities.find(msg.killerId);
        if (killerIt == m_entities.end() || !WithinCombatRange(killerIt->second, it->second)) {
            spdlog::warn("GameServer: Rejected out-of-range death report from '{}' (killer {} vs victim {})",
                         player.name, msg.killerId, msg.entityId);
            return;
        }
    }

    // Mark entity as dead on the server so future attacks are rejected
    it->second.alive = false;

    spdlog::info("GameServer: Player '{}' reports entity {} death (killer={}, reporter={})",
                 player.name, msg.entityId, msg.killerId,
                 victimIsReporter ? "victim-owner" : "killer-owner");

    // Broadcast death to ALL players (including reporter for authoritative sync)
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_CombatDeath);
    writer.WriteRaw(&msg, sizeof(msg));
    Broadcast(writer.Data(), writer.Size(),
                   KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
}

// ── Limb Health Handler ──

void GameServer::HandleLimbHealth(ConnectedPlayer& player, PacketReader& reader) {
    MsgLimbHealth msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) return;

    // Validate entity ownership
    auto it = m_entities.find(msg.entityId);
    if (it == m_entities.end() || it->second.owner != player.id) return;

    // Sanitize each limb value (NaN/Inf would propagate into clients' game
    // memory and the world save — I-13). Rewrite msg too so the rebroadcast
    // below carries only finite values.
    for (int i = 0; i < 7; i++) {
        msg.health[i] = SanitizeHealth(msg.health[i]);
        it->second.limbHealth[i] = msg.health[i];
    }

    spdlog::debug("GameServer: Player '{}' limb health for entity {} (chest={:.1f})",
                  player.name, msg.entityId, msg.health[static_cast<int>(BodyPart::Chest)]);

    // Broadcast to other players
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_LimbHealth);
    writer.WriteRaw(&msg, sizeof(msg));
    BroadcastExcept(player.id, writer.Data(), writer.Size(),
                    KMP_CHANNEL_RELIABLE_UNORDERED, ENET_PACKET_FLAG_RELIABLE);
}

// ── Status Effect Handler ──

void GameServer::HandleStatusEffect(ConnectedPlayer& player, PacketReader& reader) {
    MsgStatusEffect msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) return;

    // Validate entity ownership
    auto it = m_entities.find(msg.entityId);
    if (it == m_entities.end() || it->second.owner != player.id) return;

    // Validate effect type range
    if (msg.effectType > StatusEffect_Bandaged) return;

    // Store status effect on server entity
    it->second.statusEffects[msg.effectType] = msg.active;

    spdlog::debug("GameServer: Player '{}' entity {} status effect {} = {}",
                  player.name, msg.entityId, msg.effectType, msg.active);

    // Broadcast to other players
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_StatusEffect);
    writer.WriteRaw(&msg, sizeof(msg));
    BroadcastExcept(player.id, writer.Data(), writer.Size(),
                    KMP_CHANNEL_RELIABLE_UNORDERED, ENET_PACKET_FLAG_RELIABLE);
}

// ── Item Transfer Handler ──

void GameServer::HandleItemTransfer(ConnectedPlayer& player, PacketReader& reader) {
    MsgItemTransfer msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) return;

    // Validate: player must own the source entity
    auto srcIt = m_entities.find(msg.sourceEntityId);
    if (srcIt == m_entities.end() || srcIt->second.owner != player.id) {
        spdlog::warn("GameServer: Player '{}' tried to transfer from entity {} they don't own",
                     player.name, msg.sourceEntityId);
        return;
    }

    // Validate: destination entity must exist
    auto destIt = m_entities.find(msg.destEntityId);
    if (destIt == m_entities.end()) {
        spdlog::warn("GameServer: Transfer dest entity {} not found", msg.destEntityId);
        return;
    }

    // Validate quantity
    if (msg.quantity <= 0 || msg.quantity > 10000) return;

    spdlog::info("GameServer: Player '{}' transferred {}x item {} from entity {} to {}",
                 player.name, msg.quantity, msg.itemTemplateId,
                 msg.sourceEntityId, msg.destEntityId);

    // Broadcast inventory updates to affected players
    // Source loses item
    {
        PacketWriter writer;
        writer.WriteHeader(MessageType::S2C_InventoryUpdate);
        MsgInventoryUpdate update{};
        update.entityId = msg.sourceEntityId;
        update.action = 1; // remove
        update.itemTemplateId = msg.itemTemplateId;
        update.quantity = msg.quantity;
        writer.WriteRaw(&update, sizeof(update));
        BroadcastExcept(player.id, writer.Data(), writer.Size(),
                       KMP_CHANNEL_RELIABLE_UNORDERED, ENET_PACKET_FLAG_RELIABLE);
    }

    // Destination gains item
    {
        PacketWriter writer;
        writer.WriteHeader(MessageType::S2C_InventoryUpdate);
        MsgInventoryUpdate update{};
        update.entityId = msg.destEntityId;
        update.action = 0; // add
        update.itemTemplateId = msg.itemTemplateId;
        update.quantity = msg.quantity;
        writer.WriteRaw(&update, sizeof(update));
        BroadcastExcept(player.id, writer.Data(), writer.Size(),
                       KMP_CHANNEL_RELIABLE_UNORDERED, ENET_PACKET_FLAG_RELIABLE);
    }
}

// ── Door Interaction Handler ──

void GameServer::HandleDoorInteract(ConnectedPlayer& player, PacketReader& reader) {
    MsgDoorInteract msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) return;

    // Validate: actor must be owned by player
    auto actorIt = m_entities.find(msg.actorEntityId);
    if (actorIt == m_entities.end() || actorIt->second.owner != player.id) return;

    // Validate: building entity must exist
    auto buildingIt = m_entities.find(msg.entityId);
    if (buildingIt == m_entities.end()) return;

    // Validate action
    if (msg.action > 3) return;

    // Proximity: the actor must be next to the door/gate — no remote door ops
    // across the map (I-12). Mirrors the build-distance discipline.
    {
        constexpr float DOOR_INTERACT_DISTANCE = 12.f;
        float dx = actorIt->second.position.x - buildingIt->second.position.x;
        float dy = actorIt->second.position.y - buildingIt->second.position.y;
        float dz = actorIt->second.position.z - buildingIt->second.position.z;
        if (dx * dx + dy * dy + dz * dz > DOOR_INTERACT_DISTANCE * DOOR_INTERACT_DISTANCE) {
            spdlog::warn("GameServer: Player '{}' tried to interact with distant door {}",
                         player.name, msg.entityId);
            return;
        }
    }

    // Lock (2) / unlock (3) are base-defense actions: only the building owner
    // (or host) may change the lock state, even when standing next to it (I-12).
    if ((msg.action == 2 || msg.action == 3) &&
        buildingIt->second.owner != player.id && player.id != m_hostPlayerId) {
        spdlog::warn("GameServer: Player '{}' tried to {} door {} they don't own",
                     player.name, msg.action == 2 ? "lock" : "unlock", msg.entityId);
        return;
    }

    const char* actionNames[] = {"open", "close", "lock", "unlock"};
    spdlog::info("GameServer: Player '{}' {} door/gate {}",
                 player.name, actionNames[msg.action], msg.entityId);

    // Broadcast door state to all players
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_DoorState);
    MsgDoorState state{};
    state.entityId = msg.entityId;
    state.state = msg.action; // action maps directly to state enum
    writer.WriteRaw(&state, sizeof(state));
    Broadcast(writer.Data(), writer.Size(),
             KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
}

// ── Admin Command Handler ──

void GameServer::HandleLobbyReady(ConnectedPlayer& player, PacketReader& reader) {
    player.lobbyReady = true;
    spdlog::info("GameServer: Player '{}' (slot {}) is READY", player.name, player.id);

    // Broadcast to all clients that this player is ready
    BroadcastSystemMessage(player.name + " is ready!");

    // Check if ALL connected players are ready
    bool allReady = true;
    int readyCount = 0;
    for (const auto& [id, p] : m_players) {
        if (p.lobbyReady) {
            readyCount++;
        } else {
            allReady = false;
        }
    }

    spdlog::info("GameServer: {}/{} players ready", readyCount, m_players.size());

    if (allReady && !m_players.empty()) {
        spdlog::info("GameServer: ALL PLAYERS READY — sending LobbyStart!");
        BroadcastSystemMessage("All players ready — starting game!");

        PacketWriter writer;
        writer.WriteHeader(MessageType::S2C_LobbyStart);
        writer.WriteU8(static_cast<uint8_t>(m_players.size()));
        Broadcast(writer.Data(), writer.Size(),
                  KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
    }
}

void GameServer::HandleAdminCommand(ConnectedPlayer& player, PacketReader& reader) {
    MsgAdminCommand msg;
    if (!reader.ReadRaw(&msg, sizeof(msg))) return;

    // Force-terminate the fixed text buffer before it is ever read as a C-string
    // (msg.textParam[0] check and std::string conversion below). Without this an
    // attacker can omit the NUL and over-read the server stack, then have the
    // result broadcast to every client (I-11 / RC4).
    msg.textParam[sizeof(msg.textParam) - 1] = '\0';

    // Admin commands (kick/ban/time/weather) require a TOKEN-AUTHENTICATED host.
    // A first-connector gameplay host (no hostToken configured) is NOT admin —
    // otherwise an open server would hand kick/ban to whoever connects first (I-04).
    if (player.id != m_hostPlayerId || !m_hostAuthenticated) {
        spdlog::warn("GameServer: Player '{}' tried admin command type {} without authenticated-host rights",
                     player.name, msg.commandType);
        PacketWriter writer;
        writer.WriteHeader(MessageType::S2C_AdminResponse);
        MsgAdminResponse resp{};
        resp.success = 0;
        snprintf(resp.responseText, sizeof(resp.responseText), "Permission denied: only the host can use admin commands.");
        writer.WriteRaw(&resp, sizeof(resp));
        SendTo(player.id, writer.Data(), writer.Size(),
               KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
        return;
    }

    std::string responseText;

    switch (msg.commandType) {
    case 0: { // Kick
        auto* target = GetPlayer(msg.targetPlayerId);
        if (target && target->id != m_hostPlayerId) {
            std::string reason = msg.textParam[0] ? msg.textParam : "Kicked by host";
            spdlog::info("GameServer: Host kicked player '{}': {}", target->name, reason);
            BroadcastSystemMessage(target->name + " was kicked: " + reason);

            // Send reject to kicked player
            PacketWriter kickWriter;
            kickWriter.WriteHeader(MessageType::S2C_HandshakeReject);
            MsgHandshakeReject reject{};
            reject.reasonCode = 2; // kicked
            strncpy(reject.reasonText, reason.c_str(), sizeof(reject.reasonText) - 1);
            kickWriter.WriteRaw(&reject, sizeof(reject));
            ENetPacket* kickPkt = enet_packet_create(kickWriter.Data(), kickWriter.Size(), ENET_PACKET_FLAG_RELIABLE);
            if (!kickPkt) {
                spdlog::error("Failed to create packet ({} bytes)", kickWriter.Size());
                enet_peer_disconnect_later(target->peer, 0);
            } else {
                enet_peer_send(target->peer, KMP_CHANNEL_RELIABLE_ORDERED, kickPkt);
                enet_peer_disconnect_later(target->peer, 0);
            }

            responseText = "Kicked " + target->name;
        } else {
            responseText = "Player not found or cannot kick host.";
        }
        break;
    }
    case 1: { // Ban (RC5/I-17 — ban list was previously unreachable)
        auto* target = GetPlayer(msg.targetPlayerId);
        if (target && target->id != m_hostPlayerId) {
            std::string banned = target->name;
            if (!target->ipAddress.empty()) {
                m_playerManager.BanIP(target->ipAddress);
            }
            std::string reason = msg.textParam[0] ? msg.textParam : "Banned by host";
            BroadcastSystemMessage(banned + " was banned: " + reason);

            PacketWriter banWriter;
            banWriter.WriteHeader(MessageType::S2C_HandshakeReject);
            MsgHandshakeReject reject{};
            reject.reasonCode = 2; // banned
            strncpy(reject.reasonText, reason.c_str(), sizeof(reject.reasonText) - 1);
            banWriter.WriteRaw(&reject, sizeof(reject));
            ENetPacket* banPkt = enet_packet_create(banWriter.Data(), banWriter.Size(), ENET_PACKET_FLAG_RELIABLE);
            if (banPkt) enet_peer_send(target->peer, KMP_CHANNEL_RELIABLE_ORDERED, banPkt);
            enet_peer_disconnect_later(target->peer, 0);

            responseText = "Banned " + banned;
        } else {
            responseText = "Player not found or cannot ban host.";
        }
        break;
    }
    case 2: { // Set time
        float newTime = msg.floatParam;
        if (newTime >= 0.f && newTime < 1.f) {
            m_timeOfDay = newTime;
            BroadcastTimeSync();
            char buf[64];
            snprintf(buf, sizeof(buf), "Time set to %.2f", newTime);
            responseText = buf;
        } else {
            responseText = "Invalid time (0.0-1.0)";
        }
        break;
    }
    case 3: { // Set weather
        int weather = static_cast<int>(msg.floatParam);
        if (weather >= 0 && weather <= 4) {
            m_weatherState = weather;
            BroadcastTimeSync(); // Time sync includes weather
            const char* names[] = {"Clear", "Cloudy", "Dust Storm", "Rain", "Acid Rain"};
            responseText = std::string("Weather set to ") + names[weather];
        } else {
            responseText = "Invalid weather (0-4)";
        }
        break;
    }
    case 4: { // Announce
        std::string announcement = msg.textParam;
        if (!announcement.empty()) {
            BroadcastSystemMessage("[HOST] " + announcement);
            responseText = "Announced.";
        } else {
            responseText = "Empty announcement.";
        }
        break;
    }
    default:
        responseText = "Unknown admin command.";
        break;
    }

    // Send response
    PacketWriter writer;
    writer.WriteHeader(MessageType::S2C_AdminResponse);
    MsgAdminResponse resp{};
    resp.success = 1;
    strncpy(resp.responseText, responseText.c_str(), sizeof(resp.responseText) - 1);
    writer.WriteRaw(&resp, sizeof(resp));
    SendTo(player.id, writer.Data(), writer.Size(),
           KMP_CHANNEL_RELIABLE_ORDERED, ENET_PACKET_FLAG_RELIABLE);
}

// ── Master Server Registration ──

void GameServer::ConnectToMaster() {
    if (m_config.masterServer.empty()) {
        spdlog::info("GameServer: No master server configured, skipping registration");
        return;
    }

    // Create a separate ENet host for the master connection (1 peer, 1 channel)
    m_masterHost = enet_host_create(nullptr, 1, 1, 0, 0);
    if (!m_masterHost) {
        spdlog::warn("GameServer: Failed to create master ENet host");
        return;
    }

    ENetAddress masterAddr;
    enet_address_set_host(&masterAddr, m_config.masterServer.c_str());
    masterAddr.port = m_config.masterPort;

    m_masterPeer = enet_host_connect(m_masterHost, &masterAddr, 1, 0);
    if (!m_masterPeer) {
        spdlog::warn("GameServer: Failed to connect to master server at {}:{}",
                     m_config.masterServer, m_config.masterPort);
        enet_host_destroy(m_masterHost);
        m_masterHost = nullptr;
        return;
    }

    spdlog::info("GameServer: Connecting to master server at {}:{}...",
                 m_config.masterServer, m_config.masterPort);
}

void GameServer::SendMasterRegister() {
    if (!m_masterPeer || !m_masterConnected) return;

    PacketWriter writer;
    writer.WriteHeader(MessageType::MS_Register);

    MsgMasterRegister msg{};
    msg.protocolVersion = KMP_PROTOCOL_VERSION;
    msg.gamePort = m_config.port;
    msg.currentPlayers = static_cast<uint8_t>(m_players.size());
    msg.maxPlayers = static_cast<uint8_t>(m_config.maxPlayers);
    msg.timeOfDay = m_timeOfDay;
    msg.pvpEnabled = m_config.pvpEnabled ? 1 : 0;
    strncpy(msg.serverName, m_config.serverName.c_str(), sizeof(msg.serverName) - 1);

    // Try to fill external IP from UPnP discovery
    std::string extIP = m_upnp.GetExternalIP();
    if (!extIP.empty()) {
        strncpy(msg.externalIP, extIP.c_str(), sizeof(msg.externalIP) - 1);
    }
    // If empty, master server will use the peer's IP

    writer.WriteRaw(&msg, sizeof(msg));

    ENetPacket* packet = enet_packet_create(writer.Data(), writer.Size(),
                                             ENET_PACKET_FLAG_RELIABLE);
    if (!packet) {
        spdlog::error("Failed to create packet ({} bytes)", writer.Size());
        return;
    }
    enet_peer_send(m_masterPeer, 0, packet);
    enet_host_flush(m_masterHost);

    spdlog::info("GameServer: Registered with master server (name='{}', port={})",
                 m_config.serverName, m_config.port);
}

void GameServer::SendMasterHeartbeat() {
    if (!m_masterPeer || !m_masterConnected) return;

    PacketWriter writer;
    writer.WriteHeader(MessageType::MS_Heartbeat);

    MsgMasterHeartbeat msg{};
    msg.gamePort = m_config.port;
    msg.currentPlayers = static_cast<uint8_t>(m_players.size());
    msg.maxPlayers = static_cast<uint8_t>(m_config.maxPlayers);
    msg.timeOfDay = m_timeOfDay;

    writer.WriteRaw(&msg, sizeof(msg));

    ENetPacket* packet = enet_packet_create(writer.Data(), writer.Size(),
                                             ENET_PACKET_FLAG_RELIABLE);
    if (!packet) {
        spdlog::error("Failed to create packet ({} bytes)", writer.Size());
        return;
    }
    enet_peer_send(m_masterPeer, 0, packet);
}

void GameServer::SendMasterDeregister() {
    if (!m_masterPeer || !m_masterConnected) return;

    PacketWriter writer;
    writer.WriteHeader(MessageType::MS_Deregister);

    ENetPacket* packet = enet_packet_create(writer.Data(), writer.Size(),
                                             ENET_PACKET_FLAG_RELIABLE);
    if (!packet) {
        spdlog::error("Failed to create packet ({} bytes)", writer.Size());
        return;
    }
    enet_peer_send(m_masterPeer, 0, packet);
    enet_host_flush(m_masterHost);
}

void GameServer::UpdateMasterConnection(float deltaTime) {
    if (!m_masterHost) return;

    // Poll master connection events
    ENetEvent event;
    while (enet_host_service(m_masterHost, &event, 0) > 0) {
        switch (event.type) {
            case ENET_EVENT_TYPE_CONNECT:
                m_masterConnected = true;
                m_masterReconnectDelay = 5.f; // Reset backoff on success
                spdlog::info("GameServer: Connected to master server");
                SendMasterRegister();
                break;
            case ENET_EVENT_TYPE_DISCONNECT:
                m_masterConnected = false;
                m_masterPeer = nullptr;
                spdlog::warn("GameServer: Disconnected from master server — will retry in {:.0f}s",
                             m_masterReconnectDelay);
                break;
            case ENET_EVENT_TYPE_RECEIVE:
                enet_packet_destroy(event.packet);
                break;
            default:
                break;
        }
    }

    // Send heartbeat if connected
    if (m_masterConnected) {
        m_timeSinceMasterHeartbeat += deltaTime;
        if (m_timeSinceMasterHeartbeat >= m_masterHeartbeatInterval) {
            SendMasterHeartbeat();
            m_timeSinceMasterHeartbeat = 0.f;
        }
    } else if (m_masterPeer == nullptr && !m_config.masterServer.empty()) {
        // Auto-reconnect with exponential backoff (5s → 10s → 20s → 40s → max 60s)
        m_masterReconnectTimer += deltaTime;
        if (m_masterReconnectTimer >= m_masterReconnectDelay) {
            m_masterReconnectTimer = 0.f;
            spdlog::info("GameServer: Reconnecting to master server at {}:{}...",
                         m_config.masterServer, m_config.masterPort);

            ENetAddress masterAddr;
            enet_address_set_host(&masterAddr, m_config.masterServer.c_str());
            masterAddr.port = m_config.masterPort;
            m_masterPeer = enet_host_connect(m_masterHost, &masterAddr, 1, 0);
            if (!m_masterPeer) {
                spdlog::warn("GameServer: Master reconnect failed to start");
            }

            // Exponential backoff (cap at 60s)
            m_masterReconnectDelay = std::min(m_masterReconnectDelay * 2.f, 60.f);
        }
    }

    enet_host_flush(m_masterHost);
}

} // namespace kmp
