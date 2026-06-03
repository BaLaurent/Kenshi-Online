#include "server.h"
#include "kmp/constants.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <cstdio>
#include <cmath>
#include <spdlog/spdlog.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <cstring>
#endif

namespace kmp {

using json = nlohmann::json;

// Save/load world state to JSON for the dedicated server.
// This allows VPS-hosted servers to persist world state between restarts.

bool SaveWorldToFile(const std::string& path,
                     const std::unordered_map<EntityID, ServerEntity>& entities,
                     const std::unordered_map<std::string, SavedPlayer>& savedPlayers,
                     float timeOfDay, int weatherState) {
    json j;
    j["version"] = 3; // v3: m_savedPlayers keyed by session token (was display name)
    j["timeOfDay"] = timeOfDay;
    j["weather"] = weatherState;

    json entityArray = json::array();
    for (auto& [id, entity] : entities) {
        json e;
        e["id"] = entity.id;
        e["type"] = static_cast<int>(entity.type);
        e["owner"] = entity.owner;
        e["templateId"] = entity.templateId;
        e["factionId"] = entity.factionId;
        e["position"] = {entity.position.x, entity.position.y, entity.position.z};
        e["rotation"] = {entity.rotation.w, entity.rotation.x, entity.rotation.y, entity.rotation.z};
        e["alive"] = entity.alive;

        json healthArr = json::array();
        for (int i = 0; i < 7; i++) healthArr.push_back(entity.health[i]);
        e["health"] = healthArr;

        e["templateName"] = entity.templateName;

        json equipArr = json::array();
        for (int i = 0; i < 14; i++) equipArr.push_back(entity.equipment[i]);
        e["equipment"] = equipArr;

        entityArray.push_back(e);
    }
    j["entities"] = entityArray;

    // Save token→entity mapping so reconnecting players can reclaim entities.
    // Keyed by the secret session token (v3); shape is identical to v2 so an
    // older v2 save still parses (its name-keys become dead tokens, harmlessly
    // orphan-cleaned), avoiding a parse-throw → world wipe on load.
    json playersObj = json::object();
    for (auto& [token, sp] : savedPlayers) {
        json ids = json::array();
        for (EntityID eid : sp.entityIds) ids.push_back(eid);
        playersObj[token] = ids;
    }
    j["players"] = playersObj;

    // Write to temp file first, then atomically replace the destination.
    // This ensures no data-loss window: if we crash at any point, either
    // the old file or the new file exists in full on disk.
    std::string tmpPath = path + ".tmp";
    {
        std::ofstream file(tmpPath, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            spdlog::error("SaveWorld: Failed to open '{}'", tmpPath);
            return false;
        }
        // error_handler_t::replace: never throw on invalid UTF-8 in a stored
        // string (e.g. an attacker-supplied templateName) — substitute U+FFFD
        // instead, so a single crafted name can't crash the autosave (I-09).
        file << j.dump(2, ' ', false, json::error_handler_t::replace);
        file.flush();
        if (!file.good()) {
            spdlog::error("SaveWorld: Write/flush failed for '{}'", tmpPath);
            file.close();
            std::remove(tmpPath.c_str());
            return false;
        }
        file.close();
    }

#ifdef _WIN32
    // MoveFileExA with MOVEFILE_REPLACE_EXISTING is atomic on NTFS:
    // it replaces the destination in a single filesystem operation.
    // MOVEFILE_WRITE_THROUGH ensures the move is flushed to disk before returning.
    if (!MoveFileExA(tmpPath.c_str(), path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DWORD err = GetLastError();
        spdlog::error("SaveWorld: MoveFileExA failed (error {}), falling back to manual rename", err);

        // Fallback: rotate old -> backup, temp -> target.
        // Not fully atomic, but still safer than remove-then-rename because
        // the old file is preserved as a backup rather than deleted first.
        std::string backupPath = path + ".bak";
        std::remove(backupPath.c_str());

        // Move current file to backup (OK if it doesn't exist yet)
        std::rename(path.c_str(), backupPath.c_str());

        if (std::rename(tmpPath.c_str(), path.c_str()) != 0) {
            spdlog::error("SaveWorld: Fallback rename '{}' -> '{}' also failed", tmpPath, path);
            // Try to restore backup so we don't lose the old state
            std::rename(backupPath.c_str(), path.c_str());
            return false;
        }
        // Clean up backup on success
        std::remove(backupPath.c_str());
    }
#else
    // POSIX rename() atomically replaces the destination on the same filesystem,
    // so no temp-rotation fallback is needed (unlike Windows' non-atomic rename).
    if (std::rename(tmpPath.c_str(), path.c_str()) != 0) {
        spdlog::error("SaveWorld: rename '{}' -> '{}' failed: {}", tmpPath, path, std::strerror(errno));
        std::remove(tmpPath.c_str());
        return false;
    }
#endif

    spdlog::info("SaveWorld: Saved {} entities to '{}'", entities.size(), path);
    return true;
}

bool LoadWorldFromFile(const std::string& path,
                       std::unordered_map<EntityID, ServerEntity>& entities,
                       std::unordered_map<std::string, SavedPlayer>& savedPlayers,
                       float& timeOfDay, int& weatherState,
                       EntityID& nextEntityId) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    try {
        json j;
        file >> j;

        timeOfDay = j.value("timeOfDay", 0.5f);
        weatherState = j.value("weather", 0);

        entities.clear();
        savedPlayers.clear();
        EntityID maxId = 0;

        int loadedCount = 0;
        int skippedBadPos = 0;
        for (auto& e : j["entities"]) {
            if (loadedCount >= KMP_MAX_SYNC_ENTITIES) {
                spdlog::warn("LoadWorld: Entity cap reached ({} max), skipping remaining",
                             KMP_MAX_SYNC_ENTITIES);
                break;
            }
            ServerEntity entity;
            entity.id = e["id"];
            entity.type = static_cast<EntityType>(e["type"].get<int>());
            entity.owner = 0; // Mark all loaded entities as unowned until a player reconnects
            entity.templateId = e["templateId"];
            entity.factionId = e["factionId"];

            auto& pos = e["position"];
            entity.position = Vec3(pos[0], pos[1], pos[2]);

            // Validate position — skip entities with NaN, inf, or extreme coordinates
            if (std::isnan(entity.position.x) || std::isnan(entity.position.y) || std::isnan(entity.position.z) ||
                std::isinf(entity.position.x) || std::isinf(entity.position.y) || std::isinf(entity.position.z) ||
                std::abs(entity.position.x) > 1000000.f || std::abs(entity.position.y) > 1000000.f ||
                std::abs(entity.position.z) > 1000000.f) {
                skippedBadPos++;
                spdlog::warn("LoadWorld: Skipping entity {} — bad position ({:.1f}, {:.1f}, {:.1f})",
                             entity.id, entity.position.x, entity.position.y, entity.position.z);
                // Still track max ID to prevent collisions
                if (entity.id > maxId) maxId = entity.id;
                continue;
            }

            auto& rot = e["rotation"];
            entity.rotation = Quat(rot[0], rot[1], rot[2], rot[3]);

            entity.zone = ZoneCoord::FromWorldPos(entity.position);
            entity.alive = e.value("alive", true);

            // Defensive: a NaN/Inf health serializes as JSON null, and a raw
            // `entity.health[i] = health[i]` would throw type_error::302 → the
            // catch below would wipe the entire saved world (I-10). Skip any
            // non-finite/non-number value and keep the 100.f default instead.
            if (e.contains("health") && e["health"].is_array()) {
                auto& health = e["health"];
                for (int i = 0; i < 7 && i < static_cast<int>(health.size()); i++) {
                    if (health[i].is_number()) {
                        float h = health[i].get<float>();
                        if (std::isfinite(h)) entity.health[i] = h;
                    }
                }
            }

            entity.templateName = e.value("templateName", std::string{});

            if (e.contains("equipment")) {
                auto& equip = e["equipment"];
                for (int i = 0; i < 14 && i < static_cast<int>(equip.size()); i++) {
                    entity.equipment[i] = equip[i];
                }
            }

            entities[entity.id] = entity;
            if (entity.id > maxId) maxId = entity.id;
            loadedCount++;
        }

        // Load player→entity mapping (version 2+)
        if (j.contains("players") && j["players"].is_object()) {
            for (auto& [token, ids] : j["players"].items()) {
                if (!ids.is_array()) continue;
                SavedPlayer sp;
                sp.token = token;   // v3 key is the secret session token
                for (auto& eid : ids) {
                    if (!eid.is_number_unsigned()) continue;
                    EntityID id = eid.get<EntityID>();
                    // Only keep references to entities that actually loaded
                    if (entities.count(id)) sp.entityIds.push_back(id);
                }
                if (!sp.entityIds.empty()) {
                    savedPlayers[token] = std::move(sp);
                }
            }
            spdlog::info("LoadWorld: Loaded {} saved player records", savedPlayers.size());
        }

        nextEntityId = maxId + 1;
        if (skippedBadPos > 0) {
            spdlog::warn("LoadWorld: Skipped {} entities with bad positions", skippedBadPos);
        }
        spdlog::info("LoadWorld: Loaded {} valid entities from '{}'", entities.size(), path);
        return true;
    } catch (const std::exception& ex) {
        spdlog::error("LoadWorld: Failed to parse '{}': {}", path, ex.what());
        return false;
    }
}

} // namespace kmp
