#include "kmp/config.h"
#include "kmp/constants.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <algorithm>

#ifdef _WIN32
#include <shlobj.h>
#else
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace kmp {

using json = nlohmann::json;

// ── Validation helpers ──

template<typename T>
static T Clamp(T value, T lo, T hi) {
    return (std::max)(lo, (std::min)(value, hi));
}

// ── ClientConfig ──

std::string ClientConfig::GetDefaultPath() {
#ifdef _WIN32
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        std::string dir = std::string(path) + "\\KenshiMP";
        CreateDirectoryA(dir.c_str(), nullptr);
        return dir + "\\client.json";
    }
    return "client.json";
#else
    const char* home = std::getenv("HOME");
    if (home) {
        std::string dir = std::string(home) + "/.config/KenshiMP";
        mkdir(dir.c_str(), 0755);
        return dir + "/client.json";
    }
    return "client.json";
#endif
}

std::string ClientConfig::GetInstancePath() {
    // PID-specific config path so multiple game instances don't collide.
    // Each Kenshi process gets its own config file for saving state.
#ifdef _WIN32
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        std::string dir = std::string(path) + "\\KenshiMP";
        CreateDirectoryA(dir.c_str(), nullptr);
        DWORD pid = GetCurrentProcessId();
        return dir + "\\client_" + std::to_string(pid) + ".json";
    }
    return "client.json";
#else
    const char* home = std::getenv("HOME");
    if (home) {
        std::string dir = std::string(home) + "/.config/KenshiMP";
        mkdir(dir.c_str(), 0755);
        return dir + "/client_" + std::to_string(getpid()) + ".json";
    }
    return "client.json";
#endif
}

bool ClientConfig::Load(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    try {
        json j;
        file >> j;
        if (j.contains("playerName"))  playerName  = j["playerName"].get<std::string>();
        if (j.contains("lastServer"))  lastServer  = j["lastServer"].get<std::string>();
        if (j.contains("lastPort"))    lastPort    = j["lastPort"].get<uint16_t>();
        if (j.contains("autoConnect")) autoConnect = j["autoConnect"].get<bool>();
        if (j.contains("overlayScale")) overlayScale = j["overlayScale"].get<float>();
        if (j.contains("favoriteServers")) {
            favoriteServers = j["favoriteServers"].get<std::vector<std::string>>();
        }
        if (j.contains("masterServer")) masterServer = j["masterServer"].get<std::string>();
        if (j.contains("masterPort"))   masterPort   = j["masterPort"].get<uint16_t>();
        if (j.contains("useSyncOrchestrator")) useSyncOrchestrator = j["useSyncOrchestrator"].get<bool>();
        if (j.contains("serverPassword")) serverPassword = j["serverPassword"].get<std::string>();
        if (j.contains("hostToken"))      hostToken      = j["hostToken"].get<std::string>();
        if (j.contains("sessionTokens") && j["sessionTokens"].is_object()) {
            for (auto& [k, v] : j["sessionTokens"].items()) {
                if (v.is_string()) sessionTokens[k] = v.get<std::string>();
            }
        }

        // ── Validate loaded values ──
        if (playerName.size() > KMP_MAX_NAME_LENGTH)
            playerName.resize(KMP_MAX_NAME_LENGTH);
        lastPort    = Clamp<uint16_t>(lastPort, 1024, 65535);
        overlayScale = Clamp(overlayScale, 0.1f, 10.0f);
        masterPort  = Clamp<uint16_t>(masterPort, 1024, 65535);

        return true;
    } catch (...) {
        return false;
    }
}

bool ClientConfig::Save(const std::string& path) const {
    json j;
    j["playerName"]  = playerName;
    j["lastServer"]  = lastServer;
    j["lastPort"]    = lastPort;
    j["autoConnect"] = autoConnect;
    j["overlayScale"] = overlayScale;
    j["favoriteServers"] = favoriteServers;
    j["masterServer"] = masterServer;
    j["masterPort"]   = masterPort;
    j["useSyncOrchestrator"] = useSyncOrchestrator;
    j["serverPassword"] = serverPassword;
    j["hostToken"]      = hostToken;
    j["sessionTokens"]  = sessionTokens;

    std::ofstream file(path);
    if (!file.is_open()) return false;
    file << j.dump(2);
    return true;
}

// ── ServerConfig ──

bool ServerConfig::Load(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    try {
        json j;
        file >> j;
        if (j.contains("serverName")) serverName = j["serverName"].get<std::string>();
        if (j.contains("port"))       port       = j["port"].get<uint16_t>();
        if (j.contains("maxPlayers")) maxPlayers = j["maxPlayers"].get<int>();
        if (j.contains("password"))   password   = j["password"].get<std::string>();
        if (j.contains("hostToken"))  hostToken  = j["hostToken"].get<std::string>();
        if (j.contains("savePath"))   savePath   = j["savePath"].get<std::string>();
        if (j.contains("tickRate"))   tickRate   = j["tickRate"].get<int>();
        if (j.contains("pvpEnabled")) pvpEnabled = j["pvpEnabled"].get<bool>();
        if (j.contains("gameSpeed"))  gameSpeed  = j["gameSpeed"].get<float>();
        if (j.contains("masterServer")) masterServer = j["masterServer"].get<std::string>();
        if (j.contains("masterPort"))   masterPort   = j["masterPort"].get<uint16_t>();

        // ── Validate loaded values ──
        port        = Clamp<uint16_t>(port, 1024, 65535);
        maxPlayers  = Clamp(maxPlayers, 1, KMP_MAX_PLAYERS);
        tickRate    = Clamp(tickRate, 1, 60);
        gameSpeed   = Clamp(gameSpeed, 0.1f, 10.0f);
        masterPort  = Clamp<uint16_t>(masterPort, 1024, 65535);
        if (serverName.size() > KMP_MAX_NAME_LENGTH)
            serverName.resize(KMP_MAX_NAME_LENGTH);

        return true;
    } catch (...) {
        return false;
    }
}

bool ServerConfig::Save(const std::string& path) const {
    json j;
    j["serverName"] = serverName;
    j["port"]       = port;
    j["maxPlayers"] = maxPlayers;
    j["password"]   = password;
    j["hostToken"]  = hostToken;
    j["savePath"]   = savePath;
    j["tickRate"]   = tickRate;
    j["pvpEnabled"] = pvpEnabled;
    j["gameSpeed"]  = gameSpeed;
    j["masterServer"] = masterServer;
    j["masterPort"]   = masterPort;

    std::ofstream file(path);
    if (!file.is_open()) return false;
    file << j.dump(2);
    return true;
}

} // namespace kmp
