# Kenshi-Online dedicated server — Linux container
# Multi-stage: compile from the audited source, then ship a slim runtime.
# (We rebuild from source rather than trusting any prebuilt binary.)

# ---- Build stage ----
FROM debian:bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Only the cross-platform server-side targets are built on Linux.
# The if(WIN32) guards in CMake exclude MinHook and all client projects.
RUN cmake -B build-docker -G Ninja -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build-docker --target KenshiMP.Server KenshiMP.MasterServer

# ---- Runtime stage ----
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        libstdc++6 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/build-docker/bin/KenshiMP.Server       /opt/kenshi/KenshiMP.Server
COPY --from=build /src/build-docker/bin/KenshiMP.MasterServer /opt/kenshi/KenshiMP.MasterServer

# Run as a non-root user (I-23): the server needs no privileges, so a container
# escape shouldn't land on root. The data dir is owned by this user so the
# server can still write server.json / world.kmpsave / logs to the mounted volume.
RUN useradd --system --uid 10001 --create-home --home-dir /home/kenshi kenshi \
    && mkdir -p /data && chown -R kenshi:kenshi /data /opt/kenshi
USER kenshi

# Config (server.json), world save (world.kmpsave) and logs live here.
# Mount a volume on /data to persist them across container restarts.
WORKDIR /data

EXPOSE 27800/udp

# server.json is read from the working dir (/data). If absent on first run,
# the server writes a default one there automatically.
ENTRYPOINT ["/opt/kenshi/KenshiMP.Server"]
CMD ["server.json"]
