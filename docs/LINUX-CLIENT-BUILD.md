# Building the Windows client (`KenshiMP.Core.dll`) on Linux

The client DLL injected into Kenshi is a **Windows x64 PE**, but you do **not** need a
Windows machine or Wine to build it. Wine *runs* `.exe`s; it does not compile. We
cross-compile with **clang-cl + lld-link** (LLVM's MSVC-compatible driver, so the output
is MSVC-ABI and binary-compatible with the game) against the Microsoft CRT + Windows SDK
fetched by **xwin**.

> Why not MinGW? MinGW uses a different C++ ABI — calling the game's MSVC-compiled C++
> methods / matching its vtable & container layouts would break. clang-cl targets the
> MSVC ABI, so it interops correctly.
>
> The Core has **no dependency on the Ogre/MyGUI SDK**: `ui/mygui_bridge.cpp` resolves
> MyGUI functions from `MyGUIEngine_x64.dll` at runtime via `GetProcAddress`. The only
> external headers are `<Windows.h>` and `<d3d11.h>` (Windows SDK).

## Prerequisites (Arch)

```sh
sudo pacman -S --needed clang lld cmake ninja   # clang-cl, lld-link, llvm-lib/mt/rc
cargo install xwin                               # MSVC SDK fetcher (needs rustup/cargo)
```

## 1. Fetch the MSVC CRT + Windows SDK (once, ~82 MiB download → ~640 MiB on disk)

Keep the cache **and** output on the same filesystem (xwin moves files with `rename()`,
which fails cross-device):

```sh
xwin --accept-license --arch x86_64 --cache-dir "$HOME/.xwin-cache" splat --output "$HOME/.xwin"
```

## 2. Configure + build

```sh
cmake -S . -B build-win -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-win-clangcl.cmake \
  -DCMAKE_BUILD_TYPE=Release          # add -DXWIN_DIR=/path if not ~/.xwin

cmake --build build-win --target KenshiMP.Core
# → build-win/bin/KenshiMP.Core.dll  (PE32+ x86-64 DLL; exports dllStartPlugin/dllStopPlugin)
```

Other Windows targets build the same way: `--target KenshiMP.Injector`, `KenshiMP.Scanner`,
`KenshiMP.TestClient`, `KenshiMP.IntegrationTest`.

## 3. Deploy + run (under Proton)

Replace the prebuilt artifact and let Kenshi load it as an Ogre plugin:

```sh
cp build-win/bin/KenshiMP.Core.dll /path/to/Kenshi/KenshiMP.Core.dll   # or dist/
```

Then launch Kenshi via Steam/Proton as usual (see `docs/LINUX-CLIENT-PROTON.md`).

> **Protocol v2:** after the server-hardening change the wire format is v2 — an old
> prebuilt client DLL will be rejected with a version mismatch. Rebuild as above so the
> client speaks v2 (sends password / host-token / session-token; persists the per-server
> session token in `client.json`).

## Notes

- Only the **Release** runtime libs are fetched (`/MD`); the toolchain forces
  `CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL` so CMake's default Debug CRT (`msvcrtd.lib`,
  not shipped by xwin) is never requested.
- Build was verified clean (97/97 objects, 0 errors; 3 benign deprecated-winsock warnings
  in vendored `lib/enet/win32.c`). Runtime behavior is only verifiable in-game under Proton.
