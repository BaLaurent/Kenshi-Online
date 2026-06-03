# Héberger le serveur Kenshi-Online sur Linux

Ce guide explique comment faire tourner le **serveur dédié** Kenshi-Online sur Linux
(testé sur Arch Linux, gcc 16, et en conteneur Debian bookworm gcc 12). Tes amis se
connectent depuis un client **Windows** par **connexion directe IP**.

> **Ce qui tourne sur Linux** : `KenshiMP.Server` (serveur dédié) et `KenshiMP.MasterServer`
> (annuaire de serveurs, optionnel). **Ce qui reste Windows** : tout le client de jeu
> (`KenshiMP.Core.dll`, l'injecteur), car il s'injecte dans `kenshi_x64.exe`. Pour jouer
> toi-même depuis Linux via Proton, voir [LINUX-CLIENT-PROTON.md](LINUX-CLIENT-PROTON.md).

---

## Option 1 — Docker (recommandé)

Tout est déjà câblé. Depuis la racine du dépôt :

```bash
docker compose up -d --build      # construit l'image et lance le serveur
docker compose logs -f            # suit les logs en direct
docker compose down               # arrête le serveur
```

- Le port **27800/udp** est publié sur l'hôte.
- `server.json`, la sauvegarde du monde (`world.kmpsave`) et le log persistent dans
  `./server-data/` sur l'hôte (volume monté). Édite `./server-data/server.json` puis
  `docker compose restart` pour changer la config.

> Note : par défaut le conteneur tourne en `root`, donc les fichiers du volume
> appartiennent à `root`. Pour un desktop perso c'est sans conséquence.

## Option 2 — Build natif (sans Docker)

```bash
cmake -B build-linux -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux --target KenshiMP.Server
cd build-linux/bin
./KenshiMP.Server              # lit/crée server.json dans le dossier courant
```

Dépendances : `cmake`, un compilateur C++17 (`gcc`/`clang`), `ninja` (ou `make`). Les
bibliothèques tierces (ENet, spdlog, nlohmann/json) sont déjà incluses dans `lib/`.

---

## Configuration (`server.json`)

```json
{
  "serverName": "KenshiMP Server",
  "port": 27800,
  "maxPlayers": 16,
  "password": "",
  "pvpEnabled": true,
  "gameSpeed": 1.0,
  "tickRate": 20,
  "savePath": "world.kmpsave",
  "masterServer": "162.248.94.149",
  "masterPort": 27801
}
```

- **Connexion directe pure** : tu peux vider `"masterServer": ""` pour ne pas t'enregistrer
  sur l'annuaire public du mod. Tes amis se connectent alors uniquement par ton IP.
- `password` : laisse vide pour un serveur ouvert, ou mets un mot de passe partagé.

---

## Réseau : Tailscale (le plus simple)

Le serveur écoute en **UDP 27800**. Avec Tailscale, pas besoin de toucher à ta box
ni d'ouvrir de port sur Internet.

1. **Sur l'hôte Arch** (pas dans le conteneur) :
   ```bash
   sudo tailscale up
   tailscale ip -4        # affiche ton IP tailnet, du genre 100.x.y.z
   ```
2. **Partage le nœud** avec tes amis (ils n'ont pas besoin de rejoindre tout ton tailnet) :
   - Console admin Tailscale → ta machine → **Share** → génère le lien d'invitation, OU
   - `tailscale share` selon ta version.
3. **Tes amis** installent Tailscale, acceptent le partage, puis dans Kenshi-Online :
   ```
   /connect 100.x.y.z 27800
   ```

> ⚠️ **Le Tailscale Funnel ne marche PAS pour ce jeu.** Le Funnel ne transporte que du
> **TCP/HTTPS** (ports 443/8443/10000) ; Kenshi-Online est en **UDP**. C'est une
> limitation de Tailscale, pas du mod. Utilise le **partage de nœud** ci-dessus, qui lui
> transporte bien l'UDP en peer-to-peer.

## Réseau : sans Tailscale (port forwarding classique)

Si tu préfères exposer le serveur directement :

1. Ouvre **27800/udp** dans ton pare-feu local :
   ```bash
   # ufw
   sudo ufw allow 27800/udp
   # ou iptables
   sudo iptables -A INPUT -p udp --dport 27800 -j ACCEPT
   ```
2. Redirige **27800/udp** depuis ta box vers l'IP locale de la machine.
3. Tes amis se connectent à `<ton-IP-publique> 27800`.

---

## Vérifier que ça marche

Depuis une autre machine (ou en local avec le client Windows via Wine — voir le guide
Proton), connecte-toi. Côté serveur, tu dois voir dans les logs :

```
GameServer: Incoming connection from <ip>:<port>
GameServer: Player '<nom>' joined (ID: 1, 1 players now)
```

La sauvegarde du monde s'écrit automatiquement toutes les 60 s et à l'arrêt propre
(`Ctrl-C` / `docker compose down`).
