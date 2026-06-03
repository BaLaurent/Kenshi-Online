# Jouer à Kenshi-Online depuis Linux via Proton

> ✅ **Injection sous Proton CONFIRMÉE** — ⚠️ **boucle co-op complète à valider en partie réelle.**
> Testé sur cette machine (Arch Linux, **Kenshi 1.0.68**, **Proton - Experimental** 11.0). Le
> client est un plugin Windows (`KenshiMP.Core.dll`) injecté dans `kenshi_x64.exe`. Il n'existe
> **pas** de client Linux natif (impossible : il dépend du SDK Ogre/MyGUI de Kenshi, Windows
> uniquement). On fait donc tourner Kenshi sous **Steam Proton** (Wine) et on y charge le DLL.
>
> **Ce qui est PROUVÉ, logs à l'appui** (`KenshiOnline_*.log` dans le dossier du jeu) :
> - Le plugin Ogre se charge, le **pattern scanner** résout la mémoire sous Wine (63 258 xrefs,
>   3 055 vtables RTTI, fonctions clés trouvées).
> - **MinHook installe les hooks sous Wine** (le maillon réputé incertain) : `[OK] MinHook ready`,
>   **12 hooks installés** (`DXGI_Present`, `CharacterCreate`, `CharacterDeath`, `CharacterKO`,
>   `ItemPickup`, `ItemDrop`, `SquadSpawnBypass`, `TimeUpdate`, `AICreate`, `AIPackages`,
>   `BuyItem`, `FactionRelation`), puis `=== Kenshi-Online Initialized Successfully ===`.
> - Côté protocole (indépendant de Proton) : suite d'intégration **70/70 sous Wine**, et un
>   client Windows joue une session complète contre le serveur **Linux** natif.
>
> **Ce qui N'EST PAS encore prouvé** : le log a été capturé **au menu principal**, donc la
> boucle multijoueur réelle (rejoindre, charger un monde, **voir un autre joueur se synchroniser**)
> n'a pas été exercée — il faut une partie pilotée à la main. À surveiller en particulier :
> - `PlayerBase ... reads garbage — clearing (Steam offset mismatch)` : le pointeur du joueur
>   local a été vidé au menu. C'est **probablement** normal (aucun monde chargé = globales pas
>   encore valides), mais ça pourrait aussi trahir un écart d'offsets de la build Steam. Ça se
>   tranche **seulement** en chargeant une partie.
> - `GameWorldSingleton` : non résolu par l'orchestrateur primaire, mais **récupéré** par le
>   mécanisme secondaire (`func-disasm via GameFrameUpdate`). À confirmer que le spawn/sync des
>   joueurs distants fonctionne réellement.
>
> **Conclusion honnête** : l'injection et le hooking marchent sous Proton ; la dernière étape
> (co-op qui synchronise pour de vrai depuis le client Linux) te revient à confirmer en jeu.

---

## Pourquoi ça a une vraie chance de marcher

Sous Proton/Wine x64, `kenshi_x64.exe` s'exécute en **code x64 natif** ; Wine ne traduit
que les appels d'API Win32. Les octets du binaire et son agencement mémoire sont donc
**identiques** à Windows — c'est précisément ce qui rend valides les *patterns* et *RVA*
codés en dur pour Kenshi v1.0.68. Wine implémente `VirtualProtect`, le SEH `__try/__except`
et `MultiByteToWideChar`, tous utilisés par le client. Le point non garanti est MinHook.

---

## Pré-requis

- Kenshi installé via **Steam** et lancé **au moins une fois en Proton** (pour générer le
  préfixe Wine). Force Proton si besoin : Steam → Kenshi → Propriétés → Compatibilité →
  *Forcer l'utilisation d'un outil de compatibilité Steam Play* → Proton (récent).
- Le serveur Kenshi-Online qui tourne (voir [LINUX-SERVER.md](LINUX-SERVER.md)).
- Les fichiers `dist/` du mod : `KenshiMP.Core.dll`, `kenshi-online.mod`, et les `.layout`.

### Repères de chemins (adapte si ta bibliothèque Steam est ailleurs)

```
GAME = ~/.steam/steam/steamapps/common/Kenshi               # dossier du jeu (kenshi_x64.exe)
PFX  = ~/.steam/steam/steamapps/compatdata/233860/pfx       # préfixe Proton de Kenshi (appid 233860)
APPDATA = $PFX/drive_c/users/steamuser/AppData/Roaming      # le %APPDATA% du préfixe
```

> Si Kenshi est installé sur une autre partition (comme ce dépôt, sur un disque « Games »),
> `GAME` est dans la bibliothèque Steam correspondante : cherche le dossier contenant
> `kenshi_x64.exe`.

---

## Installation manuelle (équivalent de l'injecteur Windows)

L'injecteur/`install.bat` Windows fait exactement ces opérations — on les reproduit à la main.

```bash
GAME=~/.steam/steam/steamapps/common/Kenshi
PFX=~/.steam/steam/steamapps/compatdata/233860/pfx
DIST=/run/media/octopusman/Games/Experiences/Kenshi-Online/dist

# 1. Le plugin client, à la racine du jeu (à côté de kenshi_x64.exe)
cp "$DIST/KenshiMP.Core.dll" "$GAME/"

# 2. Les layouts MyGUI (menu multi + HUD)
cp "$DIST"/*.layout "$GAME/data/gui/layout/"

# 3. Le mod (templates de personnages des joueurs distants)
cp "/run/media/octopusman/Games/Experiences/Kenshi-Online/kenshi-online.mod" "$GAME/data/"

# 4. Enregistrer le plugin Ogre — ajoute la ligne si absente
grep -qxF 'Plugin=KenshiMP.Core' "$GAME/Plugins_x64.cfg" \
  || echo 'Plugin=KenshiMP.Core' >> "$GAME/Plugins_x64.cfg"

# 5. Activer le mod dans la liste de chargement
grep -qxF 'kenshi-online.mod' "$GAME/data/__mods.list" 2>/dev/null \
  || echo 'kenshi-online.mod' >> "$GAME/data/__mods.list"
```

### Pointer le client vers ton serveur

Écris `client.json` dans le `%APPDATA%` **du préfixe** (c'est là que `KenshiMP.Core` le lit) :

```bash
mkdir -p "$PFX/drive_c/users/steamuser/AppData/Roaming/KenshiMP"
cat > "$PFX/drive_c/users/steamuser/AppData/Roaming/KenshiMP/client.json" <<'EOF'
{
  "playerName": "TonPseudo",
  "lastServer": "127.0.0.1",
  "lastPort": 27800,
  "masterServer": "162.248.94.149",
  "masterPort": 27801
}
EOF
```

- Serveur en **local** (Docker sur la même machine) : `127.0.0.1`.
- Serveur joint via **Tailscale** : mets ton IP tailnet `100.x.y.z`.
- Tu peux aussi te connecter en jeu via le chat : `/connect <ip> 27800`.

---

## Lancer et tester

1. Lance Kenshi normalement depuis Steam (il démarre sous Proton).
2. Au menu principal, le bouton **MULTIPLAYER** doit apparaître (chargé via le `.layout`).
   Clique **MULTIPLAYER** → **JOIN GAME** → entre l'IP et le port → **CONNECT** →
   **NEW GAME** (toujours *New Game*, jamais *Load*).
3. Côté serveur, tu dois voir dans les logs :
   ```
   GameServer: Incoming connection from <ip>:<port>
   GameServer: Player '<TonPseudo>' joined
   ```

Touches utiles : **F1** (menu multi), **Tab** (liste joueurs), **Entrée** (chat),
**Inser** (log de debug — précieux si ça plante).

---

## Dépannage spécifique Proton/Wine

| Symptôme | Piste |
|---|---|
| **Le bouton MULTIPLAYER n'apparaît pas** | Les `.layout` ne sont pas dans `data/gui/layout/`, ou le plugin n'est pas chargé. Vérifie `Plugins_x64.cfg` et que `KenshiMP.Core.dll` est à la racine du jeu. |
| **Kenshi crashe au démarrage** | Le plugin est chargé mais MinHook échoue peut-être à hooker sous Wine. Lance Kenshi depuis un terminal (`WINEDEBUG=+relay` trop verbeux ; vise les logs du mod) et regarde `KenshiOnline_CRASH.log` / `KenshiOnline_Server.log` dans le dossier du jeu. |
| **Erreur d'ouverture du breadcrumb** | Le chemin `C:\Program Files (x86)\Steam\...\KenshiOnline_BREADCRUMB.txt` est codé en dur et n'existe pas dans le préfixe → **échec silencieux et sans gravité**, ce n'est pas la cause d'un crash. |
| **Connecté mais « 0 players »** | La connexion se fait après le chargement du monde : clique bien **NEW GAME**. |
| **Joueurs distants invisibles** | Vérifie que `kenshi-online.mod` est actif (étape 5). Approche-toi d'une ville/camp NPC. |

### Si l'injection échoue chez toi (autre Proton / autre version de Kenshi)

L'injection MinHook est **confirmée fonctionnelle** avec Kenshi 1.0.68 + Proton Experimental.
Si tu changes de version de Proton ou de Kenshi et que ça casse :
- Reviens à **Proton - Experimental** (celui qui a initialisé le préfixe et avec lequel le
  test a réussi).
- Vérifie que Kenshi est bien en **1.0.68** (les patterns/RVA ciblent cette version).
- En dernier recours, le **serveur Linux reste pleinement fonctionnel** pour tes potes sous
  Windows — tu n'as rien cassé, et tu peux jouer depuis une machine/VM Windows en attendant.

---

## Note sécurité importante

Le `dist/KenshiMP.Core.dll` est un binaire **pré-compilé** (PE32+ x64, non packé — vérifié).
L'audit de sécurité porte sur le **code source**, pas sur la garantie octet-par-octet que ce
DLL correspond à cette source. Pour une assurance totale avant de l'injecter dans ton jeu,
**recompile-le depuis la source auditée sur une machine Windows** (MSVC + SDK Ogre/MyGUI de
Kenshi), ou demande à un pote Windows de le faire, plutôt que d'exécuter le binaire fourni.
