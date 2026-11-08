# Sniffer réseau — C + V + assembleur x86-64

Sniffer de paquets pour **Windows** (Npcap) et **Linux** (libpcap), avec noyau C
multi-plateforme, routines d'analyse en assembleur x86-64, et plusieurs interfaces
(console, TUI ANSI, GUI Win32 native, GUI expérimentale en V).

- **Noyau C** : chargement dynamique de `wpcap.dll` / `libpcap.so`, capture sur thread
  dédié, file circulaire de paquets, statistiques, agrégation hôtes/flux
- **Assembleur x86-64** : inversion d'octets (`sniffer_bswap16`) et accumulation de
  checksum (`sniffer_fold_checksum`), avec repli C si l'architecture n'est pas x86-64
- **CLI C** : affichage console simple
- **TUI ANSI** : interface terminal couleur (Windows VT et Linux)
- **GUI Win32** : thème sombre, arborescence des applications, IP actives, connexions,
  paquets en direct, dump hexadécimal, icône de notification, filtre IP
- **GUI V** : variante en langage V via le module `gg` (optionnelle)

## Fonctionnalités

### Capture
- Énumération des interfaces réseau (`pcap_findalldevs`)
- Sélection automatique de l'interface la plus pertinente (Ethernet / Wi-Fi)
- Capture sur thread séparé, file circulaire de **4096 paquets**
- Compteurs : paquets capturés, octets, paquets perdus, état de capture
- Filtre BPF prévu dans l'API (`sniffer_start(device, bpf_filter)`)

### Analyse des paquets
- Couche 2/3 : Ethernet, ARP, IPv4, IPv6
- Couche 4 : ICMP, TCP (flags SYN/ACK/FIN/RST/PSH), UDP
- Décodage applicatif :
  - **DNS** (requête/réponse + nom de domaine)
  - **DHCP** (DISCOVER / OFFER / REQUEST / ACK, yiaddr)
  - **HTTP** (en-tête `Host:`)
  - **TLS/HTTPS**, **SMB**, **SSDP/UPnP**, **NBNS/NetBIOS**
  - Détection **jeux en ligne** (Steam, Minecraft, Unreal/GTA…) et **consoles**
    (Xbox Live, PSN, STUN, IPsec, Teredo…)
- Agrégation en mémoire :
  - jusqu'à **512 hôtes** (IP, MAC, alias, octets émis/reçus, dernier paquet)
  - jusqu'à **2048 flux** (IP:port ↔ IP:port, protocole, trafic, paquets, indice)
- Sur Windows : corrélation avec les **processus** et leurs connexions locales
  (filtre par exécutable)

## Prérequis

### Windows
1. [Npcap](https://npcap.com/) installé (mode « WinPcap API compatible » recommandé)
2. **GCC / MinGW** (`gcc`, `ar`) dans le `PATH`
3. Droits **administrateur** pour capturer

### Linux
1. `libpcap` : `sudo apt install libpcap0.8 libpcap-dev`
2. `gcc`, `make`, `pthread`
3. `sudo` pour ouvrir une interface en capture

> Le projet détecte automatiquement la plateforme. Sous Linux x86-64, la variante
> assembleur `asm/sniffer_x86_linux.S` est utilisée ; sinon `core/sniffer_asm_port.c`
> (implémentation C) prend le relais.

## Compilation

> **Sous Windows**, utilisez **PowerShell** (pas de `sudo`, `apt`, ni de chemin sans
> `.exe`). Fermez la fenêtre Sniffer avant de reconstruire la GUI.

### Windows (PowerShell) — recommandé

```powershell
cd sniffer
.\build.ps1
```

Le script compile le noyau, la CLI, la GUI Win32 et la TUI, puis tente la GUI V si
`v.exe` est disponible.

Équivalent avec `make` (MinGW/MSYS) :

```powershell
make all
```

### Linux

```sh
sudo apt install libpcap-dev build-essential
make all
chmod +x run_gui.sh
```

### Nettoyage

```powershell
make clean      # ou : Remove-Item -Recurse -Force build
```

## Binaires produits

| Fichier | Plateforme | Description |
|---------|------------|-------------|
| `build/sniffer_gui.exe` | Windows | Fenêtre Win32 (listes + hex + tray) |
| `build/sniffer_tui[.exe]` | Windows + Linux | Interface terminal couleur |
| `build/sniffer_cli[.exe]` | Windows + Linux | Console |
| `build/sniffer_gui_v.exe` | Windows | Variante V/gg (si `v` est à jour) |
| `build/libsniffer_core.a` | Toutes | Bibliothèque statique du noyau |

## Utilisation

### GUI Windows

```powershell
.\run_gui.ps1
```

Le script relance l'exécutable avec élévation (UAC) si nécessaire. Sinon, lancez
directement `build\sniffer_gui.exe` **en administrateur**, choisissez une interface puis
cliquez sur **Démarrer**.

### TUI (Windows / Linux)

```powershell
.\build\sniffer_tui.exe
```

```sh
./run_gui.sh      # relance avec sudo si besoin (Linux)
```

Touches : **S** démarrer, **X** arrêter, **flèches** changer d'interface, **Q** quitter.

### CLI

Windows — exemple avec une interface Npcap :

```powershell
.\build\sniffer_cli.exe -l
.\build\sniffer_cli.exe "\Device\NPF_{A0C021C3-0051-4EDC-AB86-C7DC2C27E045}"
```

Linux :

```sh
./build/sniffer_cli -l
sudo ./build/sniffer_cli eth0
```

Sans argument, la CLI liste les interfaces puis capture sur la première. `Ctrl+C` arrête.

## Architecture

```
                       ┌──────────────────────────────┐
   Npcap / libpcap ───►│ sniffer_wpcap.c (dlopen)     │
                       └──────────────┬───────────────┘
                                      │ paquets bruts
                                      ▼
                       ┌──────────────────────────────┐
                       │ sniffer_core.c               │
                       │  thread capture + ring 4096  │
                       └──────────────┬───────────────┘
                                      │ sniffer_packet_t
                                      ▼
                       ┌──────────────────────────────┐
                       │ sniffer_parse.c              │  ← asm (bswap/checksum)
                       │  Ethernet/ARP/IP/TCP/UDP ... │
                       └──────────────┬───────────────┘
                                      │
                                      ▼
                       ┌──────────────────────────────┐
                       │ sniffer_insight.c            │  hôtes + flux
                       │ sniffer_winproc.c (Windows)  │  processus/connexions
                       └──────────────┬───────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              ▼                       ▼                       ▼
          CLI (cli/)            TUI (gui_tui/)          GUI (gui_c/, gui/)
```

### Arborescence

```
core/       API et logique de capture (wpcap, parsing, insight, winproc)
asm/        Routines x86-64 (GAS, Intel syntax) — Windows et Linux
cli/        Programme console
gui_tui/    Interface terminal ANSI
gui_c/      GUI Win32 native (thème sombre, listes, hex)
gui/        Application V (module gg, optionnelle)
image/      Ressources (logo)
build/      Sortie de compilation
```

## API du noyau

Déclarations dans `core/sniffer_core.h` :

```c
int  sniffer_init(void);
void sniffer_shutdown(void);

int  sniffer_device_count(void);
int  sniffer_device_get(int index, char *name, size_t name_len,
                        char *desc, size_t desc_len);
int  sniffer_device_default_index(void);

int  sniffer_start(const char *device, const char *bpf_filter);
int  sniffer_stop(void);

int  sniffer_poll(sniffer_packet_t *out);   // 1 = paquet dispo, 0 = vide
void sniffer_stats(sniffer_stats_t *out);

const char *sniffer_proto_name(sniffer_proto_t p);
```

Agrégation (`core/sniffer_insight.h`) : `sniffer_insight_host_count/get`,
`sniffer_insight_flow_count/get`, `sniffer_category_name`.

Le noyau est utilisable en bibliothèque statique (`-DSNIFFER_STATIC`) ou exportable en
DLL (`-DSNIFFER_BUILD_DLL`).

## Notes

- Le filtre BPF est réservé pour une évolution : `sniffer_start` accepte déjà le
  paramètre `bpf_filter`, actuellement ignoré.
- Sans Npcap (Windows) ou libpcap (Linux), l'initialisation échoue avec un message
  explicite affiché dans l'interface.
- La GUI V (`gui/main.v`) nécessite un compilateur `v` synchronisé avec `vlib` ;
  `build.ps1` l'ignore proprement si la compilation échoue.
- La capture nécessite les droits administrateur (Windows) ou `root` (Linux).

## Licence

Distribué sous licence **MIT** — voir [LICENSE](LICENSE).
