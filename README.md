# SpotAlpine

Backend binario SP para Alpine Linux.  
Un solo archivo Python, sin dependencias. Protocolo binario sobre TCP.

```
Spot (Rust/egui) ── TCP :1801 ──► spot-server.py (Alpine)
```

## Instalar

```bash
apk add python3
wget https://raw.githubusercontent.com/avisonofgod/SpotAlpine/main/spot-server.py
python3 spot-server.py
```

O con script incluido:

```bash
chmod +x install.sh
./install.sh
```

## Usar

```bash
python3 spot-server.py --port 1801 --bind 0.0.0.0
```

## Servicio OpenRC

```bash
rc-service spot-server start
rc-service spot-server stop
rc-update add spot-server default
```

## Archivos

```
SpotAlpine/
├── spot-server.py   → Backend binario (224 líneas)
├── install.sh       → Instalación en Alpine
└── README.md
```
