# Paperlike 13K 2025 Color — Linux Init Script

Open-source Linux init script for the DASUNG Paperlike 13K 2025 color e-ink display.
Replaces the proprietary PaperLikeClient app with a standalone Python script.

## Requirements

- Python 3 + pyserial (`pip install pyserial`)
- ch341 kernel module (usually loaded automatically)

## Setup

```bash
pip install pyserial
sudo usermod -aG dialout $USER   # allow serial port access
# Log out and back in for group change to take effect
```

## Usage

```bash
# Init and keep display alive (recommended):
python3 paperlike_init_linux.py --daemon

# Single-shot init (display will deactivate without keepalive):
python3 paperlike_init_linux.py

# Adjust display settings (can combine multiple):
python3 paperlike_init_linux.py --mode 3              # Display mode 1-6
python3 paperlike_init_linux.py --brightness 32        # Brightness 0-64
python3 paperlike_init_linux.py --speed 5              # Speed 1-8
python3 paperlike_init_linux.py --temperature 3        # Color temperature 0-5
python3 paperlike_init_linux.py --front-light 1        # Front light (0=off, 1=warm, 2=cold)
python3 paperlike_init_linux.py --dither off            # MCU dithering (on/off)
python3 paperlike_init_linux.py --refresh              # Force full refresh
python3 paperlike_init_linux.py --query                # Query device info
python3 paperlike_init_linux.py --mode 3 --brightness 32 --daemon  # Combine
python3 paperlike_init_linux.py --send 0x02 0x03       # Send raw command
```

### Display modes

| Mode | Name    |
|------|---------|
| 1    | Fast    |
| 2    | Fast+   |
| 3    | Balance |
| 4    | Text    |
| 5    | Text+   |
| 6    | Read    |

### Daemon control socket

When the daemon is running, commands from other instances are automatically
forwarded via a Unix socket (`$XDG_RUNTIME_DIR/paperlike.sock`). No need to
stop the daemon to change settings:

```bash
python3 paperlike_init_linux.py --daemon &      # start daemon
python3 paperlike_init_linux.py --brightness 50  # forwarded to daemon
python3 paperlike_init_linux.py --mode 1         # forwarded to daemon
python3 paperlike_init_linux.py --query           # forwarded to daemon
```

### Disconnect/reconnect

In daemon mode, the script handles USB disconnect and reconnect automatically.
When the display is unplugged, it waits for the device to reappear (the serial
port path may change, e.g. `ttyUSB2` -> `ttyUSB3`) and re-runs the full init.

### systemd service (auto-start on boot)

```ini
# /etc/systemd/system/paperlike.service
[Unit]
Description=Paperlike 13K Display Init
After=multi-user.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /path/to/paperlike_init_linux.py --daemon
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now paperlike.service
```

## Hardware

- **Display**: Paperlike 13K 2025 Color, 3200x2400 @ 37Hz
- **Connection**: USB-C (DisplayPort Alt Mode + USB data)
- **Control**: CH340 serial (VID:PID 0x1a86:0x7523) at 115200 8N1

## Serial protocol

24 ASCII hex characters, **UPPERCASE** (MCU is case-sensitive):

```
5FF5 CC OO PPPPPPPPPPPP A0FA
     |  |  |            └ trailer
     |  |  └ payload (6 bytes, usually zeros)
     |  └ option byte
     └ command byte
```

### Commands

| CMD  | OPT   | Description |
|------|-------|-------------|
| 0x01 | 1-8   | Set speed/threshold |
| 0x02 | 1-6   | Set display mode |
| 0x03 | 1     | Force refresh |
| 0x07 | 0-2   | Set front light mode (0=off, 1=warm, 2=cold) |
| 0x08 | 0-5   | Set color temperature |
| 0x09 | 0-64  | Set brightness |
| 0x0A | *     | Query (opt selects parameter) |
| 0x20 | 0/1   | Dithering control (0=enable/deactivate, 1=disable/activate) |

The display stays active only with periodic `0x20 0x01` commands (~10s interval).
On shutdown, send `0x20 0x00` to deactivate cleanly.
