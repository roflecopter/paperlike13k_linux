#!/usr/bin/env python3
"""
Paperlike 13K 2025 Color Display - Linux Init Script

Sends the serial initialization sequence over CH340 USB-serial to activate
the e-ink display panel.

Protocol:
  - CH340 serial at 115200 8N1, no flow control, DTR=low, RTS=low
  - Packet format (24 ASCII hex chars, UPPERCASE):
    5FF5 + cmd(2hex) + opt(2hex) + 000000000000 + A0FA
  - Response format: same structure, cmd=F0 for status, cmd=F5 for heartbeat
  - CRITICAL: MCU requires uppercase hex. Lowercase is silently ignored.

Usage:
  pip install pyserial
  python3 paperlike_init_linux.py --daemon              # Keep alive (recommended)
  python3 paperlike_init_linux.py                       # Single-shot init
  python3 paperlike_init_linux.py --mode 3              # Display mode 1-6
  python3 paperlike_init_linux.py --brightness 32       # Brightness 0-64
  python3 paperlike_init_linux.py --mode 3 --brightness 32 --daemon  # Combine

  When a daemon is running, commands are forwarded to it automatically:
  python3 paperlike_init_linux.py --brightness 50       # Sent via daemon

Requires: ch341 kernel module (usually loaded automatically on Fedora)
"""

import sys
import time
import json
import serial
import serial.tools.list_ports
import subprocess
import glob
import os
import signal
import socket
import threading


# ─── Socket path ──────────────────────────────────────────────────────────────

SOCK_PATH = os.path.join(os.environ.get('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}'),
                         'paperlike.sock')


# ─── Protocol ────────────────────────────────────────────────────────────────

def make_packet(cmd, opt=0):
    """Build a 24-char UPPERCASE ASCII hex packet."""
    return f"{0x5FF5:04X}{cmd:02X}{opt:02X}{0:012X}{0xA0FA:04X}".encode('ascii')


def parse_packets(data):
    """Parse all protocol packets from raw bytes. Returns list of (cmd, opt, payload)."""
    if not data:
        return []
    text = data.decode('ascii', errors='replace').upper()
    packets = []
    pos = 0
    while pos <= len(text) - 24:
        idx = text.find('5FF5', pos)
        if idx == -1:
            break
        if idx + 24 <= len(text):
            pkt = text[idx:idx+24]
            if pkt[20:24] == 'A0FA':
                cmd = int(pkt[4:6], 16)
                opt = int(pkt[6:8], 16)
                payload = pkt[8:20]
                packets.append((cmd, opt, payload))
                pos = idx + 24
                continue
        pos = idx + 1
    return packets


# ─── Serial port ──────────────────────────────────────────────────────────────

def open_serial(port):
    """Open serial port with correct settings for Paperlike MCU."""
    ser = serial.Serial(
        port=port,
        baudrate=115200,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=0.5,
        rtscts=False,
        dsrdtr=False,
    )
    ser.dtr = False
    ser.rts = False
    ser.reset_input_buffer()
    time.sleep(0.3)
    return ser


def find_serial_port():
    """Find the CH340 serial port (PID 0x7523) for MCU control."""
    for p in serial.tools.list_ports.comports():
        if p.vid == 0x1a86 and p.pid == 0x7523:
            return p.device
    # Fallback: any WCH serial port
    for p in serial.tools.list_ports.comports():
        if p.vid == 0x1a86:
            return p.device
    # Fallback: glob
    candidates = glob.glob('/dev/ttyUSB*') + glob.glob('/dev/ttyACM*')
    return candidates[0] if candidates else None


# ─── Commands ─────────────────────────────────────────────────────────────────

def send_cmd(ser, cmd, opt=0, label="", wait=0.2):
    """Send a command and read response."""
    packet = make_packet(cmd, opt)
    ser.write(packet)
    ser.flush()
    time.sleep(wait)
    resp = ser.read(ser.in_waiting or 256)
    parsed = parse_packets(resp)

    # Filter heartbeats for display
    non_hb = [p for p in parsed if not (p[0] == 0xF5 and p[1] == 0x20)]
    if non_hb:
        for p in non_hb:
            print(f"  TX 0x{cmd:02X},0x{opt:02X} [{label:22s}] -> RESP 0x{p[0]:02X},0x{p[1]:02X} {p[2]}")
    else:
        status = "heartbeat" if parsed else "(none)"
        print(f"  TX 0x{cmd:02X},0x{opt:02X} [{label:22s}] -> {status}")

    return parsed


def query_device_info(ser):
    """Run the full query sequence."""
    info = {}
    queries = [
        (0x10, "MCU version"),
        (0x13, "Display version/modes"),
        (0x01, "Speed/threshold"),
        (0x02, "Display mode"),
        (0x07, "Front light mode"),
        (0x09, "Brightness"),
        (0x08, "Color temperature"),
    ]
    for opt, label in queries:
        wait = 0.4 if opt == 0x10 else 0.2
        pkts = send_cmd(ser, 0x0A, opt, f"Query {label}", wait=wait)
        for p in pkts:
            if p[0] == 0xF0:
                val = int(p[2][2:4], 16) if len(p[2]) >= 4 else 0
                info[label] = val
    return info


# ─── Display detection / dithering ────────────────────────────────────────────

def find_paperlike_connector():
    """Find DRM connector for the Paperlike display."""
    for edid_path in sorted(glob.glob('/sys/class/drm/card*-*/edid')):
        try:
            with open(edid_path, 'rb') as f:
                edid = f.read()
            if edid and (b'Paperlike' in edid or b'DASUNG' in edid):
                dirname = os.path.basename(os.path.dirname(edid_path))
                return dirname.split('-', 1)[1] if '-' in dirname else dirname
        except (IOError, PermissionError):
            continue
    return None


def try_disable_dithering(verbose=True):
    """Attempt to disable GPU dithering."""
    if verbose:
        print("\n--- Disable GPU dithering ---")
    connector = find_paperlike_connector()
    if connector and verbose:
        print(f"  Paperlike on connector: {connector}")
    if connector:
        for prop in ['dithering', 'Dithering', 'dither']:
            try:
                r = subprocess.run(['xrandr', '--output', connector, '--set', prop, 'off'],
                                   capture_output=True, text=True, timeout=5)
                if r.returncode == 0 and verbose:
                    print(f"  Disabled via xrandr --set {prop} off")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
    for p in glob.glob('/sys/kernel/debug/dri/*/amdgpu_dm_dither'):
        try:
            with open(p, 'w') as f:
                f.write('0')
            if verbose:
                print(f"  Disabled AMD dithering via {p}")
        except (PermissionError, IOError):
            pass


# ─── Control socket (daemon IPC) ─────────────────────────────────────────────

def daemon_is_running():
    """Check if a daemon is listening on the control socket."""
    if not os.path.exists(SOCK_PATH):
        return False
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(SOCK_PATH)
        s.close()
        return True
    except (ConnectionRefusedError, OSError):
        # Stale socket
        try:
            os.unlink(SOCK_PATH)
        except OSError:
            pass
        return False


def send_to_daemon(request):
    """Send a request to the running daemon. Returns response dict."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(SOCK_PATH)
    s.sendall(json.dumps(request).encode() + b'\n')
    # Read response
    buf = b''
    while b'\n' not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    s.close()
    return json.loads(buf.decode())


def start_control_socket(ser, serial_lock):
    """Start a background thread listening for control commands on a Unix socket."""
    try:
        os.unlink(SOCK_PATH)
    except OSError:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK_PATH)
    srv.listen(2)
    srv.settimeout(1)  # allow periodic check for shutdown

    def handle_client(conn):
        try:
            conn.settimeout(5)
            buf = b''
            while b'\n' not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            if not buf:
                return

            request = json.loads(buf.decode())
            results = []

            with serial_lock:
                if request.get('type') == 'query':
                    info = query_device_info(ser)
                    results = [{'info': info}]
                elif request.get('type') == 'commands':
                    for c in request['commands']:
                        cmd, opt, label = c['cmd'], c['opt'], c['label']
                        pkts = send_cmd(ser, cmd, opt, label)
                        results.append({
                            'cmd': cmd, 'opt': opt, 'label': label,
                            'response': [(p[0], p[1], p[2]) for p in pkts]
                        })

            conn.sendall(json.dumps({'ok': True, 'results': results}).encode() + b'\n')
        except Exception as e:
            try:
                conn.sendall(json.dumps({'ok': False, 'error': str(e)}).encode() + b'\n')
            except Exception:
                pass
        finally:
            conn.close()

    def listen_loop():
        while True:
            try:
                conn, _ = srv.accept()
                handle_client(conn)
            except socket.timeout:
                continue
            except OSError:
                break

    t = threading.Thread(target=listen_loop, daemon=True)
    t.start()
    return srv


# ─── Init ─────────────────────────────────────────────────────────────────────

def wait_for_heartbeat(ser, timeout=6):
    """Wait for MCU heartbeat. Returns True if received."""
    start = time.time()
    while time.time() - start < timeout:
        d = ser.read(256)
        if d:
            pkts = parse_packets(d)
            if any(p[0] == 0xF5 for p in pkts):
                return True
        time.sleep(0.05)
    return False


def activate_display(ser):
    """Run the init sequence: heartbeat, query, dithering, activate."""
    print("\n--- Waiting for heartbeat ---")
    if wait_for_heartbeat(ser):
        print("  Heartbeat received - MCU alive")
    else:
        print("  WARNING: No heartbeat (continuing anyway)")

    print("\n--- Query device info ---")
    info = query_device_info(ser)
    if info:
        print(f"  Got {len(info)} responses - serial TX confirmed working!")
    else:
        print("  No query responses")

    try_disable_dithering()

    print("\n--- Activate display ---")
    send_cmd(ser, 0x20, 0x01, "Dithering disable", wait=0.3)

    print("\n--- Monitoring (5s) ---")
    start = time.time()
    while time.time() - start < 5:
        d = ser.read(256)
        if d:
            pkts = parse_packets(d)
            for p in pkts:
                kind = "HB" if p[0] == 0xF5 else f"0x{p[0]:02X}"
                print(f"  [{time.time()-start:.1f}s] {kind} opt=0x{p[1]:02X}")
        time.sleep(0.05)

    print("\n--- Init complete ---")


def wait_for_device(fixed_port=None):
    """Wait for the Paperlike serial port to appear. Returns (port, serial).
    Re-scans for CH340 on each attempt since USB path can change on replug."""
    backoff = 1
    max_backoff = 15
    while True:
        port = fixed_port or find_serial_port()
        if port:
            try:
                ser = open_serial(port)
                ser.read(ser.in_waiting or 256)  # drain
                return port, ser
            except (serial.SerialException, OSError):
                pass
        time.sleep(backoff)
        backoff = min(backoff + 1, max_backoff)


def init_display(port, daemon=False, interval=10):
    """Run the full Paperlike 13K init sequence."""
    print(f"Paperlike 13K 2025 Color - Linux Init")
    print(f"Serial port: {port}")
    print("=" * 50)

    ser = open_serial(port)
    ser.read(ser.in_waiting or 256)  # drain

    activate_display(ser)

    if not daemon:
        print("TIP: Use --daemon to keep display active")
        ser.close()
        return

    # Daemon mode
    print(f"\nDaemon: refreshing every {interval}s (Ctrl+C to stop)")
    print(f"Control socket: {SOCK_PATH}")

    serial_lock = threading.Lock()
    ctrl_srv = start_control_socket(ser, serial_lock)

    def cleanup(signum, frame):
        print("\n\nShutting down...")
        try:
            with serial_lock:
                ser.write(make_packet(0x20, 0x00))
                ser.flush()
                print("  Sent deactivate")
        except Exception:
            pass
        try:
            ctrl_srv.close()
            os.unlink(SOCK_PATH)
        except Exception:
            pass
        try:
            ser.close()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    tick = 0
    while True:
        time.sleep(interval)
        tick += 1
        try:
            with serial_lock:
                ser.read(ser.in_waiting or 0)  # drain heartbeats
                ser.write(make_packet(0x20, 0x01))
                ser.flush()
            if tick % 6 == 0:
                try_disable_dithering(verbose=False)
            sys.stdout.write(f"\r  [{time.strftime('%H:%M:%S')}] tick {tick}   ")
            sys.stdout.flush()
        except (serial.SerialException, OSError) as e:
            print(f"\n  Disconnected: {e}")
            try:
                ctrl_srv.close()
            except Exception:
                pass
            try:
                ser.close()
            except Exception:
                pass

            # Wait for device to reappear (port path may change on replug)
            print("  Waiting for device...")
            new_port, ser = wait_for_device()
            port = new_port
            print(f"  Device back on {port} - re-initializing...")
            activate_display(ser)
            ctrl_srv = start_control_socket(ser, serial_lock)
            print(f"\nDaemon: resuming (Ctrl+C to stop)")
            tick = 0


# ─── Client: send commands via daemon or direct ──────────────────────────────

def build_commands(args):
    """Build list of (cmd, opt, label) from parsed args."""
    commands = []
    if args.mode is not None:
        commands.append((0x02, args.mode, f"Set mode {args.mode}"))
    if args.speed is not None:
        commands.append((0x01, args.speed, f"Set speed {args.speed}"))
    if args.brightness is not None:
        commands.append((0x09, args.brightness, f"Set brightness {args.brightness}"))
    if args.temperature is not None:
        commands.append((0x08, args.temperature, f"Set temperature {args.temperature}"))
    if args.front_light is not None:
        commands.append((0x07, args.front_light, f"Set front light {args.front_light}"))
    if args.dither is not None:
        val = 0 if args.dither == 'on' else 1
        commands.append((0x20, val, f"Dither {'on (enable)' if val == 0 else 'off (disable)'}"))
    if args.refresh:
        commands.append((0x03, 0x01, "Force refresh"))
    if args.send:
        for pair in args.send:
            cmd_val = int(pair[0], 0)
            opt_val = int(pair[1], 0)
            commands.append((cmd_val, opt_val, f"Raw 0x{cmd_val:02X} 0x{opt_val:02X}"))
    return commands


def run_via_daemon(commands=None, query=False):
    """Send commands to the running daemon via socket. Returns True on success."""
    try:
        if query:
            resp = send_to_daemon({'type': 'query'})
        else:
            req = {'type': 'commands', 'commands': [
                {'cmd': c[0], 'opt': c[1], 'label': c[2]} for c in commands
            ]}
            resp = send_to_daemon(req)

        if resp.get('ok'):
            print("  (sent via daemon)")
            return True
        else:
            print(f"  Daemon error: {resp.get('error')}")
            return False
    except (ConnectionRefusedError, OSError) as e:
        print(f"  Could not reach daemon: {e}")
        return False


def run_commands_direct(port, commands):
    """Send commands directly over serial (no daemon running)."""
    ser = open_serial(port)
    for cmd, opt, label in commands:
        send_cmd(ser, cmd, opt, label)
    ser.close()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description='Paperlike 13K 2025 Color - Linux Init',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s --daemon                          # Init + keep alive (recommended)
  %(prog)s                                   # Single-shot init
  %(prog)s --mode 3                          # Set display mode
  %(prog)s --brightness 32                   # Set brightness
  %(prog)s --mode 3 --brightness 32          # Set multiple at once
  %(prog)s --mode 3 --daemon                 # Set mode then keep alive
  %(prog)s --query                           # Query all device info
  %(prog)s --refresh                         # Force display refresh
  %(prog)s --dither off                      # Disable MCU dithering
  %(prog)s --front-light 1                   # Set front light mode
  %(prog)s --send 0x02 0x03                  # Send raw command
  %(prog)s --send 0x02 0x03 --send 0x09 0x20 # Multiple raw commands
  %(prog)s /dev/ttyUSB0 --daemon             # Specify port manually

display modes (--mode):
  1 = Fast     2 = Fast+     3 = Balance
  4 = Text     5 = Text+     6 = Read

daemon control:
  When a daemon is running, setting commands (--mode, --brightness, etc.)
  are automatically forwarded to it via a Unix socket. No need to stop
  the daemon first.

daemon reconnect:
  In --daemon mode, the script automatically handles USB disconnect/reconnect.
  When the display is unplugged, it waits for it to reappear (port path may
  change) and re-runs the full init sequence.
""")
    parser.add_argument('port', nargs='?', help='Serial port (default: auto-detect)')
    parser.add_argument('--daemon', action='store_true', help='Keep sending activation (recommended)')
    parser.add_argument('--interval', type=int, default=10, help='Daemon interval seconds (default: 10)')
    parser.add_argument('--mode', type=int, choices=range(1, 7), metavar='1-6',
                        help='Set display mode (1=Fast 2=Fast+ 3=Balance 4=Text 5=Text+ 6=Read)')
    parser.add_argument('--speed', type=int, choices=range(1, 9), metavar='1-8',
                        help='Set speed/threshold (1-8)')
    parser.add_argument('--brightness', type=int, choices=range(0, 65), metavar='0-64',
                        help='Set brightness (0-64)')
    parser.add_argument('--temperature', type=int, choices=range(0, 6), metavar='0-5',
                        help='Set color temperature (0-5)')
    parser.add_argument('--front-light', type=int, choices=range(0, 3), metavar='0-2',
                        help='Set front light mode (0=off 1=warm 2=cold)')
    parser.add_argument('--dither', choices=['on', 'off'],
                        help='MCU dithering control (off = sharper, recommended)')
    parser.add_argument('--refresh', action='store_true', help='Force display refresh')
    parser.add_argument('--send', nargs=2, action='append', metavar=('CMD', 'OPT'),
                        help='Send raw command (hex or decimal, e.g. --send 0x02 0x03)')
    parser.add_argument('--query', action='store_true', help='Query device info')
    parser.add_argument('--monitor', action='store_true', help='Monitor serial traffic')
    args = parser.parse_args()

    # Build command list from args
    commands = build_commands(args)
    use_daemon = daemon_is_running()

    # Query mode
    if args.query:
        if use_daemon:
            run_via_daemon(query=True)
        else:
            port = args.port or find_serial_port()
            if not port:
                print("ERROR: No CH340/CH341 serial port found.")
                sys.exit(1)
            ser = open_serial(port)
            query_device_info(ser)
            ser.close()
        return

    # Monitor mode (always direct, needs exclusive port access)
    if args.monitor:
        port = args.port or find_serial_port()
        if not port:
            print("ERROR: No CH340/CH341 serial port found.")
            sys.exit(1)
        print(f"Monitoring {port} (Ctrl+C to stop)...")
        ser = open_serial(port)
        try:
            while True:
                d = ser.read(256)
                if d:
                    pkts = parse_packets(d)
                    for p in pkts:
                        kind = "HB" if p[0] == 0xF5 else f"0x{p[0]:02X}"
                        print(f"  [{time.strftime('%H:%M:%S')}] {kind} opt=0x{p[1]:02X} {p[2]}")
                time.sleep(0.01)
        except KeyboardInterrupt:
            pass
        ser.close()
        return

    # If commands given and daemon is running, forward to daemon
    if commands and use_daemon and not args.daemon:
        run_via_daemon(commands=commands)
        return

    # Resolve port for direct operations
    port = args.port
    if not port:
        port = find_serial_port()
        if not port:
            print("ERROR: No CH340/CH341 serial port found.")
            print("  sudo modprobe ch341")
            print("  sudo usermod -aG dialout $USER")
            sys.exit(1)
        print(f"Auto-detected: {port}")

    # Send setting commands directly if no daemon
    if commands and not args.daemon:
        run_commands_direct(port, commands)
        return

    # Send settings then start daemon, or just start daemon/init
    if commands:
        ser = open_serial(port)
        for cmd, opt, label in commands:
            send_cmd(ser, cmd, opt, label)
        ser.close()

    init_display(port, daemon=args.daemon, interval=args.interval)


if __name__ == '__main__':
    main()
