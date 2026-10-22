#!/usr/bin/env python3
"""Test real GTK caption pointer clicks on native Wayland through WSLg.

AT-SPI only reads GTK geometry. Windows sends mouse movement, left press and
release to the WSLg host window; accessibility actions/WebDriver cannot test
this regression. Requires the existing Python gi/Atspi and Windows PowerShell.
No Xvfb, compositor emulation, live profile, installed service or proxy changes.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


PRIVATE_BUS_MARKER = 'HOMEPROXY_WINDOW_CONTROLS_PRIVATE_BUS'


def private_bus_environment(environment):
    # Neither GTK accessibility nor single-instance activation may reach the
    # caller's session. dbus-run-session supplies a new address to its child.
    env = {key: value for key, value in environment.items()
           if not key.startswith('DBUS_') and key != 'AT_SPI_BUS_ADDRESS'}
    env[PRIVATE_BUS_MARKER] = '1'
    return env


def mark_failed(report, error):
    report['passed'] = False
    report.setdefault('errors', []).append(str(error))


def stop_processes(processes):
    errors = []
    for process in reversed(processes):
        try:
            if process.poll() is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            else:
                process.wait(timeout=5)
        except Exception as error:
            errors.append(str(error))
    if errors:
        raise RuntimeError('Process cleanup failed: ' + '; '.join(errors))


@contextmanager
def reap_before_profile_removal(processes):
    try:
        yield
    finally:
        stop_processes(processes)


def finish_cleanup(report, actions):
    # A failed finalizer must neither preserve a green report nor prevent the
    # other finalizers (including restoring the user's cursor) from running.
    for action in actions:
        try:
            action()
        except BaseException as error:
            mark_failed(report, error)


WIN32 = r'''
Add-Type -TypeDefinition @"
using System; using System.Text; using System.Runtime.InteropServices;
public class CaptionQA {
 public delegate bool Callback(IntPtr h, IntPtr p);
 [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left,Top,Right,Bottom; }
 [StructLayout(LayoutKind.Sequential)] public struct Point { public int X,Y; }
 [DllImport("user32.dll")] public static extern bool EnumWindows(Callback cb, IntPtr p);
 [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
 [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
 [DllImport("user32.dll")] public static extern bool IsZoomed(IntPtr h);
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out Rect r);
 [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out Rect r);
 [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr h, ref Point p);
 [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
 [DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(Point p);
 [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr h, uint flags);
 [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
 [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int command);
 [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
 [DllImport("user32.dll")] public static extern bool GetCursorPos(out Point p);
 [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
 [DllImport("user32.dll")] public static extern void mouse_event(uint f,uint x,uint y,uint d,UIntPtr e);
}
"@
$ErrorActionPreference = 'Stop'
[void][CaptionQA]::SetProcessDPIAware()
'''


def pointer_center(frame, button, host):
    """Map GTK-local extents to the host client, refusing uncertain geometry."""
    fx, fy, fw, fh = frame
    bx, by, bw, bh = button
    hx, hy, hw, hh = host
    if min(fw, fh, bw, bh, hw, hh) <= 0:
        raise ValueError('Invalid caption geometry')
    if not (fx <= bx and fy <= by and bx + bw <= fx + fw and by + bh <= fy + fh):
        raise ValueError('Caption button is outside its GTK frame')
    # WSLg normally uses identical GTK/host pixels. Refuse scaling assumptions
    # instead of risking a click on another application or an unrelated control.
    if abs(fw - hw) > 2 or abs(fh - hh) > 2:
        raise ValueError(f'GTK/host pixel geometry differs: {frame} / {host}')
    return round(hx + bx - fx + bw / 2), round(hy + by - fy + bh / 2)


def wait_for(predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.1)
    raise AssertionError('Timed out waiting for native window state')


class WindowsPointer:
    def __init__(self, executable):
        self.executable = executable

    def run(self, code):
        result = subprocess.run([self.executable, '-NoProfile', '-NonInteractive',
                                 '-Command', WIN32 + code], capture_output=True,
                                text=True, timeout=20)
        if result.returncode:
            raise RuntimeError('Windows pointer driver: ' + result.stderr.strip()[:3000])
        return json.loads(result.stdout)

    def restore_host(self, handle):
        # Wayland has no client unminimize request. Restore the WSLg host just
        # as its taskbar does; all tested caption actions still use pointers.
        return self.run(f'''
if (-not [CaptionQA]::IsWindow([IntPtr]{handle})) {{throw 'Restore target vanished'}}
[void][CaptionQA]::ShowWindow([IntPtr]{handle},9)
[void][CaptionQA]::SetForegroundWindow([IntPtr]{handle})
'true'
''')

    def windows(self):
        return self.run(r'''
$items = [System.Collections.Generic.List[object]]::new()
[void][CaptionQA]::EnumWindows({param($h,$p)
 $title=[Text.StringBuilder]::new(1024)
 [void][CaptionQA]::GetWindowText($h,$title,1024)
 if ([CaptionQA]::IsWindowVisible($h) -and $title.ToString() -like 'HomeProxy*') {
  $items.Add(@{handle=$h.ToInt64();title=$title.ToString()})
 }
 return $true
},[IntPtr]::Zero)
ConvertTo-Json -InputObject @($items.ToArray()) -Compress
''')

    def state(self, handle):
        return self.run(f'''
$h=[IntPtr]{handle}
$r=[CaptionQA+Rect]::new(); $p=[CaptionQA+Point]::new()
[void][CaptionQA]::GetClientRect($h,[ref]$r)
[void][CaptionQA]::ClientToScreen($h,[ref]$p)
@{{exists=[CaptionQA]::IsWindow($h);minimized=[CaptionQA]::IsIconic($h);
 maximized=[CaptionQA]::IsZoomed($h);client=@($p.X,$p.Y,$r.Right,$r.Bottom)}} | ConvertTo-Json -Compress
''')

    def save_context(self):
        return self.run('''
$p=[CaptionQA+Point]::new(); [void][CaptionQA]::GetCursorPos([ref]$p)
@{foreground=[CaptionQA]::GetForegroundWindow().ToInt64();cursor=@($p.X,$p.Y)} | ConvertTo-Json -Compress
''')

    def restore_context(self, context):
        self.run(f'''
[void][CaptionQA]::SetCursorPos({context['cursor'][0]},{context['cursor'][1]})
if ([CaptionQA]::IsWindow([IntPtr]{context['foreground']})) {{
 [void][CaptionQA]::SetForegroundWindow([IntPtr]{context['foreground']})
}}
'true'
''')

    def click(self, handle, x, y, screenshot, crop):
        windows_path = subprocess.run(['wslpath', '-w', str(screenshot)], capture_output=True,
                                      text=True, check=True).stdout.strip().replace("'", "''")
        return self.run(f'''
$h=[IntPtr]{handle}
if (-not [CaptionQA]::IsWindow($h)) {{throw 'Test window no longer exists'}}
[void][CaptionQA]::SetForegroundWindow($h)
Start-Sleep -Milliseconds 150
if ([CaptionQA]::GetForegroundWindow() -ne $h) {{throw 'Test window did not gain foreground'}}
# Leave caption hover/snap popups before approaching the next caption. This
# moves only within our client and never clicks an overlay to dismiss it.
$client=[CaptionQA+Rect]::new(); $origin=[CaptionQA+Point]::new()
[void][CaptionQA]::GetClientRect($h,[ref]$client)
[void][CaptionQA]::ClientToScreen($h,[ref]$origin)
[void][CaptionQA]::SetCursorPos($origin.X+[int]($client.Right/2),$origin.Y+[int]($client.Bottom/2))
Start-Sleep -Milliseconds 500
[void][CaptionQA]::SetCursorPos({x},{y})
Start-Sleep -Milliseconds 150
$p=[CaptionQA+Point]::new(); [void][CaptionQA]::GetCursorPos([ref]$p)
if ($p.X -ne {x} -or $p.Y -ne {y}) {{throw 'Pointer position did not match caption'}}
$under=[CaptionQA]::GetAncestor([CaptionQA]::WindowFromPoint($p),2)
if ($under -ne $h) {{
 $title=[Text.StringBuilder]::new(1024); [void][CaptionQA]::GetWindowText($under,$title,1024)
 throw ('Caption pointer is obscured or outside the test window; actual handle='+$under+' title='+$title)
}}
if ([CaptionQA]::GetForegroundWindow() -ne $h) {{throw 'Foreground changed before pointer press'}}
Add-Type -AssemblyName System.Drawing
$r=[CaptionQA+Rect]::new(); [void][CaptionQA]::GetClientRect($h,[ref]$r)
$origin=[CaptionQA+Point]::new(); [void][CaptionQA]::ClientToScreen($h,[ref]$origin)
$bitmap=[Drawing.Bitmap]::new({crop[2]},{crop[3]})
$graphics=[Drawing.Graphics]::FromImage($bitmap)
try {{
 $graphics.CopyFromScreen($origin.X+{crop[0]},$origin.Y+{crop[1]},0,0,$bitmap.Size)
 $bitmap.Save('{windows_path}',[Drawing.Imaging.ImageFormat]::Png)
}} finally {{ $graphics.Dispose(); $bitmap.Dispose() }}
[CaptionQA]::mouse_event(2,0,0,0,[UIntPtr]::Zero)
try {{ Start-Sleep -Milliseconds 80 }} finally {{ [CaptionQA]::mouse_event(4,0,0,0,[UIntPtr]::Zero) }}
'true'
''')


def self_test():
    class GeometryTests(unittest.TestCase):
        def test_client_translation(self):
            self.assertEqual(pointer_center([0, 0, 1232, 859], [1086, 31, 34, 30],
                                            [447, 15, 1232, 859]), (1550, 61))

        def test_unknown_scale_is_rejected(self):
            with self.assertRaises(ValueError):
                pointer_center([0, 0, 1200, 800], [1100, 10, 30, 30], [0, 0, 1800, 1200])

        def test_outside_button_is_rejected(self):
            with self.assertRaises(ValueError):
                pointer_center([0, 0, 1200, 800], [-2147483648, 0, 30, 30], [0, 0, 1200, 800])

        def test_private_bus_drops_caller_activation_and_accessibility(self):
            original = {'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/caller-bus',
                        'DBUS_STARTER_ADDRESS': 'unix:path=/caller-starter',
                        'AT_SPI_BUS_ADDRESS': 'unix:path=/caller-accessibility',
                        'WAYLAND_DISPLAY': 'wayland-0'}
            isolated = private_bus_environment(original)
            self.assertNotIn('DBUS_SESSION_BUS_ADDRESS', isolated)
            self.assertNotIn('DBUS_STARTER_ADDRESS', isolated)
            self.assertNotIn('AT_SPI_BUS_ADDRESS', isolated)
            self.assertEqual(isolated['WAYLAND_DISPLAY'], 'wayland-0')
            self.assertEqual(original['DBUS_SESSION_BUS_ADDRESS'], 'unix:path=/caller-bus')

        def test_profile_cleanup_failure_revokes_success(self):
            class BrokenCleanup:
                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    raise OSError('injected profile cleanup failure')

            report = {'passed': False}
            try:
                with BrokenCleanup():
                    report['passed'] = True
            except Exception as error:
                mark_failed(report, error)
            self.assertFalse(report['passed'])
            self.assertIn('injected profile cleanup failure', report['errors'][0])

        def test_failed_finalizer_does_not_skip_cursor_restore(self):
            report = {'passed': True}
            restored = []

            def broken_cleanup():
                raise OSError('injected process cleanup failure')

            finish_cleanup(report, [broken_cleanup, lambda: restored.append(True)])
            self.assertFalse(report['passed'])
            self.assertEqual(restored, [True])

        def test_context_restore_failure_revokes_success(self):
            report = {'passed': True}

            def broken_restore():
                raise OSError('injected cursor restoration failure')

            finish_cleanup(report, [broken_restore])
            self.assertFalse(report['passed'])

        def test_real_child_reaped_before_profile_disappears(self):
            processes = []
            with tempfile.TemporaryDirectory(prefix='homeproxy-cleanup-selftest-') as temporary:
                profile = Path(temporary)
                with reap_before_profile_removal(processes):
                    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
                    processes.append(process)
                self.assertIsNotNone(process.poll())
                self.assertTrue(profile.exists())
            self.assertFalse(profile.exists())

        def test_broken_process_does_not_leave_other_child_alive(self):
            class BrokenProcess:
                def poll(self):
                    raise OSError('injected process polling failure')

            process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
            try:
                with self.assertRaisesRegex(RuntimeError, 'injected process polling failure'):
                    stop_processes([process, BrokenProcess()])
                self.assertIsNotNone(process.poll())
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)

    return 0 if unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(GeometryTests)).wasSuccessful() else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--desktop', type=Path)
    parser.add_argument('--binaries-dir', type=Path, default=Path('target/release'))
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--powershell', default=shutil.which('powershell.exe'))
    parser.add_argument('--decoration-layout', choices=[':minimize,maximize,close'],
                        help='Set Ubuntu-style GTK buttons in the isolated test profile only')
    parser.add_argument('--scenario', choices=['fresh-minimize-restore-close', 'fresh-close',
                                               'maximize-then-minimize', 'maximize-restore-close'])
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not args.desktop or not args.artifacts or not args.powershell:
        parser.error('--desktop, --artifacts and Windows PowerShell are required')
    if os.environ.get(PRIVATE_BUS_MARKER) != '1':
        runner = shutil.which('dbus-run-session')
        if not runner:
            parser.error('dbus-run-session is required for an isolated native test')
        return subprocess.run([runner, '--', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:]], env=private_bus_environment(os.environ)).returncode
    # A caller-provided marker alone cannot bypass the private session wrapper.
    try:
        session_parent = Path(f'/proc/{os.getppid()}/exe').resolve(strict=True).name
    except OSError:
        session_parent = None
    if session_parent != 'dbus-run-session' or not os.environ.get('DBUS_SESSION_BUS_ADDRESS'):
        parser.error('Native test must be a child of its own dbus-run-session')
    import gi
    gi.require_version('Atspi', '2.0')
    from gi.repository import Atspi
    if not os.environ.get('WAYLAND_DISPLAY'):
        parser.error('A real Wayland session is required; Xvfb is insufficient')
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True, mode=0o700)
    report = {'backend': 'wayland', 'input': 'Win32 mouse movement/left press/release via WSLg',
              'atspi': 'read-only geometry', 'decoration_layout': args.decoration_layout or 'GTK session default',
              'session_bus': 'private dbus-run-session', 'binaries': {}, 'scenarios': [], 'passed': False}
    pointer = WindowsPointer(args.powershell)
    context = None
    processes = []
    try:
        context = pointer.save_context()
        with tempfile.TemporaryDirectory(prefix='homeproxy-caption-') as temporary, reap_before_profile_removal(processes):
            root = Path(temporary)
            binaries = root / 'binaries'
            binaries.mkdir(mode=0o700)
            for name, source in [('klidna-sit', args.desktop),
                                 ('homeproxy', args.binaries_dir / 'homeproxy'),
                                 ('homeproxyd', args.binaries_dir / 'homeproxyd')]:
                source = source.resolve()
                digest = hashlib.sha256(source.read_bytes()).hexdigest()
                shutil.copy2(source, binaries / name)
                assert hashlib.sha256((binaries / name).read_bytes()).hexdigest() == digest
                report['binaries'][name] = {'source': str(source), 'sha256': digest}
            endpoint = root / 'run/control.sock'
            env = dict(os.environ, GDK_BACKEND='wayland', HOMEPROXY_SOCKET=str(endpoint),
                       XDG_CONFIG_HOME=str(root / 'config'), XDG_DATA_HOME=str(root / 'data'),
                       XDG_CACHE_HOME=str(root / 'ui-cache'), LIBGL_ALWAYS_SOFTWARE='1',
                       NO_AT_BRIDGE='0', GTK_THEME='Adwaita')
            if args.decoration_layout:
                gtk_config = root / 'config/gtk-3.0'
                gtk_config.mkdir(parents=True, mode=0o700)
                (gtk_config / 'settings.ini').write_text(
                    '[Settings]\ngtk-decoration-layout=' + args.decoration_layout + '\n')
                # GTK Wayland's GNOME preference overrides settings.ini. A
                # keyfile backend confines this desktop preference to our XDG
                # profile; dconf/the user's live settings must never be edited.
                env['GSETTINGS_BACKEND'] = 'keyfile'
                subprocess.run(['gsettings', 'set', 'org.gnome.desktop.wm.preferences',
                                'button-layout', args.decoration_layout], env=env,
                               capture_output=True, text=True, check=True, timeout=10)
            with (artifacts / 'native.log').open('w') as log:
                daemon = subprocess.Popen([str(binaries / 'homeproxyd'), '--state-dir', str(root / 'state'),
                                           '--cache-dir', str(root / 'cache'), '--socket', str(endpoint),
                                           '--foreground'], env=env, stdout=log, stderr=log)
                processes.append(daemon)

                def daemon_status():
                    assert daemon.poll() is None, 'Isolated daemon exited'
                    result = subprocess.run([str(binaries / 'homeproxy'), '--socket', str(endpoint),
                                             '--json', 'status'], env=env, text=True, capture_output=True,
                                            timeout=10, check=True)
                    value = json.loads(result.stdout)
                    assert value['ok'] and value['result']['platform'] == 'linux'
                    assert not value['result']['running'], 'Fresh test profile unexpectedly runs a proxy'
                    return True

                wait_for(lambda: endpoint.exists())
                daemon_status()

                def gtk_frame(process):
                    desktop = Atspi.get_desktop(0)
                    for i in range(desktop.get_child_count()):
                        application = desktop.get_child_at_index(i)
                        if application.get_process_id() == process.pid:
                            for j in range(application.get_child_count()):
                                frame = application.get_child_at_index(j)
                                if frame.get_role_name() == 'frame':
                                    return frame
                    assert process.poll() is None, 'Desktop exited before showing a GTK frame'
                    return None

                def extents(node):
                    rect = node.get_component_iface().get_extents(Atspi.CoordType.SCREEN)
                    return [rect.x, rect.y, rect.width, rect.height]

                def caption(frame, name):
                    # Restrict discovery to the native header, never a web control
                    # with a matching accessible name.
                    header = frame.get_child_at_index(0)
                    pending = [(header, 0)]
                    while pending:
                        node, depth = pending.pop()
                        if node.get_name() == name and node.get_role_name() == 'button':
                            return node
                        if depth < 4:
                            pending.extend((node.get_child_at_index(i), depth + 1)
                                           for i in range(node.get_child_count()))
                    raise AssertionError(f'Native GTK caption {name!r} was not found')

                for label, actions in [('fresh-minimize-restore-close', ['Minimize', 'RestoreHost', 'Close']), ('fresh-close', ['Close']),
                                       ('maximize-then-minimize', ['Maximize', 'Minimize']),
                                       ('maximize-restore-close', ['Maximize', 'Restore', 'Close'])]:
                    if args.scenario and label != args.scenario:
                        continue
                    before = {item['handle'] for item in pointer.windows()}
                    process = subprocess.Popen([str(binaries / 'klidna-sit')], env=env,
                                               stdout=log, stderr=log)
                    processes.append(process)
                    scenario = {'name': label, 'clicks': [], 'passed': False}
                    report['scenarios'].append(scenario)
                    try:
                        frame = wait_for(lambda: gtk_frame(process))
                        candidates = wait_for(lambda: [item for item in pointer.windows()
                                                       if item['handle'] not in before])
                        assert len(candidates) == 1, 'Cannot uniquely identify the new WSLg host window'
                        handle = candidates[0]['handle']
                        scenario['host'] = candidates[0]
                        time.sleep(1)
                        initial = pointer.state(handle)
                        assert initial['exists'] and not initial['minimized'] and not initial['maximized']
                        scenario['initial'] = initial
                        for action in actions:
                            if action == 'RestoreHost':
                                pointer.restore_host(handle)
                                wait_for(lambda: not pointer.state(handle)['minimized'], timeout=3)
                                assert process.poll() is None, 'Restoring lost the desktop process'
                                scenario['clicks'].append({'housekeeping': 'restore WSLg host as its taskbar does',
                                                          'host_after': pointer.state(handle)})
                                daemon_status()
                                continue
                            button = caption(frame, action)
                            state = pointer.state(handle)
                            frame_rect, button_rect = extents(frame), extents(button)
                            x, y = pointer_center(frame_rect, button_rect, state['client'])
                            event = {'caption': action, 'gtk_frame': frame_rect, 'gtk_button': button_rect,
                                     'host_before': state, 'pointer': [x, y]}
                            scenario['clicks'].append(event)
                            screenshot = artifacts / f'{label}-{len(scenario["clicks"]):02d}-{action.lower()}.png'
                            event['screenshot_before_pointer'] = str(screenshot)
                            # Omit transparent CSD shadows: they expose ambient
                            # windows behind the isolated application.
                            children = [extents(frame.get_child_at_index(i))
                                        for i in range(frame.get_child_count())]
                            cx = min(rect[0] for rect in children)
                            cy = min(rect[1] for rect in children)
                            crop = [cx - frame_rect[0], cy - frame_rect[1],
                                    max(rect[0] + rect[2] for rect in children) - cx,
                                    max(rect[1] + rect[3] for rect in children) - cy]
                            pointer.click(handle, x, y, screenshot, crop)
                            time.sleep(.6)
                            event['host_after'] = pointer.state(handle)
                            event['desktop_exit'] = process.poll()
                            if action == 'Close':
                                wait_for(lambda: process.poll() is not None, timeout=3)
                                assert not pointer.state(handle)['exists'], 'Close left the native window alive'
                                assert process.returncode == 0, f'Desktop close exit was {process.returncode}'
                            else:
                                key = 'minimized' if action == 'Minimize' else 'maximized'
                                expected = action != 'Restore'
                                assert event['host_after'][key] == expected, f'{action} pointer click did not change native {key}'
                                assert process.poll() is None, 'Caption action unexpectedly exited the desktop'
                            daemon_status()
                        scenario['daemon_alive'] = daemon_status()
                        scenario['passed'] = True
                        print(f'PASS {label}', flush=True)
                    except Exception as error:
                        scenario['error'] = str(error)
                        scenario['daemon_alive'] = daemon_status()
                        print(f'FAIL {label}: {error}', flush=True)
                    finally:
                        if process.poll() is None:
                            process.terminate()
                            process.wait(timeout=10)
                        time.sleep(.3)
                report['passed'] = bool(report['scenarios']) and all(item['passed'] for item in report['scenarios'])
    except BaseException as error:
        mark_failed(report, error)
        report['error'] = str(error)
        print(f'BLOCKED: {error}', flush=True)
    finally:
        cleanup = [lambda: stop_processes(processes)]
        if context is not None:
            cleanup.append(lambda: pointer.restore_context(context))
        finish_cleanup(report, cleanup)
        (artifacts / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
