"""Render real Qt widgets in a hidden window; never captures the desktop or starts packet capture."""
from pathlib import Path
import argparse
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--exe', type=Path, default=ROOT / 'build-plus-release/FlowLens.exe')
parser.add_argument('--output', type=Path, default=ROOT / 'output/plus/04-ui/gui')
parser.add_argument('--qt-root', type=Path, default=Path(r'D:\ProgramData\Anaconda3\Library'))
options = parser.parse_args()
options.output.mkdir(parents=True, exist_ok=True)
environment = os.environ.copy()
environment['PATH'] = str(options.qt_root / 'bin') + os.pathsep + environment['PATH']
environment['QT_PLUGIN_PATH'] = str(options.qt_root / 'plugins')
# Old Qt's generic offscreen backend on Windows has no font engine. Use the
# native font engine with WA_DontShowOnScreen; QWidget::render reads no screen.
environment['QT_QPA_PLATFORM'] = 'windows'
environment['QT_SCALE_FACTOR'] = '1'
command = [str(options.exe), '--preview-ui', str(options.output), str(ROOT / 'samples/showcase.pcap')]
result = subprocess.run(command, env=environment, capture_output=True, timeout=60)
(options.output / 'process.txt').write_text('Exit: ' + str(result.returncode) + '\nSTDOUT:\n' +
    result.stdout.decode('utf-8', 'replace') + '\nSTDERR:\n' + result.stderr.decode('utf-8', 'replace'), encoding='utf-8')
validation = json.loads((options.output / 'ui-validation.json').read_text(encoding='utf-8'))
assert result.returncode == 0 and validation['status'] == 'PASS', validation
checks = [value for value in validation.values() if isinstance(value, bool)]
assert len(checks) >= 30 and all(checks), validation
fixes = validation.get('bugfix_checks', {})
assert len(fixes) >= 14 and all(fixes.values()), validation
for name in ['overview.png', 'ip-reassembly.png', 'bugfix-reset.png', 'bugfix-pid-flow.png']:
    assert (options.output / name).stat().st_size > 10000
print('PASS', len(checks), 'Qt UI checks +', len(fixes), 'bugfix checks; hidden widget rendering only, no screen capture or live capture')
