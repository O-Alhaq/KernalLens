#!/usr/bin/env python3
"""Explicit, repeatable Ubuntu development setup. Never starts capture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ('build-essential', 'make', 'clang', 'llvm', 'bpftool', 'libbpf-dev',
            'libelf-dev', 'zlib1g-dev', 'pkg-config', 'python3', 'python3-venv',
            'python3-pip', 'nodejs', 'npm', 'iproute2', 'ca-certificates')


def run(command, **kwargs):
    print('+ '+shlex.join(map(str, command)), flush=True)
    return subprocess.run(list(map(str, command)), cwd=ROOT, check=True, **kwargs)


def output(command):
    return subprocess.check_output(command, cwd=ROOT, text=True, stderr=subprocess.STDOUT).strip()


def check_platform(release=None, system=None):
    release = platform.freedesktop_os_release() if release is None else release
    system = platform.system() if system is None else system
    if system != 'Linux' or release.get('ID') != 'ubuntu' or release.get('VERSION_ID') != '26.04':
        raise RuntimeError('Automatic setup targets Ubuntu 26.04 LTS on Linux. See docs/SETUP.md for prerequisites on other systems; no OS packages were changed.')


def missing_packages():
    missing = []
    for package in PACKAGES:
        try:
            if output(['dpkg-query', '-W', '-f=${Status}', package]) == 'install ok installed':
                continue
        except subprocess.CalledProcessError:
            pass
        missing.append(package)
    return missing


def install_packages(packages, assume_yes=False):
    if not packages:
        print('✓ OS packages already satisfied')
        return
    print('Missing OS packages: '+', '.join(packages))
    print('Setup will refresh Ubuntu package indexes and install these packages via sudo apt-get.\n'
          'It will not add repositories or run a system upgrade.')
    if not assume_yes:
        if not sys.stdin.isatty() or input('Install these OS packages? [y/N] ').strip().lower() not in ('y', 'yes'):
            raise RuntimeError('OS installation declined. Install the listed packages yourself, then rerun ./scripts/setup.sh (or use --yes after reviewing the list).')
    run(['sudo', '-v'])
    run(['sudo', '-n', 'apt-get', 'update'])
    run(['sudo', '-n', 'apt-get', 'install', '-y', '--no-install-recommends', *packages])


def check_kernel(btf=Path('/sys/kernel/btf/vmlinux')):
    if not btf.is_file() or not os.access(btf, os.R_OK):
        raise RuntimeError('Kernel BTF is unavailable at /sys/kernel/btf/vmlinux. Boot a supported Ubuntu generic kernel; see docs/SETUP.md. Setup cannot enable missing kernel features.')
    # CONFIG_FTRACE_SYSCALLS may be visible without root even when tracefs is not.
    config = Path('/boot')/f'config-{platform.release()}'
    if config.is_file() and os.access(config, os.R_OK):
        text = config.read_text()
        for name in ('CONFIG_BPF', 'CONFIG_BPF_SYSCALL', 'CONFIG_DEBUG_INFO_BTF', 'CONFIG_FTRACE_SYSCALLS'):
            if f'{name}=y' not in text.splitlines():
                raise RuntimeError(f'Running kernel lacks {name}=y. See docs/SETUP.md; a supported kernel is required.')
    print('✓ Kernel BTF prerequisite (actual XDP/tracepoint attachment is checked at dashboard startup)')


def check_owned_artifacts(root=ROOT, uid=None):
    uid = os.getuid() if uid is None else uid
    for name in ('.venv', 'frontend/node_modules', 'build', '.tools'):
        path = root/name
        if path.is_symlink():
            raise RuntimeError(f'Refusing symlinked setup output directory: {path}')
        if not path.exists():
            continue
        paths = [path]
        for directory, dirs, files in os.walk(path, followlinks=False):
            paths.extend(Path(directory)/item for item in (*dirs, *files))
        for item in paths:
            if item.lstat().st_uid != uid:
                raise RuntimeError(f'Setup output is owned by another user: {item}. Repair that specific artifact separately; do not run setup with sudo.')


def ensure_venv(root=ROOT):
    python = root/'.venv/bin/python'
    if not (root/'.venv').exists():
        run([sys.executable, '-m', 'venv', str(root/'.venv')])
    elif not python.is_file():
        raise RuntimeError('Existing .venv is incomplete; inspect it before moving it aside and rerunning ./scripts/setup.sh. It was not deleted.')
    result = output([str(python), '-c', 'import sys; print(sys.prefix != sys.base_prefix)'])
    if result != 'True':
        raise RuntimeError('.venv/bin/python is not a virtual environment. Inspect .venv; setup will not install into system Python.')
    print('✓ Python virtual environment (reused when present)')
    return python


def version(value):
    try:
        return tuple(int(piece) for piece in value.lstrip('v').split('.')[:3])
    except ValueError:
        raise RuntimeError(f'Cannot parse tool version {value!r}') from None


def npm_command(root=ROOT):
    if version(output(['node', '--version'])) < (22, 12, 0):
        raise RuntimeError('Node.js 22.12+ is required. Install a compatible version from https://nodejs.org/en/download/ as your normal user, then rerun setup. No remote installer or repository was added.')
    if version(output(['npm', '--version'])) >= (10, 0, 0):
        print('✓ Node/npm supported')
        return ['npm']
    # Ubuntu ships npm 9: keep its global install untouched. Bootstrap a single
    # npm package locally, outside frontend's peer-dependency resolver.
    local = root/'.tools/npm/node_modules/npm/bin/npm-cli.js'
    if not local.is_file():
        print('Preparing project-local npm 11 (.tools/npm); global npm is unchanged.')
        run(['npm', 'install', '--prefix', str(root/'.tools/npm'), '--no-save', '--no-package-lock',
             '--ignore-scripts', '--global=false', '--no-audit', '--no-fund', 'npm@11'])
    command = ['node', str(local)]
    if version(output([*command, '--version'])) < (11, 0, 0):
        raise RuntimeError('Project-local npm is incomplete/unsupported. Inspect .tools/npm before retrying setup.')
    print('✓ Node/npm (project-local npm 11)')
    return command


def frontend_fingerprint(root):
    return hashlib.sha256((root/'frontend/package.json').read_bytes() + b'\0' +
                          (root/'frontend/package-lock.json').read_bytes()).hexdigest()


def ensure_frontend(npm, root=ROOT):
    stamp = root/'.tools/frontend-dependencies.sha256'
    fingerprint = frontend_fingerprint(root)
    # npm ls verifies the installed tree; the stamp also detects edited manifests.
    unchanged = not stamp.exists() or stamp.read_text().strip() == fingerprint
    if (root/'frontend/node_modules').is_dir() and unchanged:
        result = subprocess.run([*npm, '--prefix', str(root/'frontend'), 'ls', '--all', '--include=dev', '--silent'],
                                cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        satisfied = result.returncode == 0
    else:
        satisfied = False
    if satisfied:
        print('✓ Frontend dependencies already satisfied (reused)')
    else:
        print('Installing frontend dependencies from package-lock.json; npm ci replaces an incomplete/outdated node_modules tree.')
        run([*npm, '--prefix', str(root/'frontend'), 'ci', '--include=dev', '--global=false', '--no-audit', '--no-fund'])
        run([*npm, '--prefix', str(root/'frontend'), 'ls', '--all', '--include=dev', '--silent'], stdout=subprocess.DEVNULL)
        print('✓ Frontend dependencies')
    stamp.parent.mkdir(exist_ok=True)
    stamp.write_text(fingerprint+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--yes', action='store_true', help='approve the printed missing OS package list without prompting')
    parser.add_argument('--check', action='store_true', help='inspect prerequisites only; do not install, build or write files')
    args = parser.parse_args()
    try:
        if os.geteuid() == 0:
            raise RuntimeError('Run ./scripts/setup.sh as your normal user, without sudo. Only apt package installation uses sudo.')
        check_platform()
        print('KernelLens Setup\n✓ Linux environment: Ubuntu 26.04 LTS')
        check_kernel()
        check_owned_artifacts()
        missing = missing_packages()
        if args.check:
            print('Missing OS packages: '+(', '.join(missing) if missing else 'none'))
            print('Read-only preflight complete. Run ./scripts/setup.sh to prepare and validate all dependencies.')
            return 1 if missing else 0
        install_packages(missing, args.yes)
        for command in ('make', 'cc', 'clang', 'llc', 'bpftool', 'pkg-config', 'node', 'npm', 'ip'):
            if shutil.which(command) is None:
                raise RuntimeError(f'{command} is still unavailable. Inspect apt output or your PATH; see docs/SETUP.md.')
        run(['clang', '-target', 'bpf', '-x', 'c', '-c', '-o', os.devnull, '-'], input=b'int probe;')
        run(['bpftool', 'version'])
        run(['pkg-config', '--exists', 'libbpf', 'libelf'])
        print('✓ clang/LLVM BPF target\n✓ bpftool\n✓ libbpf/build tooling\n✓ Python')
        python = ensure_venv()
        run([str(python), '-m', 'pip', 'install', '-r', 'requirements-dev.txt'])
        run([str(python), '-m', 'pip', 'check'])
        print('✓ Python dependencies')
        npm = npm_command()
        ensure_frontend(npm)
        run(['make', 'all'])
        print('✓ KernelLens build')
        run([str(python), '-B', 'scripts/validate_config.py'])
        print('✓ Configuration\n\nSetup complete.\n\nStart KernelLens with:\n\n    make dashboard')
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'\nSetup failed: {error}\nSee docs/SETUP.md. Fix the reported issue and rerun ./scripts/setup.sh.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
