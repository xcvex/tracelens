#!/usr/bin/env python3
"""
Local build script for TraceLens

Usage:
    python build.py          # Build for current platform
    python build.py --clean  # Clean build artifacts first
"""

import os
import sys
import shutil
import subprocess
import argparse
from pathlib import Path


def clean():
    """Clean build artifacts"""
    dirs_to_remove = ['build', 'dist', '__pycache__']
    files_to_remove = ['*.pyc', '*.pyo', '*.spec.bak']
    
    for dir_name in dirs_to_remove:
        for path in Path('.').rglob(dir_name):
            if path.is_dir():
                print(f"Removing {path}")
                shutil.rmtree(path)
    
    for pattern in files_to_remove:
        for path in Path('.').rglob(pattern):
            if path.is_file():
                print(f"Removing {path}")
                path.unlink()


def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import PyInstaller
        print(f"✓ PyInstaller {PyInstaller.__version__}")
    except ImportError:
        print("✗ PyInstaller not found. Installing...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyinstaller'], check=True)
    
    # Check project dependencies
    try:
        import rich
        import click
        import dns
        import httpx
        print("✓ All dependencies installed")
    except ImportError as e:
        print(f"✗ Missing dependency: {e}")
        print("Installing dependencies...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], check=True)


def build():
    """Build the executable"""
    print("\n" + "=" * 60)
    print("Building TraceLens executable...")
    print("=" * 60 + "\n")
    
    # Run PyInstaller
    result = subprocess.run(
        [sys.executable, '-m', 'PyInstaller', 'tracelens.spec', '--noconfirm'],
        capture_output=False
    )
    
    if result.returncode != 0:
        print("\n✗ Build failed!")
        sys.exit(1)
    
    # Get output path
    if sys.platform == 'win32':
        exe_path = Path('dist/tracelens.exe')
    else:
        exe_path = Path('dist/tracelens')
    
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print("\n" + "=" * 60)
        print(f"✓ Build successful!")
        print(f"  Output: {exe_path.absolute()}")
        print(f"  Size: {size_mb:.1f} MB")
        print("=" * 60)
        
        # Test the build
        print("\nTesting build...")
        test_result = subprocess.run([str(exe_path), '--version'], capture_output=True, text=True)
        if test_result.returncode == 0:
            print(f"✓ {test_result.stdout.strip()}")
        else:
            print(f"✗ Test failed: {test_result.stderr}")
    else:
        print("\n✗ Output file not found!")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Build TraceLens executable')
    parser.add_argument('--clean', action='store_true', help='Clean build artifacts first')
    parser.add_argument('--clean-only', action='store_true', help='Only clean, do not build')
    args = parser.parse_args()
    
    os.chdir(Path(__file__).parent)
    
    if args.clean or args.clean_only:
        print("Cleaning build artifacts...")
        clean()
        if args.clean_only:
            print("Done.")
            return
    
    check_dependencies()
    build()


if __name__ == '__main__':
    main()
