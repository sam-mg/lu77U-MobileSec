#!/usr/bin/env python3
"""
Framework detection constants for lu77U-MobileSec
"""

# React Native detection indicators
REACT_NATIVE_INDICATORS = [
    'assets/index.android.bundle',
    'assets/index.bundle', 
    'assets/main.jsbundle',
    'libreactnativejni.so',
    'libhermes.so',
    'libjscexecutor.so',
    'assets/node_modules',
    'com.facebook.react',
    'com.facebook.hermes'
]

# Flutter detection indicators
FLUTTER_INDICATORS = [
    'libflutter.so',
    'libapp.so',
    'flutter_assets/',
    'assets/flutter_assets/',
    'isolate_snapshot_data',
    'vm_snapshot_data',
    'kernel_blob.bin',
    'io.flutter',
    'flutter.embedding'
]
