"""Framework detection constants for lu77U-MobileSec"""

REACT_NATIVE_INDICATORS = {
    'assets/index.android.bundle': 15,
    'assets/index.bundle': 15, 
    'assets/main.jsbundle': 15,
    'libreactnativejni.so': 20,
    'libhermes.so': 20,
    'libjscexecutor.so': 15,
    'assets/node_modules': 12,
    'com.facebook.react': 18,
    'com.facebook.hermes': 18,
    'react-native': 12,
    'metro-runtime': 8,
    'jsbundle': 10,
    'ReactNative': 10,
    'RCTBridge': 12,
    'RCTRootView': 12
}

FLUTTER_INDICATORS = {
    'libflutter.so': 20,
    'libapp.so': 18,
    'flutter_assets/': 20,
    'assets/flutter_assets/': 20,
    'isolate_snapshot_data': 15,
    'vm_snapshot_data': 15,
    'kernel_blob.bin': 18,
    'io.flutter': 18,
    'flutter.embedding': 18,
    'flutter_assets': 15,
    'flutter/': 12,
    'dart.': 12,
    'FlutterActivity': 15,
    'FlutterFragment': 15,
    'MethodChannel': 10
}

KOTLIN_INDICATORS = {
    'kotlin/': 15,
    'kotlinx/': 15,
    'kotlin.Metadata': 18,
    'kotlin.jvm.internal': 12,
    'kotlin.coroutines': 12,
    '.kt': 8,
    'kotlin.': 10,
    'KotlinVersion': 10,
    'kotlin.Unit': 8,
    'kotlin.collections': 8
}

JAVA_INDICATORS = {
    'java.lang': 8,
    'java.util': 8,
    'android.app': 12,
    'android.support': 12,
    'androidx.': 15,
    '.java': 5,
    'com.android': 10,
    'android.os': 8,
    'android.content': 8,
    'android.view': 8
}

NATIVE_INDICATORS = {
    'lib/arm64-v8a/': 12,
    'lib/armeabi-v7a/': 12,
    'lib/x86/': 10,
    'lib/x86_64/': 10,
    '.so': 8,
    'jni/': 15,
    'native': 6,
    'libc++': 8,
    'liblog.so': 5,
    'libandroid.so': 5
}