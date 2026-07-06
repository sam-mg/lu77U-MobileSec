#!/usr/bin/env python3
"""Constants that are used in lu77U-MobileSec"""

DEFAULT_STRING_PREFIXES = [
    "android.",
    "com.android.",
    "androidx.",
    "com.google.",
    "java.",
    "javax.",
    "org.apache.",
    "kotlin.",
    "io.flutter.",
    'abc_', 
    'androidx_', 
    'appbar_', 
    'bottom_sheet_', 
    'bottomsheet_',
    'character_counter_', 
    'clear_text_', 
    'error_', 
    'exposed_dropdown_',
    'fab_', 
    'hide_bottom_', 
    'icon_content_', 
    'item_view_', 
    'm3_',
    'material_', 
    'mtrl_', 
    'password_toggle_', 
    'path_password_',
    'search_menu_', 
    'searchbar_', 
    'searchview_', 
    'side_sheet_', 
    'status_bar_'
]

DEFAULT_STRING_EXACT_MATCHES = {
    "true", 
    "false", 
    "null", 
    "undefined", 
    "NaN", 
    "Infinity",
    "onCreate", 
    "onDestroy", 
    "onPause", 
    "onResume", 
    "onStart", 
    "onStop",
    "main", 
    "test", 
    "debug", 
    "release", 
    "profile",
    'search_menu_title', 
    'submit'
}

FRAMEWORK_VALIDATION_PATTERNS = [
    r'^android\.',
    r'^com\.android\.',
    r'^androidx\.',
    r'^com\.google\.',
    r'^\$\{.*\}$',
    r'^@\w+/',
    r'^\d+$',
    r'^[a-f0-9]{8,}$',
]

RESPONSE_PARSER_PATTERNS = [
    (r'vulnerability_type["\s:]+([^",\n}]+)', 'vulnerability_type'),
    (r'file["\s:]+([^",\n}]+)', 'file'),
    (r'line_number["\s:]+(\d+)', 'line_number'),
    (r'code_snippet["\s:]+(.+?)(?=",|\})', 'code_snippet'),
    (r'description["\s:]+([^",\n}]+)', 'description'),
    (r'severity["\s:]+([^",\n}]+)', 'severity')
]

ANDROGUARD_LOGGERS = [
    'androguard',
    'androguard.misc', 
    'androguard.core',
    'androguard.core.apk',
    'androguard.core.axml',
    'androguard.decompiler'
]

DANGEROUS_PERMISSIONS = [
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.CAMERA',
    'android.permission.RECORD_AUDIO',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.READ_CONTACTS',
    'android.permission.WRITE_CONTACTS',
    'android.permission.READ_SMS',
    'android.permission.SEND_SMS',
    'android.permission.READ_PHONE_STATE',
    'android.permission.CALL_PHONE',
    'android.permission.INSTALL_PACKAGES',
    'android.permission.SYSTEM_ALERT_WINDOW',
    'android.permission.WRITE_SETTINGS'
]

PERMISSION_PATTERNS = [
    r'<uses-permission\s+android:name="([^"]+)"',
    r'android:permission="([^"]+)"',
    r'E: uses-permission.*name="([^"]+)"',
]

FRAMEWORK_FLUTTER = "Flutter"
FRAMEWORK_REACT_NATIVE = "React Native"
FRAMEWORK_CORDOVA = "Cordova"
FRAMEWORK_XAMARIN = "Xamarin"
FRAMEWORK_UNITY = "Unity"
FRAMEWORK_UNREAL = "Unreal Engine"
FRAMEWORK_LIBGDX = "LibGDX"
FRAMEWORK_EXPO = "Expo"
FRAMEWORK_KONY = "Kony"
FRAMEWORK_JAVA = "Java"
FRAMEWORK_KOTLIN = "Kotlin"
FRAMEWORK_HYBRID = "Hybrid"

TECH_DETECTION_MAP = {
    FRAMEWORK_FLUTTER: [
        "libflutter.so",
        "assets/flutter_assets/",
        "isolate_snapshot"
    ],
    FRAMEWORK_REACT_NATIVE: [
        "libreactnativejni.so",
        "assets/index.android.bundle",
        "index.bundle",
        "libhermes.so",
        "libjsi.so"
    ],
    FRAMEWORK_CORDOVA: [
        "assets/www/index.html",
        "assets/www/cordova.js",
        "assets/www/cordova_plugins.js"
    ],
    FRAMEWORK_XAMARIN: [
        "assemblies/Sikur.Monodroid.dll",
        "assemblies/Sikur.dll",
        "assemblies/Xamarin.Mobile.dll",
        "assemblies/mscorlib.dll",
        "libmonodroid.so",
        "libmonosgen-2.0.so",
    ],
    FRAMEWORK_UNITY: [
        "libunity.so",
        "assets/bin/Data/Managed/UnityEngine.dll",
        "assets/bin/Data/Managed/UnityEditor.dll"
    ],
    FRAMEWORK_UNREAL: [
        "libUE4.so",
        "assets/Unreal/UE4Game/Manifest.xml"
    ],
    FRAMEWORK_LIBGDX: [
        "libgdx.so",
        "assets/libgdx/lwjgl.so",
        "assets/libgdx.jar"
    ],
    FRAMEWORK_EXPO: [
        "assets/shell-app.bundle",
        "assets/expo-manifest.json"
    ],
    FRAMEWORK_KONY: [
        "assets/kony.js",
        "assets/konyframework.js",
        "assets/KonyApps/config.json"
    ],
}

CORDOVA_APK_INDICATORS = [
    'assets/www/index.html',
    'assets/www/cordova.js',
    'assets/www/cordova_plugins.js',
    'res/xml/config.xml'
]

CORDOVA_APK_CLASS_INDICATORS = [
    'org/apache/cordova/',
    'org/apache/cordova/engine/SystemWebViewEngine',
    'org/apache/cordova/PluginManager',
    'org/apache/cordova/CordovaWebView',
    'org/apache/cordova/ConfigXmlParser'
]

CORDOVA_PROJECT_INDICATORS = [
    'config.xml',
    'www/index.html',
    'www/cordova.js',
    'platforms/android',
    'plugins'
]

KONY_APK_INDICATORS = [
    'assets/kony.js',
    'assets/konyframework.js',
    'assets/KonyApps/config.json'
]

KONY_PROJECT_INDICATORS = [
    'kony',
    'KonyApps',
    'modules/kony'
]

KONY_PROJECT_FILES = [
    'kony.properties',
    'projectProperties.json',
    'projectsettings.json'
]

XAMARIN_APK_INDICATORS = [
    'assemblies/Sikur.Monodroid.dll',
    'assemblies/Sikur.dll',
    'assemblies/Xamarin.Mobile.dll',
    'assemblies/mscorlib.dll',
    'libmonodroid.so',
    'libmonosgen-2.0.so',
    'libxamarin-app.so'
]

XAMARIN_PROJECT_FILES = [
    '*.csproj',
    '*.sln',
    'Resources/',
    'Properties/AndroidManifest.xml'
]

XAMARIN_PROJECT_EXTENSIONS = [
    '.csproj',
    '.sln',
    '.xaml'
]

UNITY_APK_INDICATORS = [
    'libunity.so',
    'libmain.so',
    'assets/bin/Data/Managed/UnityEngine.dll',
    'assets/bin/Data/Managed/UnityEditor.dll',
    'assets/bin/Data/level0',
    'assets/bin/Data/sharedassets0.assets'
]

UNITY_PROJECT_INDICATORS = [
    'Assets/',
    'ProjectSettings/',
    'Library/'
]

UNITY_PROJECT_FILES = [
    'ProjectSettings.asset',
    'ProjectVersion.txt'
]

UNREAL_APK_INDICATORS = [
    'libUE4.so',
    'libUnreal.so',
    'assets/Unreal/UE4Game/Manifest.xml',
    'assets/Unreal/'
]

UNREAL_PROJECT_INDICATORS = [
    'Config/',
    'Content/',
    'Source/',
    '*.uproject'
]

LIBGDX_APK_INDICATORS = [
    "libgdx.so",
    "assets/libgdx/lwjgl.so",
    "assets/libgdx.jar"
]

LIBGDX_PROJECT_INDICATORS = [
    "android/",
    "core/",
    "desktop/",
    "ios/"
]

LIBGDX_GRADLE_KEYWORDS = [
    "com.badlogicgames.gdx",
    "gdxVersion",
    "libgdx"
]

VALID_AI_MODELS = [
    "deepseek-v3.1:671b-cloud",
    "gpt-oss:20b-cloud",
    "gpt-oss:120b-cloud",
    "kimi-k2:1t-cloud",
    "qwen3-coder:480b-cloud",
    "glm-4.6:cloud",
    "minimax-m2:cloud"
]
