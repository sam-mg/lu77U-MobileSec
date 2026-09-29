#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.agent.graph_tables

Purpose:
    The descriptor tables the Android code graph, the call graph and the ownership classifier all read: which package prefixes are bundled third-party SDKs, and which call targets belong to each security-relevant sink family.

Responsibilities:
    Hold VENDOR_PREFIXES and SINK_FAMILIES as plain data, with no imports from the rest of the agent package.

Dependencies:
    typing only.

Implementation notes:
    These tables used to live in code_graph, which meant ownership and call_graph had to import code_graph back while code_graph was importing them, forming an import cycle. Keeping pure data in a leaf module that imports nothing from the package is what breaks that cycle, and it keeps the three consumers reading one copy of each table so a vendor added here is treated consistently by classification, pruning and sink tagging.
"""

from typing import Dict, Tuple

VENDOR_PREFIXES: Tuple[str, ...] = (
    "Lokhttp3/", "Lokio/", "Lretrofit2/", "Lcom/squareup/", "Lcom/google/gson/",
    "Lorg/chromium/", "Lcom/fasterxml/",
    "Lio/reactivex/", "Lrx/", "Lcom/jakewharton/",
    "Lcom/appsflyer/", "Lcom/adjust/", "Lcom/mixpanel/", "Lcom/amplitude/",
    "Lcom/segment/", "Lcom/clevertap/", "Lcom/braze/", "Lcom/appboy/",
    "Lcom/onesignal/", "Lio/branch/", "Lcom/moengage/", "Lcom/netcore/",
    "Lio/sentry/", "Lcom/bugsnag/", "Lcom/crashlytics/", "Lcom/newrelic/",
    "Lcom/instabug/", "Lcom/datadog/",
    "Lcom/facebook/", "Ltwitter4j/", "Lcom/paypal/", "Lcom/stripe/",
    "Lcom/razorpay/", "Lcom/phonepe/", "Lorg/npci/",
    "Lco/hyperverge/", "Lcom/onfido/", "Lcom/jumio/", "Lcom/regula/",
    "Lcom/bumptech/", "Lcom/airbnb/", "Lcom/github/", "Lde/hdodenhof/",
    "Lcom/theartofdev/", "Lcom/scottyab/", "Lcom/journeyapps/",
    "Lorg/greenrobot/", "Lbutterknife/", "Ldagger/", "Ljavax/inject/",
    "Lcom/mikepenz/", "Lcom/nostra13/", "Lcom/tencent/", "Lcom/alibaba/",
    "Lcom/huawei/", "Lcom/xiaomi/", "Lcom/miui/",
    "Lcom/facebook/stetho/", "Lcom/facebook/flipper/", "Lleakcanary/",
    "Lcom/squareup/leakcanary/",
)

SINK_FAMILIES: Dict[str, Tuple[str, ...]] = {
    "sql": ("->execSQL", "->rawQuery", "SQLiteDatabase;->query", "->compileStatement"),
    "prefs": ("SharedPreferences", "getDefaultSharedPreferences"),
    "logging": ("Landroid/util/Log;",),
    "crypto": ("Ljavax/crypto/Cipher;", "MessageDigest;", "SecretKeySpec",
               "IvParameterSpec", "Ljava/security/"),
    "webview": ("->loadUrl", "->loadData", "addJavascriptInterface",
                "setJavaScriptEnabled", "->evaluateJavascript", "setAllowFileAccess"),
    "runtime": ("Ljava/lang/Runtime;->exec", "ProcessBuilder"),
    "storage": ("getExternalStorage", "->openFileOutput", "MODE_WORLD",
                "getExternalFilesDir", "Landroid/os/Environment;"),
    "uri": ("->getLastPathSegment", "->getQueryParameter"),
    "native": ("Ljava/lang/System;->loadLibrary", "Ljava/lang/System;->load"),
    "ipc": ("->getStringExtra", "->getData", "->getSerializableExtra",
            "->getParcelableExtra"),
    "display": ("Landroid/widget/TextView;->setText",),
}
