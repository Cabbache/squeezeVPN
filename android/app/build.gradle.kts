plugins {
    id("com.android.application")
}

android {
    namespace = "app.svpn"
    compileSdk = 36
    defaultConfig {
        applicationId = "app.svpn"
        minSdk = 28 // javax.crypto ChaCha20-Poly1305
        targetSdk = 36
        versionCode = 1
        versionName = "0.1"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions { unitTests.isReturnDefaultValues = true }
}

dependencies {
    implementation(project(":tunnel")) // fork of com.wireguard.android:tunnel 1.0.20260102 (tunnel/NOTICE)
    implementation("com.github.luben:zstd-jni:1.5.7-6@aar")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    // the scanner uses androidx.core (ContextCompat) for the camera permission but does not declare it
    implementation("androidx.core:core:1.13.1")
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.github.luben:zstd-jni:1.5.7-6") // desktop natives for JVM tests
}
