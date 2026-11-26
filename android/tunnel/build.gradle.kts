// Fork of wireguard-android's `tunnel` module (tag 1.0.20260102, Apache-2.0, see COPYING and NOTICE).
plugins {
    id("com.android.library")
}

android {
    namespace = "com.wireguard.android.tunnel"
    compileSdk = 36
    ndkVersion = "30.0.16248370"
    defaultConfig {
        minSdk = 28
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    externalNativeBuild {
        cmake {
            path("tools/CMakeLists.txt")
            version = "4.1.2"
        }
    }
    buildTypes {
        all {
            externalNativeBuild {
                cmake {
                    targets("libwg-go.so")
                    arguments("-DGRADLE_USER_HOME=${project.gradle.gradleUserHomeDir}")
                    arguments("-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON")
                    // the app's id: wireguard-go's control socket lives in its cache folder
                    arguments("-DANDROID_PACKAGE_NAME=app.svpn")
                }
            }
        }
    }
}

dependencies {
    implementation("androidx.annotation:annotation:1.9.1")
    implementation("androidx.collection:collection:1.5.0")
    compileOnly("com.google.code.findbugs:jsr305:3.0.2")
}
