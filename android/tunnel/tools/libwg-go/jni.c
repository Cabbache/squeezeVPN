/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2017-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct go_string { const char *str; long n; };
extern int wgTurnOn(struct go_string ifname, int tun_fd, struct go_string settings);
extern void wgTurnOff(int handle);
extern int wgGetSocketV4(int handle);
extern int wgGetSocketV6(int handle);
extern char *wgGetConfig(int handle);
extern char *wgVersion();

/* squeezeVPN: Go asks GoBackend.plainFlow() about each new connection (see mark/). */
static JavaVM *svpn_vm;
static jclass svpn_backend;
static jmethodID svpn_plain_flow;

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
	JNIEnv *env;
	jclass c;

	if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK)
		return JNI_ERR;
	svpn_vm = vm;
	c = (*env)->FindClass(env, "com/wireguard/android/backend/GoBackend");
	if (c) {
		svpn_backend = (*env)->NewGlobalRef(env, c);
		svpn_plain_flow = (*env)->GetStaticMethodID(env, c, "plainFlow", "(IIIII)Z");
	}
	if ((*env)->ExceptionCheck(env))
		(*env)->ExceptionClear(env);
	return JNI_VERSION_1_6;
}

int svpn_plain(int proto, uint32_t src, uint32_t dst, int sport, int dport)
{
	JNIEnv *env;
	int attached = 0, ret;

	if (!svpn_vm || !svpn_backend || !svpn_plain_flow)
		return 0;
	if ((*svpn_vm)->GetEnv(svpn_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*svpn_vm)->AttachCurrentThread(svpn_vm, &env, NULL) != JNI_OK)
			return 0;
		attached = 1;
	}
	ret = (*env)->CallStaticBooleanMethod(env, svpn_backend, svpn_plain_flow, proto, (jint)src, (jint)dst, sport, dport);
	if ((*env)->ExceptionCheck(env)) {
		(*env)->ExceptionClear(env);
		ret = 0;
	}
	if (attached)
		(*svpn_vm)->DetachCurrentThread(svpn_vm);
	return ret;
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOn(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings)
{
	const char *ifname_str = (*env)->GetStringUTFChars(env, ifname, 0);
	size_t ifname_len = (*env)->GetStringUTFLength(env, ifname);
	const char *settings_str = (*env)->GetStringUTFChars(env, settings, 0);
	size_t settings_len = (*env)->GetStringUTFLength(env, settings);
	int ret = wgTurnOn((struct go_string){
		.str = ifname_str,
		.n = ifname_len
	}, tun_fd, (struct go_string){
		.str = settings_str,
		.n = settings_len
	});
	(*env)->ReleaseStringUTFChars(env, ifname, ifname_str);
	(*env)->ReleaseStringUTFChars(env, settings, settings_str);
	return ret;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOff(JNIEnv *env, jclass c, jint handle)
{
	wgTurnOff(handle);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetSocketV4(JNIEnv *env, jclass c, jint handle)
{
	return wgGetSocketV4(handle);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetSocketV6(JNIEnv *env, jclass c, jint handle)
{
	return wgGetSocketV6(handle);
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetConfig(JNIEnv *env, jclass c, jint handle)
{
	jstring ret;
	char *config = wgGetConfig(handle);
	if (!config)
		return NULL;
	ret = (*env)->NewStringUTF(env, config);
	free(config);
	return ret;
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_GoBackend_wgVersion(JNIEnv *env, jclass c)
{
	jstring ret;
	char *version = wgVersion();
	if (!version)
		return NULL;
	ret = (*env)->NewStringUTF(env, version);
	free(version);
	return ret;
}
