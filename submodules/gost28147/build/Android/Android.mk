LOCAL_PATH:= $(call my-dir)/../../
include $(CLEAR_VARS)

LOCAL_MODULE:= libgost28147

LOCAL_SRC_FILES := \
	Gost28147.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include

LOCAL_CFLAGS +=	-frtti -Wno-pointer-sign

include $(BUILD_SHARED_LIBRARY)