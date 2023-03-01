LOCAL_PATH:= $(call my-dir)/../../
include $(CLEAR_VARS)

LOCAL_MODULE:= libmagma

LOCAL_SRC_FILES := \
	src/cypher.c \
	src/magma.c \
	src/tests.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include

LOCAL_CFLAGS +=	-frtti -Wno-pointer-sign

include $(BUILD_SHARED_LIBRARY)