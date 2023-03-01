LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE:= libsignature

LOCAL_SRC_FILES += \
	ecp_341012.c \
	ecp_algebra.c \
	hesh_341112.c \
	signature.c \
	signature_jni.c 

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/

#LOCAL_CFLAGS +=	-fstack-protector -frtti -ffunction-sections -fno-exceptions -fvisibility=hidden -fdata-sections
#LOCAL_CFLAGS +=	-fstack-protector -frtti -ffunction-sections -fno-exceptions -fvisibility=hidden -fdata-sections -Os -rdynamic
LOCAL_CFLAGS +=	-fstack-protector -frtti -ffunction-sections -fno-exceptions -fdata-sections


#LOCAL_LDFLAGS += -Wl,--gc-sections


include $(BUILD_SHARED_LIBRARY)