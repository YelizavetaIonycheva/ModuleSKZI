LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE:= libhesh341112

LOCAL_SRC_FILES := \
	Hesh341112.c \

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/ \

#LOCAL_CFLAGS += -Wno-parentheses -Wno-int-to-pointer-cast -Wno-incompatible-pointer-types -Wno-shift-count-overflow
#LOCAL_CFLAGS +=	-fstack-protector -frtti -ffunction-sections -fno-exceptions -fdata-sections
#LOCAL_LDLIBS += -llog

include $(BUILD_SHARED_LIBRARY)