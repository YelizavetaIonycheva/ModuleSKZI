LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE:= libupdsch

LOCAL_SRC_FILES := \
	algebra.c \
	gostr3411_prf.c \
	updsch.c \
	updsch_manager.c \
	#test_updsch.c \

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/ \
	$(LOCAL_PATH)/../hesh341112 \
	$(LOCAL_PATH)/../magma/include
	

LOCAL_SHARED_LIBRARIES += libmagma libhesh341112

#LOCAL_CFLAGS += -Wno-parentheses -Wno-int-to-pointer-cast -Wno-incompatible-pointer-types -Wno-shift-count-overflow
#LOCAL_CFLAGS +=	-fstack-protector -frtti -ffunction-sections -fno-exceptions -fdata-sections

LOCAL_CFLAGS += -DLOGGING_UPDSCH=0
LOCAL_LDLIBS += -llog
include $(BUILD_SHARED_LIBRARY)