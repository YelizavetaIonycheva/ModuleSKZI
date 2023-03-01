LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE:= libvpnclient

LOCAL_SRC_FILES := \
	check_IKEv2.c \
	ESP.c \
	IKEv2.c \
	vpnClient.c \
	F.c \
	jniVnpClient.c \
	crc32.c \
	Hesh341112.c \
	MMT.c \
	updsch/algebra.c \
	updsch/gostr3411_prf.c \
	updsch/updsch.c \
	updsch/updsch_manager.c \
	updsch/test_updsch.c \
	keyservice/key.c \
	skn/skn.c \
	nonce.c

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/ \
	$(LOCAL_PATH)/updsch \
	$(LOCAL_PATH)/skn \
	$(LOCAL_PATH)/keyservice

ifeq ($(BUILD_MAGMA), true)
	LOCAL_SHARED_LIBRARIES :=  libmagma
	
	LOCAL_C_INCLUDES += $(LOCAL_PATH)/../magma/include
		
	LOCAL_CFLAGS += -DCRYPT_MAGMA
else
	LOCAL_SHARED_LIBRARIES :=  libgost28147
	
	LOCAL_C_INCLUDES += $(LOCAL_PATH)/../gost28147
		
	LOCAL_CFLAGS += -DCRYPT_GOST28147
endif

LOCAL_CFLAGS += -DNO_TSI
#LOCAL_CFLAGS += -Wno-parentheses -Wno-int-to-pointer-cast -Wno-incompatible-pointer-types -Wno-shift-count-overflow
LOCAL_CFLAGS +=	-fstack-protector -frtti -ffunction-sections -fno-exceptions -fdata-sections

LOCAL_CFLAGS += -DLOGGING_UPDSCH=0
LOCAL_LDLIBS += -llog
include $(BUILD_SHARED_LIBRARY)