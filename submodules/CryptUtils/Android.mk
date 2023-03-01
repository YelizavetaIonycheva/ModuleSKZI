LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE:= libcryptutils

LOCAL_SRC_FILES := \
	jniCryptUtils.c \
	crc32.c \
	Hesh341112.c \
	CryptUtils.c \

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/

ifeq ($(BUILD_MAGMA), true)
	LOCAL_SHARED_LIBRARIES :=  libmagma
	
	LOCAL_C_INCLUDES += $(LOCAL_PATH)/../magma/include
		
	LOCAL_CFLAGS += -DCRYPT_MAGMA
else
	LOCAL_SHARED_LIBRARIES :=  libgost28147
	
	LOCAL_C_INCLUDES += $(LOCAL_PATH)/../gost28147
		
	LOCAL_CFLAGS += -DCRYPT_GOST28147
endif

//LOCAL_CFLAGS += -Wno-parentheses -Wno-int-to-pointer-cast -Wno-incompatible-pointer-types -Wno-shift-count-overflow
//LOCAL_CFLAGS +=	-fstack-protector -frtti -ffunction-sections -fno-exceptions -fdata-sections

include $(BUILD_SHARED_LIBRARY)