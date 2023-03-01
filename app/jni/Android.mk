
#liblicense
include $(root-dir)/submodules/Signature/Android.mk

BUILD_MAGMA := true
ifeq ($(BUILD_MAGMA), true)
    #libmagma
    include $(root-dir)/submodules/magma/build/Android/Android.mk
else
    #libgost28147
    include $(root-dir)/submodules/gost28147/build/Android/Android.mk
endif

#libcryptutils
include $(root-dir)/submodules/CryptUtils/Android.mk

#libvpnclient
include $(root-dir)/submodules/VpnClient/Android.mk
