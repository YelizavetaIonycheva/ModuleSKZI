
#liblicense
include $(app-root-dir)/submodules/Signature/Android.mk

BUILD_MAGMA := true
ifeq ($(BUILD_MAGMA), true)
    #libmagma
    include $(app-root-dir)/submodules/magma/build/Android/Android.mk
else
    #libgost28147
    include $(app-root-dir)/submodules/gost28147/build/Android/Android.mk
endif

#libhesh341112
include $(app-root-dir)/submodules/hesh341112/Android.mk

#libupdsch
include $(app-root-dir)/submodules/updsch/Android.mk

#libcryptutils
include $(app-root-dir)/submodules/CryptUtils/Android.mk

#libvpnclient
include $(app-root-dir)/submodules/VpnClient/Android.mk
