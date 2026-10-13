TARGET := iphone:clang:latest:17.0
ARCHS = arm64
INSTALL_TARGET_PROCESSES = BeReal

include $(THEOS)/makefiles/common.mk
TWEAK_NAME = CameraRollPrototype
CameraRollPrototype_FILES = Tweak.m
CameraRollPrototype_CFLAGS = -fobjc-arc
CameraRollPrototype_FRAMEWORKS = UIKit PhotosUI UniformTypeIdentifiers
include $(THEOS_MAKE_PATH)/tweak.mk
