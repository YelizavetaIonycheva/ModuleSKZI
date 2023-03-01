APP_PROJECT_PATH := $(call my-dir)/../../

APP_STL := c++_shared
APP_CFLAGS += -fexceptions -frtti -Os
APP_CPPFLAGS += -std=c++11

root-dir := $(APP_PROJECT_PATH)