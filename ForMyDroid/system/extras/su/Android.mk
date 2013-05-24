LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= su.c

LOCAL_MODULE:= su

LOCAL_STATIC_LIBRARIES := libc

LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := debug tests

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/../../../external/sqlite/dist \
	$(LOCAL_PATH)/../../../external/sqlite/android 

LOCAL_SHARED_LIBRARIES := \
	libsqlite 
	
include $(BUILD_EXECUTABLE)
