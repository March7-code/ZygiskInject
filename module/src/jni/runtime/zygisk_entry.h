#ifndef ZYGISKFRIDA_RUNTIME_ZYGISK_ENTRY_H
#define ZYGISKFRIDA_RUNTIME_ZYGISK_ENTRY_H

#include <jni.h>

#include <map>
#include <string>

#include "companion_client.h"
#include "../zygisk.h"

namespace runtime {

class zygisk_entry {
 public:
    void on_load(zygisk::Api *api, JNIEnv *env);
    void pre_app_specialize(zygisk::AppSpecializeArgs *args);
    void post_app_specialize(const zygisk::AppSpecializeArgs *args);

 private:
    zygisk::Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;
    std::string app_name_;
    companion_session companion_session_;
    std::map<std::string, std::string> prepared_tmpfile_paths_;
    std::string prepared_gadget_connect_override_address_;
    bool prepared_companion_success_ = false;
};

}  // namespace runtime

#endif  // ZYGISKFRIDA_RUNTIME_ZYGISK_ENTRY_H
