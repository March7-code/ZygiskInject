#include "injector.h"

#include <chrono>
#include <cinttypes>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>

#include "../child_gating.h"
#include "../inject.h"
#include "../inject_stealth.h"
#include "../log.h"

namespace runtime {

namespace {

std::string get_process_name() {
    std::ifstream file("/proc/self/cmdline");
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

void wait_for_init(const std::string &app_name) {
    LOGI("Wait for process to complete init");

    while (get_process_name().find(app_name) == std::string::npos) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    LOGI("Process init completed");
}

void delay_start_up(uint64_t start_up_delay_ms) {
    if (start_up_delay_ms <= 0) return;

    LOGI("Waiting for configured start up delay %" PRIu64 "ms", start_up_delay_ms);

    int countdown = 0;
    uint64_t delay = start_up_delay_ms;

    for (int i = 0; i < 10 && delay > 1000; i++) {
        delay -= 1000;
        countdown++;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    for (int i = countdown; i > 0; i--) {
        LOGI("Injecting libs in %d seconds", i);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void run_injection_pipeline(target_config cfg, injector_prepare prepare) {
    inject_stealth::log_hidden_port_for_config(cfg);

    wait_for_init(cfg.app_name);

    if (cfg.child_gating.enabled) {
        enable_child_gating(cfg.child_gating);
    }

    delay_start_up(cfg.start_up_delay_ms);

    if (prepare) {
        if (!prepare(cfg)) {
            LOGW("[injector] prepare stage failed, skip injection");
            return;
        }
    }

    for (auto &lib_path : cfg.injected_libraries) {
        LOGI("Injecting %s", lib_path.c_str());
        inject_lib(lib_path, "");
    }
}

}  // namespace

void start_injection(target_config cfg, injector_prepare prepare) {
    std::thread inject_thread(run_injection_pipeline, std::move(cfg), std::move(prepare));
    inject_thread.detach();
}

}  // namespace runtime
