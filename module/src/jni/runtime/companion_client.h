#ifndef ZYGISKFRIDA_RUNTIME_COMPANION_CLIENT_H
#define ZYGISKFRIDA_RUNTIME_COMPANION_CLIENT_H

#include <map>
#include <string>

#include "../config.h"

namespace zygisk {
struct Api;
}  // namespace zygisk

namespace runtime {

struct companion_session {
    int fd = -1;
    std::string companion_json;
};

// Open a companion session in preAppSpecialize and fetch config json.
// The returned fd stays open and can be used later to continue protocol
// (library materialization / unix proxy / tracer request).
bool open_companion_session(zygisk::Api *api,
                            const std::string &app_name,
                            companion_session *out);

// Continue companion protocol (step 2/3/4) and close session:
// - request tmp copies for injected libraries
// - optionally request unix proxy
// - optionally request tracer launch (request_tracer=true)
//
// Returns true when protocol completes (individual library copy failures
// are still reported in logs and skipped).
bool finalize_companion_for_injection(companion_session *session,
                                      const target_config &cfg,
                                      std::map<std::string, std::string> *tmpfile_paths,
                                      std::string *gadget_connect_override_address,
                                      bool request_tracer = true);

// Launch tracer immediately via a separate companion connection.
// This is used to keep tracer at the earliest stage while deferring
// SO materialization/injection until after delay.
bool launch_tracer_now(zygisk::Api *api,
                       const std::string &app_name,
                       const target_config &cfg);

// Close a session fd if still open.
void close_companion_session(companion_session *session);

}  // namespace runtime

#endif  // ZYGISKFRIDA_RUNTIME_COMPANION_CLIENT_H
