#include "io_context.hpp"
#include "http_server.hpp"

// C++ 全栈，聊天服务器
// 1. AJAX，轮询与长轮询
// 2. WebSocket，JSON 消息

void server() {
    io_context ctx;
    auto server = http_server::make();
    server->get_router().route("/", [](http_server::http_request &request) {
        std::string response = "你好，世界";
        request.write_response(200, response);
    });
    server->do_start("127.0.0.1", "8080");

    ctx.join();
}

int main() {
    try {
        server();
    } catch (std::system_error const &e) {
        fmt::println("{} ({}/{})", e.what(), e.code().category().name(),
                     e.code().value());
    }
    return 0;
}
