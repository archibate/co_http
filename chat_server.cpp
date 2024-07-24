#include "io_context.hpp"
#include "http_server.hpp"
#include "file_utils.hpp"
#include "reflect.hpp"
#include <unistd.h>

using namespace std::chrono_literals;

// C++ 全栈，聊天服务器
// 1. AJAX，轮询与长轮询 (OK)
// 2. WebSocket，JSON 消息

struct Message {
    std::string user;
    std::string content;

    REFLECT(user, content);
};

struct RecvParams {
    uint32_t first;

    REFLECT(first);
};

std::vector<Message> messages;
stop_source recv_timeout_stop = stop_source::make();

void server() {
    io_context ctx;
    chdir("../static");
    messages.push_back({"系统", "你好，欢迎来到小彭聊天室"});
    auto server = http_server::make();
    server->get_router().route("/", [](http_server::http_request &request) {
        std::string response = file_get_content("index.html");
        request.write_response(200, response, "text/html");
    });
    server->get_router().route("/favicon.ico", [](http_server::http_request &request) {
        std::string response = file_get_content("favicon.ico");
        request.write_response(200, response, "image/x-icon");
    });
    server->get_router().route("/send", [](http_server::http_request &request) {
        // fmt::println("/send 收到了 {}", request.body);
        messages.push_back(reflect::json_decode<Message>(request.body));
        recv_timeout_stop.request_stop();
        recv_timeout_stop = stop_source::make();
        request.write_response(200, "OK");
    });
    server->get_router().route("/recv", [](http_server::http_request &request) {
        auto params = reflect::json_decode<RecvParams>(request.body);
        if (messages.size() > params.first) {
            std::vector<Message> submessages(messages.begin() + params.first,
                                             messages.end());
            std::string response = reflect::json_encode(submessages);
            // fmt::println("/recv 立即返回 {}", response);
            request.write_response(200, response);
        } else {
            io_context::get().set_timeout(3s, [&request, params] {
                std::vector<Message> submessages;
                if (messages.size() > params.first) {
                    submessages.assign(messages.begin() + params.first,
                                       messages.end());
                }
                std::string response = reflect::json_encode(submessages);
                // fmt::println("/recv 延迟返回 {}", response);
                request.write_response(200, response);
            }, recv_timeout_stop);
        }
    });
    // fmt::println("正在监听：http://0.0.0.0:8080");
    server->do_start("0.0.0.0", "8080");

    ctx.join();
}

int main() {
    // try {
        server();
    // } catch (std::system_error const &e) {
    //     fmt::println("{} ({}/{})", e.what(), e.code().category().name(),
    //                  e.code().value());
    // }
    return 0;
}
