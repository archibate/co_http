#include "io_context.hpp"
#include "http_server.hpp"

void server() {
    io_context ctx;
    auto server = http_server::make();
    server->get_router().route("/", [](http_server::http_request &request) {
        std::string response;
        if (request.body.empty()) {
            response = "你好，你的请求正文为空哦";
        } else {
            response = fmt::format("你好，你的请求是: [{}]，共 {} 字节",
                                   request.body, request.body.size());
        }
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
