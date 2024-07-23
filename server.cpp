#include "io_context.hpp"
#include "http_server.hpp"
#include "http_client.hpp"

void server() {
    io_context ctx;
    auto acceptor = http_server::make();
    acceptor->get_router().route("/", [](http_server::http_request &request) {
        std::string response;
        if (request.body.empty()) {
            response = "你好，你的请求正文为空哦";
        } else {
            response = fmt::format("你好，你的请求是: [{}]，共 {} 字节",
                                   request.body, request.body.size());
        }
        request.write_response(200, response);
    });
    acceptor->do_start("127.0.0.1", "8080");

    ctx.join();
}

void client() {
    io_context ctx;
    auto client = http_client::make();

    client->do_request(
        {"GET", "http://142857.red"},
        [client](expected<int> ret,
                 http_client::http_response const &response) {
            ret.expect("http://142857.red");
            fmt::println("{}", response.body);

            io_context::get().set_timeout(std::chrono::seconds(1), [client] {
                client->do_request(
                    {"GET", "http://142857.red"},
                    [client](expected<int> ret,
                             http_client::http_response const &response) {
                        ret.expect("http://142857.red");
                        fmt::println("{}", response.body);
                    });
            });
        });

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
