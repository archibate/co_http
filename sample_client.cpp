#include "io_context.hpp"
#include "http_client.hpp"

void client() {
    io_context ctx;
    auto client = http_client::make();

    client->do_request(
        {"GET", "http://142857.red"},
        [client](expected<int> ret,
                 http_client::http_response const &response) {
            ret.expect("http://142857.red");
            // fmt::println("{}", response.body);

            io_context::get().set_timeout(std::chrono::seconds(1), [client] {
                client->do_request(
                    {"GET", "http://142857.red"},
                    [client](expected<int> ret,
                             http_client::http_response const &response) {
                        ret.expect("http://142857.red");
                        // fmt::println("{}", response.body);
                    });
            });
        });

    ctx.join();
}

int main() {
    // try {
        client();
    // } catch (std::system_error const &e) {
    //     fmt::println("{} ({}/{})", e.what(), e.code().category().name(),
    //                  e.code().value());
    // }
    return 0;
}
