#pragma once

#include <map>
#include <memory>
#include <string>
#include "expected.hpp"
#include "stop_source.hpp"
#include "http_codec.hpp"

struct http_client : std::enable_shared_from_this<http_client> {
    using pointer = std::shared_ptr<http_client>;

    static pointer make() {
        return std::make_shared<pointer::element_type>();
    }

    struct http_request {
        std::string method;
        std::string url;
        std::string body = {};
        string_map headers = {};
    };

    struct http_response {
        int status;
        std::string body;
        string_map headers;
    };

    struct _http_url_parser {
        std::string m_hostname;
        std::string m_scheme;
        std::string m_url;

        _http_url_parser() = default;

        _http_url_parser(std::string url) : m_url(std::move(url)) {
            // 解析 URL
            auto pos = m_url.find("://");
            if (pos == std::string::npos) {
                pos = 0;
                m_scheme = "http";
            } else {
                m_scheme = m_url.substr(0, pos);
                m_url = m_url.substr(pos + 3);
            }
            pos = m_url.find('/');
            if (pos == std::string::npos) {
                m_hostname = m_url;
                m_url = "/";
            } else {
                m_hostname = m_url.substr(0, pos);
                m_url = m_url.substr(pos);
            }
        }
    };

    struct http_connection_handler
        : std::enable_shared_from_this<http_connection_handler> {
        using pointer = std::shared_ptr<http_connection_handler>;

        static pointer make() {
            return std::make_shared<pointer::element_type>();
        }

        http_request m_request;
        http_request_writer<> m_req_writer;
        http_response_parser<> m_res_parser;
        async_file m_conn;
        callback<expected<int>, http_response const &> m_cb;
        stop_source m_stop;
        _http_url_parser m_parsed_url;
        bytes_buffer m_readbuf{1024};

        address_resolver::address_info _resolve_address(address_resolver &res) {
            std::string service = m_parsed_url.m_scheme;
            std::string name = m_parsed_url.m_hostname;
            auto colon = name.rfind(':');
            if (colon != std::string::npos) {
                service = name.substr(colon + 1);
                name = name.substr(0, colon);
            }
            return res.resolve(name, service);
        }

        void do_request(http_request request,
                        _http_url_parser const &parsed_url,
                        callback<expected<int>, http_response const &> cb,
                        stop_source stop = {}) {
            m_cb = std::move(cb);
            m_stop = stop;
            m_request = std::move(request);
            if (m_conn) {
                // fmt::println("复用现有连接");
                do_compose();
                return;
            }
            m_parsed_url = std::move(parsed_url);
            // fmt::println("连接到 {}，服务 {}，路径 {}", m_parsed_url.m_hostname, m_parsed_url.m_scheme, m_request.url);
            // "http://142857.red/" 变成
            // m_hostname = "142857.red";
            // m_scheme = "http";
            // m_request.url = "/";
            address_resolver res;
            auto addr = _resolve_address(res);
            m_conn = async_file{addr.create_socket()};
            // fmt::println("开始连接...");
            return m_conn.async_connect(
                addr,
                [self = shared_from_this()](expected<int> ret) mutable {
                    ret.expect("connect");
                    // fmt::println("连接成功...");
                    self->do_compose();
                },
                m_stop);
        }

        void do_compose() {
            m_req_writer.begin_header(m_request.method, m_request.url);
            m_req_writer.write_header("Host", m_parsed_url.m_hostname);
            m_req_writer.write_header("User-agent", "co_http");
            m_req_writer.write_header("Accept", "*/*");
            if (!m_request.body.empty()) {
                m_req_writer.write_header(
                    "Content-length", std::to_string(m_request.body.size()));
            }
            m_req_writer.end_header();
            if (!m_request.body.empty()) {
                m_req_writer.write_body(m_request.body);
            }
            http_response response;
            // fmt::println("正在写入请求...");
            return do_write(m_req_writer.buffer());
        }

        void do_write(bytes_const_view buffer) {
            return m_conn.async_write(
                buffer,
                [self = shared_from_this(), buffer](expected<size_t> ret) {
                    if (ret.error()) {
                        return self->m_cb(ret.error(), {});
                    }
                    auto n = ret.value();
                    // fmt::println("写入 {} 字节", n);

                    if (buffer.size() == n) {
                        // fmt::println("写入请求成功，开始读取");
                        self->m_req_writer.reset_state();
                        return self->do_read();
                    }
                    return self->do_write(buffer.subspan(n));
                },
                m_stop);
        }

        void do_read() {
            // 开始读取
            return m_conn.async_read(
                m_readbuf,
                [self = this->shared_from_this()](expected<size_t> ret) {
                    if (ret.error()) {
                        // fmt::println("读取出错 {}，放弃连接", strerror(-ret.error()));
                        return self->m_cb(ret.error(), {});
                    }
                    size_t n = ret.value();
                    // 如果读到 EOF，说明对面，关闭了连接
                    if (n == 0) {
                        // fmt::println("对面关闭了连接");
                        return;
                    }
                    // fmt::println("读取到了 {} 个字节: {}", n, std::string_view{self->m_readbuf.data(), n});
                    // 成功读取，则推入解析
                    self->m_res_parser.push_chunk(
                        self->m_readbuf.subspan(0, n));
                    if (!self->m_res_parser.request_finished()) {
                        return self->do_read();
                    } else {
                        return self->do_finish();
                    }
                },
                m_stop);
        }

        void do_finish() {
            if (m_stop.stop_requested()) {
                return m_cb(-ECANCELED, {});
            }

            auto response = http_response{
                m_res_parser.status(),
                std::move(m_res_parser.body()),
                std::move(m_res_parser.headers()),
            };
            m_res_parser.reset_state();
            return m_cb(0, response);
        }
    };

    std::map<std::string, http_connection_handler::pointer> m_conn_pool;

    void do_request(http_request request,
                    callback<expected<int>, http_response const &> cb,
                    stop_source stop = {}) {
        auto parsed_url = _http_url_parser{request.url};
        auto key = parsed_url.m_scheme + parsed_url.m_hostname;
        auto it = m_conn_pool.find(key);
        http_connection_handler::pointer conn;
        if (it != m_conn_pool.end()) {
            conn = it->second;
        } else {
            conn = http_connection_handler::make();
            m_conn_pool.insert({key, conn});
        }
        request.url = parsed_url.m_url;
        conn->do_request(std::move(request), std::move(parsed_url),
                         std::move(cb), stop);
    }
};
