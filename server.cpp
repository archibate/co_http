#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cassert>
#include <chrono>
#include <fcntl.h>
#include <fmt/format.h>
#include <map>
#include <netdb.h>
#include <stdexcept>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <system_error>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

template <class T>
struct [[nodiscard]] expected {
    std::make_signed_t<T> m_res;

    expected() = default;

    expected(std::make_signed_t<T> res) noexcept : m_res(res) {}

    int error() const noexcept {
        if (m_res < 0) {
            return m_res;
        }
        return 0;
    }

    bool is_error(int err) const noexcept {
        return m_res == -err;
    }

    std::error_code error_code() const noexcept {
        if (m_res < 0) {
            return std::error_code(-m_res, std::system_category());
        }
        return std::error_code();
    }

    T expect(char const *what) const {
        if (m_res < 0) {
            auto ec = error_code();
            fmt::println(stderr, "{}: {}", what, ec.message());
            throw std::system_error(ec, what);
        }
        return m_res;
    }

    T value() const {
        if (m_res < 0) {
            auto ec = error_code();
            fmt::println(stderr, "{}", ec.message());
            throw std::system_error(ec);
        }
        // assert(m_res >= 0);
        return m_res;
    }

    T raw_value() const {
        return m_res;
    }
};

template <class U, class T>
expected<U> convert_error(T res) {
    if (res == -1) {
        return -errno;
    }
    return res;
}

template <int = 0, class T>
expected<T> convert_error(T res) {
    if (res == -1) {
        return -errno;
    }
    return res;
}

// [[noreturn]] void _throw_system_error(const char *what) {
//     auto ec = std::error_code(errno, std::system_category());
//     fmt::println(stderr, "{}: {} ({}.{})", what, ec.message(),
//     ec.category().name(), ec.value()); throw std::system_error(ec, what);
// }
//
// template <int Except = 0, class T>
// T check_error(const char *what, T res) {
//     if (res == -1) {
//         if constexpr (Except != 0) {
//             if (errno == Except) {
//                 return -1;
//             }
//         }
//         _throw_system_error(what);
//     }
//     return res;
// }

// #define SOURCE_INFO_IMPL_2(file, line) "In " file ":" #line ": "
// #define SOURCE_INFO_IMPL(file, line) SOURCE_INFO_IMPL_2(file, line)
// #define SOURCE_INFO(...) SOURCE_INFO_IMPL(__FILE__, __LINE__) __VA_ARGS__
// #define CHECK_CALL_EXCEPT(except, func, ...)
// check_error<except>(SOURCE_INFO() #func, func(__VA_ARGS__)) #define
// CHECK_CALL(func, ...) check_error(SOURCE_INFO(#func), func(__VA_ARGS__))

std::error_category const &gai_category() {
    static struct final : std::error_category {
        char const *name() const noexcept override {
            return "getaddrinfo";
        }

        std::string message(int err) const override {
            return gai_strerror(err);
        }
    } instance;

    return instance;
}

struct no_move {
    no_move() = default;
    no_move(no_move &&) = delete;
    no_move &operator=(no_move &&) = delete;
    no_move(no_move const &) = delete;
    no_move &operator=(no_move const &) = delete;
};

using string_map = std::map<std::string, std::string>;

struct bytes_const_view {
    char const *m_data;
    size_t m_size;

    char const *data() const noexcept {
        return m_data;
    }

    size_t size() const noexcept {
        return m_size;
    }

    char const *begin() const noexcept {
        return data();
    }

    char const *end() const noexcept {
        return data() + size();
    }

    bytes_const_view subspan(size_t start,
                             size_t len = static_cast<size_t>(-1)) const {
        if (start > size()) {
            throw std::out_of_range("bytes_const_view::subspan");
        }
        if (len > size() - start) {
            len = size() - start;
        }
        return {data() + start, len};
    }

    operator std::string_view() const noexcept {
        return std::string_view{data(), size()};
    }
};

struct bytes_view {
    char *m_data;
    size_t m_size;

    char *data() const noexcept {
        return m_data;
    }

    size_t size() const noexcept {
        return m_size;
    }

    char *begin() const noexcept {
        return data();
    }

    char *end() const noexcept {
        return data() + size();
    }

    bytes_view subspan(size_t start, size_t len) const {
        if (start > size()) {
            throw std::out_of_range("bytes_view::subspan");
        }
        if (len > size() - start) {
            len = size() - start;
        }
        return {data() + start, len};
    }

    operator bytes_const_view() const noexcept {
        return bytes_const_view{data(), size()};
    }

    operator std::string_view() const noexcept {
        return std::string_view{data(), size()};
    }
};

struct bytes_buffer {
    std::vector<char> m_data;

    bytes_buffer() = default;
    bytes_buffer(bytes_buffer &&) = default;
    bytes_buffer &operator=(bytes_buffer &&) = default;
    explicit bytes_buffer(bytes_buffer const &) = default;

    explicit bytes_buffer(size_t n) : m_data(n) {}

    char const *data() const noexcept {
        return m_data.data();
    }

    char *data() noexcept {
        return m_data.data();
    }

    size_t size() const noexcept {
        return m_data.size();
    }

    char const *begin() const noexcept {
        return data();
    }

    char *begin() noexcept {
        return data();
    }

    char const *end() const noexcept {
        return data() + size();
    }

    char *end() noexcept {
        return data() + size();
    }

    bytes_const_view subspan(size_t start, size_t len) const {
        return operator bytes_const_view().subspan(start, len);
    }

    bytes_view subspan(size_t start, size_t len) {
        return operator bytes_view().subspan(start, len);
    }

    operator bytes_const_view() const noexcept {
        return bytes_const_view{m_data.data(), m_data.size()};
    }

    operator bytes_view() noexcept {
        return bytes_view{m_data.data(), m_data.size()};
    }

    operator std::string_view() const noexcept {
        return std::string_view{m_data.data(), m_data.size()};
    }

    void append(bytes_const_view chunk) {
        m_data.insert(m_data.end(), chunk.begin(), chunk.end());
    }

    void append(std::string_view chunk) {
        m_data.insert(m_data.end(), chunk.begin(), chunk.end());
    }

    template <size_t N>
    void append_literial(char const (&literial)[N]) {
        append(std::string_view{literial, N - 1});
    }

    void clear() {
        m_data.clear();
    }

    void resize(size_t n) {
        m_data.resize(n);
    }

    void reserve(size_t n) {
        m_data.reserve(n);
    }
};

template <size_t N>
struct static_bytes_buffer {
    std::array<char, N> m_data;

    char const *data() const noexcept {
        return m_data.data();
    }

    char *data() noexcept {
        return m_data.data();
    }

    static constexpr size_t size() noexcept {
        return N;
    }

    operator bytes_const_view() const noexcept {
        return bytes_const_view{m_data.data(), N};
    }

    operator bytes_view() noexcept {
        return bytes_view{m_data.data(), N};
    }

    operator std::string_view() const noexcept {
        return std::string_view{m_data.data(), m_data.size()};
    }
};

template <class... Args>
struct callback {
    struct _callback_base {
        virtual void _call(Args... args) = 0;
        virtual ~_callback_base() = default;
    };

    template <class F>
    struct _callback_impl final : _callback_base {
        F m_func;

        template <class... Ts,
                  class = std::enable_if_t<std::is_constructible_v<F, Ts...>>>
        _callback_impl(Ts &&...ts) : m_func(std::forward<Ts>(ts)...) {}

        void _call(Args... args) override {
            m_func(std::forward<Args>(args)...);
        }
    };

    std::unique_ptr<_callback_base> m_base;

    template <class F, class = std::enable_if_t<
                           std::is_invocable_v<F, Args...> &&
                           !std::is_same_v<std::decay_t<F>, callback>>>
    callback(F &&f)
        : m_base(std::make_unique<_callback_impl<std::decay_t<F>>>(
              std::forward<F>(f))) {}

    callback() = default;

    callback(std::nullptr_t) noexcept {}

    callback(callback const &) = delete;
    callback &operator=(callback const &) = delete;
    callback(callback &&) = default;
    callback &operator=(callback &&) = default;

    void operator()(Args... args) const {
        assert(m_base);
        return m_base->_call(std::forward<Args>(args)...);
    }

    void *get_address() const noexcept {
        return static_cast<void *>(m_base.get());
    }

    void *leak_address() noexcept {
        return static_cast<void *>(m_base.release());
    }

    static callback from_address(void *addr) noexcept {
        callback cb;
        cb.m_base = std::unique_ptr<_callback_base>(
            static_cast<_callback_base *>(addr));
        return cb;
    }

    explicit operator bool() const noexcept {
        return m_base != nullptr;
    }
};

struct stop_source {
    struct _control_block {
        bool m_stop = false;
        callback<> m_cb;
    };

    std::shared_ptr<_control_block> m_control;

    stop_source() = default;

    stop_source(std::in_place_t)
        : m_control(std::make_shared<_control_block>()) {}

    bool stop_requested() const noexcept {
        return m_control && m_control->m_stop;
    }

    bool stop_possible() const noexcept {
        return m_control != nullptr;
    }

    void request_stop() const {
        if (!m_control) {
            return;
        }
        m_control->m_stop = true;
        if (m_control->m_cb) {
            m_control->m_cb();
            m_control->m_cb = nullptr;
        }
    }

    void set_stop_callback(callback<> cb) const noexcept {
        if (!m_control) {
            return;
        }
        assert(!m_control->m_cb);
        m_control->m_cb = std::move(cb);
    }

    void clear_stop_callback() const noexcept {
        if (!m_control) {
            return;
        }
        m_control->m_cb = nullptr;
    }
};

struct timer_context {
    struct _timer_entry {
        callback<> m_cb;
        stop_source m_stop;
    };

    timer_context() = default;
    timer_context(timer_context &&) = delete;

    std::multimap<std::chrono::steady_clock::time_point, _timer_entry>
        m_timer_heap;

    void set_timeout(std::chrono::steady_clock::duration dt, callback<> cb,
                     stop_source stop = {}) {
        auto expire_time = std::chrono::steady_clock::now() + dt;
        auto it = m_timer_heap.insert(
            {expire_time, _timer_entry{std::move(cb), stop}});
        stop.set_stop_callback([this, it] {
            auto cb = std::move(it->second.m_cb);
            m_timer_heap.erase(it);
            cb();
        });
    }

    std::chrono::steady_clock::duration duration_to_next_timer() {
        while (!m_timer_heap.empty()) {
            auto it = m_timer_heap.begin();
            // 看看最近的一次计时器事件，是否已经过时？
            auto now = std::chrono::steady_clock::now();
            if (it->first <= now) {
                // 如果已经过时，则触发该定时器的回调，并删除
                it->second.m_stop.clear_stop_callback();
                auto cb = std::move(it->second.m_cb);
                m_timer_heap.erase(it);
                cb();
            } else {
                return it->first - now;
            }
        }
        return std::chrono::nanoseconds(-1);
    }

    bool is_empty() const {
        return m_timer_heap.empty();
    }
};

struct io_context : timer_context {
    int m_epfd;
    size_t m_epcount = 0;

    static inline thread_local io_context *g_instance = nullptr;

    io_context()
        : m_epfd(convert_error(epoll_create1(0)).expect("epoll_create")) {
        g_instance = this;
    }

    void join() {
        std::array<struct epoll_event, 128> events;
        while (!is_empty()) {
            std::chrono::nanoseconds dt = duration_to_next_timer();
            struct timespec timeout, *timeoutp = nullptr;
            if (dt.count() > 0) {
                timeout.tv_sec = dt.count() / 1'000'000'000;
                timeout.tv_nsec = dt.count() % 1'000'000'000;
                timeoutp = &timeout;
            }
            int ret =
                convert_error(epoll_pwait2(m_epfd, events.data(), events.size(),
                                           timeoutp, nullptr))
                    .expect("epoll_pwait2");
            for (int i = 0; i < ret; ++i) {
                auto cb = callback<>::from_address(events[i].data.ptr);
                cb();
                --m_epcount;
            }
        }
    }

    ~io_context() {
        close(m_epfd);
        g_instance = nullptr;
    }

    static io_context &get() {
        assert(g_instance);
        return *g_instance;
    }

    bool is_empty() const {
        return timer_context::is_empty() && m_epcount == 0;
    }
};

struct file_descriptor {
    int m_fd = -1;

    file_descriptor() = default;

    explicit file_descriptor(int fd) : m_fd(fd) {}

    file_descriptor(file_descriptor &&that) noexcept : m_fd(that.m_fd) {
        that.m_fd = -1;
    }

    file_descriptor &operator=(file_descriptor &&that) noexcept {
        std::swap(m_fd, that.m_fd);
        return *this;
    }

    ~file_descriptor() {
        if (m_fd == -1) {
            return;
        }
        close(m_fd);
    }
};

struct address_resolver {
    struct address_ref {
        struct sockaddr *m_addr;
        socklen_t m_addrlen;
    };

    struct address {
        union {
            struct sockaddr m_addr;
            struct sockaddr_storage m_addr_storage;
        };

        socklen_t m_addrlen = sizeof(struct sockaddr_storage);

        operator address_ref() {
            return {&m_addr, m_addrlen};
        }
    };

    struct address_info {
        struct addrinfo *m_curr = nullptr;

        address_ref get_address() const {
            return {m_curr->ai_addr, m_curr->ai_addrlen};
        }

        int create_socket() const {
            return convert_error(socket(m_curr->ai_family, m_curr->ai_socktype,
                                        m_curr->ai_protocol))
                .expect("socket");
        }

        [[nodiscard]] bool next_entry() {
            m_curr = m_curr->ai_next;
            if (m_curr == nullptr) {
                return false;
            }
            return true;
        }
    };

    struct addrinfo *m_head = nullptr;

    address_info resolve(std::string const &name, std::string const &service) {
        int err = getaddrinfo(name.c_str(), service.c_str(), NULL, &m_head);
        if (err != 0) {
            auto ec = std::error_code(err, gai_category());
            throw std::system_error(ec, name + ":" + service);
        }
        return {m_head};
    }

    address_resolver() = default;

    address_resolver(address_resolver &&that) : m_head(that.m_head) {
        that.m_head = nullptr;
    }

    ~address_resolver() {
        if (m_head) {
            freeaddrinfo(m_head);
        }
    }
};

struct async_file : file_descriptor {
    async_file() = default;

    explicit async_file(int fd) : file_descriptor(fd) {
        int flags = convert_error(fcntl(m_fd, F_GETFL)).expect("F_GETFL");
        flags |= O_NONBLOCK;
        convert_error(fcntl(m_fd, F_SETFL, flags)).expect("F_SETFL");

        struct epoll_event event;
        event.events = EPOLLET;
        event.data.ptr = nullptr;
        convert_error(
            epoll_ctl(io_context::get().m_epfd, EPOLL_CTL_ADD, m_fd, &event))
            .expect("EPOLL_CTL_ADD");
    }

    void _epoll_callback(callback<> &&resume, uint32_t events,
                         stop_source stop) {
        struct epoll_event event;
        event.events = events;
        event.data.ptr = resume.get_address();
        convert_error(
            epoll_ctl(io_context::get().m_epfd, EPOLL_CTL_MOD, m_fd, &event))
            .expect("EPOLL_CTL_MOD");
        ++io_context::get().m_epcount;
        stop.set_stop_callback([resume_ptr = resume.leak_address()] {
            callback<>::from_address(resume_ptr)();
        });
    }

    void async_read(bytes_view buf, callback<expected<size_t>> cb,
                    stop_source stop = {}) {
        if (stop.stop_requested()) {
            stop.clear_stop_callback();
            return cb(-ECANCELED);
        }
        auto ret = convert_error<size_t>(read(m_fd, buf.data(), buf.size()));
        if (!ret.is_error(EAGAIN)) {
            stop.clear_stop_callback();
            return cb(ret);
        }

        // 如果 read 可以读了，请操作系统，调用，我这个回调
        return _epoll_callback(
            [this, buf, cb = std::move(cb), stop]() mutable {
                return async_read(buf, std::move(cb), stop);
            },
            EPOLLIN | EPOLLERR | EPOLLET | EPOLLONESHOT, stop);
    }

    void async_write(bytes_const_view buf, callback<expected<size_t>> cb,
                     stop_source stop = {}) {
        if (stop.stop_requested()) {
            stop.clear_stop_callback();
            return cb(-ECANCELED);
        }
        auto ret = convert_error<size_t>(write(m_fd, buf.data(), buf.size()));
        if (!ret.is_error(EAGAIN)) {
            stop.clear_stop_callback();
            return cb(ret);
        }

        // 如果 write 可以写了，请操作系统，调用，我这个回调
        return _epoll_callback(
            [this, buf, cb = std::move(cb), stop]() mutable {
                return async_write(buf, std::move(cb), stop);
            },
            EPOLLOUT | EPOLLERR | EPOLLET | EPOLLONESHOT, stop);
    }

    void async_accept(address_resolver::address &addr,
                      callback<expected<int>> cb, stop_source stop = {}) {
        if (stop.stop_requested()) {
            stop.clear_stop_callback();
            return cb(-ECANCELED);
        }
        auto ret =
            convert_error<int>(accept(m_fd, &addr.m_addr, &addr.m_addrlen));
        if (!ret.is_error(EAGAIN)) {
            stop.clear_stop_callback();
            return cb(ret);
        }

        // 如果 accept 到请求了，请操作系统，调用，我这个回调
        return _epoll_callback(
            [this, &addr, cb = std::move(cb), stop]() mutable {
                return async_accept(addr, std::move(cb), stop);
            },
            EPOLLIN | EPOLLERR | EPOLLET | EPOLLONESHOT, stop);
    }

    void async_connect(address_resolver::address_info const &addr,
                       callback<expected<int>> cb, stop_source stop = {}) {
        if (stop.stop_requested()) {
            stop.clear_stop_callback();
            return cb(-ECANCELED);
        }
        auto addr_ptr = addr.get_address();
        auto ret =
            convert_error(connect(m_fd, addr_ptr.m_addr, addr_ptr.m_addrlen));
        if (!ret.is_error(EINPROGRESS)) {
            stop.clear_stop_callback();
            return cb(ret);
        }
        return _epoll_callback(
            [this, cb = std::move(cb), stop]() mutable {
                if (stop.stop_requested()) {
                    stop.clear_stop_callback();
                    return cb(-ECANCELED);
                }
                int ret;
                socklen_t ret_len = sizeof(ret);
                convert_error(
                    getsockopt(m_fd, SOL_SOCKET, SO_ERROR, &ret, &ret_len))
                    .expect("getsockopt");
                if (ret > 0) {
                    ret = -ret;
                }
                stop.clear_stop_callback();
                return cb(ret);
            },
            EPOLLOUT | EPOLLERR | EPOLLONESHOT, stop);
    }

    static async_file async_bind(address_resolver::address_info const &addr) {
        auto sock = async_file{addr.create_socket()};
        auto serve_addr = addr.get_address();
        int on = 1;
        setsockopt(sock.m_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        setsockopt(sock.m_fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
        convert_error(bind(sock.m_fd, serve_addr.m_addr, serve_addr.m_addrlen))
            .expect("bind");
        convert_error(listen(sock.m_fd, SOMAXCONN)).expect("listen");
        return sock;
    }

    async_file(async_file &&) = default;
    async_file &operator=(async_file &&) = default;

    ~async_file() {
        if (m_fd == -1) {
            return;
        }
        epoll_ctl(io_context::get().m_epfd, EPOLL_CTL_DEL, m_fd, nullptr);
    }

    explicit operator bool() const noexcept {
        return m_fd != -1;
    }
};

struct http11_header_parser {
    bytes_buffer m_header;    // "GET / HTTP/1.1\nHost: 142857.red\r\nAccept:
                              // */*\r\nConnection: close"
    std::string m_headline;   // "GET / HTTP/1.1"
    string_map m_header_keys; // {"Host": "142857.red", "Accept": "*/*",
                              // "Connection: close"}
    std::string m_body; // 不小心超量读取的正文（如果有的话）
    bool m_header_finished = false;

    void reset_state() {
        m_header.clear();
        m_headline.clear();
        m_header_keys.clear();
        m_body.clear();
        m_header_finished = 0;
    }

    [[nodiscard]] bool header_finished() {
        return m_header_finished; // 如果正文都结束了，就不再需要更多数据
    }

    void _extract_headers() {
        std::string_view header = m_header;
        size_t pos = header.find("\r\n", 0, 2);
        m_headline = std::string(header.substr(0, pos));
        while (pos != std::string::npos) {
            // 跳过 "\r\n"
            pos += 2;
            // 从当前位置开始找，先找到下一行位置（可能为 npos）
            size_t next_pos = header.find("\r\n", pos, 2);
            size_t line_len = std::string::npos;
            if (next_pos != std::string::npos) {
                // 如果下一行还不是结束，那么 line_len
                // 设为本行开始到下一行之间的距离
                line_len = next_pos - pos;
            }
            // 就能切下本行
            std::string_view line = header.substr(pos, line_len);
            size_t colon = line.find(": ", 0, 2);
            if (colon != std::string::npos) {
                // 每一行都是 "键: 值"
                std::string key = std::string(line.substr(0, colon));
                std::string_view value = line.substr(colon + 2);
                // 键统一转成小写，实现大小写不敏感的判断
                std::transform(key.begin(), key.end(), key.begin(), [](char c) {
                    if ('A' <= c && c <= 'Z') {
                        c += 'a' - 'A';
                    }
                    return c;
                });
                // 古代 C++ 过时的写法：m_header_keys[key] = value;
                // 现代 C++17 的高效写法：
                m_header_keys.insert_or_assign(std::move(key), value);
            }
            pos = next_pos;
        }
    }

    void push_chunk(bytes_const_view chunk) {
        assert(!m_header_finished);
        size_t old_size = m_header.size();
        m_header.append(chunk);
        std::string_view header = m_header;
        // 如果还在解析头部的话，尝试判断头部是否结束
        if (old_size < 4) {
            old_size = 4;
        }
        old_size -= 4;
        size_t header_len = header.find("\r\n\r\n", old_size, 4);
        if (header_len != std::string::npos) {
            // 头部已经结束
            m_header_finished = true;
            // 把不小心多读取的正文留下
            m_body = header.substr(header_len + 4);
            m_header.resize(header_len);
            // 开始分析头部，尝试提取 Content-length 字段
            _extract_headers();
        }
    }

    std::string &headline() {
        return m_headline;
    }

    string_map &headers() {
        return m_header_keys;
    }

    bytes_buffer &headers_raw() {
        return m_header;
    }

    std::string &extra_body() {
        return m_body;
    }
};

template <class HeaderParser = http11_header_parser>
struct _http_base_parser {
    HeaderParser m_header_parser;
    size_t m_content_length = 0;
    size_t body_accumulated_size = 0;
    bool m_body_finished = false;

    void reset_state() {
        m_header_parser.reset_state();
        m_content_length = 0;
        body_accumulated_size = 0;
        m_body_finished = false;
    }

    [[nodiscard]] bool header_finished() {
        return m_header_parser.header_finished();
    }

    [[nodiscard]] bool request_finished() {
        return m_body_finished;
    }

    std::string &headers_raw() {
        return m_header_parser.headers_raw();
    }

    std::string &headline() {
        return m_header_parser.headline();
    }

    string_map &headers() {
        return m_header_parser.headers();
    }

    std::string _headline_first() {
        // "GET / HTTP/1.1" request
        // "HTTP/1.1 200 OK" response
        auto &line = headline();
        size_t space = line.find(' ');
        if (space == std::string::npos) {
            return "";
        }
        return line.substr(0, space);
    }

    std::string _headline_second() {
        // "GET / HTTP/1.1"
        auto &line = headline();
        size_t space1 = line.find(' ');
        if (space1 == std::string::npos) {
            return "";
        }
        size_t space2 = line.find(' ', space1 + 1);
        if (space2 == std::string::npos) {
            return "";
        }
        return line.substr(space1 + 1, space2 - (space1 + 1));
    }

    std::string _headline_third() {
        // "GET / HTTP/1.1"
        auto &line = headline();
        size_t space1 = line.find(' ');
        if (space1 == std::string::npos) {
            return "";
        }
        size_t space2 = line.find(' ', space1 + 1);
        if (space2 == std::string::npos) {
            return "";
        }
        return line.substr(space2);
    }

    std::string &body() {
        return m_header_parser.extra_body();
    }

    size_t _extract_content_length() {
        auto &headers = m_header_parser.headers();
        auto it = headers.find("content-length");
        if (it == headers.end()) {
            return 0;
        }
        try {
            return std::stoi(it->second);
        } catch (std::logic_error const &) {
            return 0;
        }
    }

    void push_chunk(bytes_const_view chunk) {
        assert(!m_body_finished);
        if (!m_header_parser.header_finished()) {
            m_header_parser.push_chunk(chunk);
            if (m_header_parser.header_finished()) {
                body_accumulated_size = body().size();
                m_content_length = _extract_content_length();
                if (body_accumulated_size >= m_content_length) {
                    m_body_finished = true;
                }
            }
        } else {
            body().append(chunk);
            body_accumulated_size += chunk.size();
            if (body_accumulated_size >= m_content_length) {
                m_body_finished = true;
            }
        }
    }

    std::string read_some_body() {
        return std::move(body());
    }
};

template <class HeaderParser = http11_header_parser>
struct http_request_parser : _http_base_parser<HeaderParser> {
    std::string method() {
        return this->_headline_first();
    }

    std::string url() {
        return this->_headline_second();
    }
};

template <class HeaderParser = http11_header_parser>
struct http_response_parser : _http_base_parser<HeaderParser> {
    int status() {
        auto s = this->_headline_second();
        try {
            return std::stoi(s);
        } catch (std::logic_error const &) {
            return -1;
        }
    }
};

struct http11_header_writer {
    bytes_buffer m_buffer;

    void reset_state() {
        m_buffer.clear();
    }

    bytes_buffer &buffer() {
        return m_buffer;
    }

    void begin_header(std::string_view first, std::string_view second,
                      std::string_view third) {
        m_buffer.append(first);
        m_buffer.append_literial(" ");
        m_buffer.append(second);
        m_buffer.append_literial(" ");
        m_buffer.append(third);
    }

    void write_header(std::string_view key, std::string_view value) {
        m_buffer.append_literial("\r\n");
        m_buffer.append(key);
        m_buffer.append_literial(": ");
        m_buffer.append(value);
    }

    void end_header() {
        m_buffer.append_literial("\r\n\r\n");
    }
};

template <class HeaderWriter = http11_header_writer>
struct _http_base_writer {
    HeaderWriter m_header_writer;

    void _begin_header(std::string_view first, std::string_view second,
                       std::string_view third) {
        m_header_writer.begin_header(first, second, third);
    }

    void reset_state() {
        m_header_writer.reset_state();
    }

    bytes_buffer &buffer() {
        return m_header_writer.buffer();
    }

    void write_header(std::string_view key, std::string_view value) {
        m_header_writer.write_header(key, value);
    }

    void end_header() {
        m_header_writer.end_header();
    }

    void write_body(std::string_view body) {
        m_header_writer.buffer().append(body);
    }
};

template <class HeaderWriter = http11_header_writer>
struct http_request_writer : _http_base_writer<HeaderWriter> {
    void begin_header(std::string_view method, std::string_view url) {
        this->_begin_header(method, url, "HTTP/1.1");
    }
};

template <class HeaderWriter = http11_header_writer>
struct http_response_writer : _http_base_writer<HeaderWriter> {
    void begin_header(int status) {
        this->_begin_header("HTTP/1.1", std::to_string(status), "OK");
    }
};

struct http_server : std::enable_shared_from_this<http_server> {
    using pointer = std::shared_ptr<http_server>;

    static pointer make() {
        return std::make_shared<pointer::element_type>();
    }

    struct http_request {
        std::string url;
        std::string method; // GET, POST, PUT, ...
        std::string body;

        http_response_writer<> *m_res_writer = nullptr;

        void write_response(
            int status, std::string_view content,
            std::string_view content_type = "text/plain;charset=utf-8") {
            m_res_writer->begin_header(status);
            m_res_writer->write_header("Server", "co_http");
            m_res_writer->write_header("Content-type", content_type);
            m_res_writer->write_header("Connection", "keep-alive");
            m_res_writer->write_header("Content-length",
                                       std::to_string(content.size()));
            m_res_writer->end_header();
            m_res_writer->write_body(content);
        }
    };

    struct http_router {
        std::map<std::string, callback<http_request &>> m_routes;

        void route(std::string url, callback<http_request &> cb) {
            // 为指定路径设置回调函数
            m_routes.insert_or_assign(url, std::move(cb));
        }

        void do_handle(http_request &request) {
            // 寻找匹配的路径
            auto it = m_routes.find(request.url);
            if (it != m_routes.end()) {
                return it->second(request);
            }
            fmt::println("找不到路径: {}", request.url);
            return request.write_response(404, "404 Not Found");
        }
    };

    struct http_connection_handler
        : std::enable_shared_from_this<http_connection_handler> {
        async_file m_conn;
        bytes_buffer m_readbuf{1024};
        http_request_parser<> m_req_parser;
        http_response_writer<> m_res_writer;
        http_router *m_router = nullptr;

        using pointer = std::shared_ptr<http_connection_handler>;

        static pointer make() {
            return std::make_shared<pointer::element_type>();
        }

        void do_start(http_router *router, int connfd) {
            m_router = router;
            m_conn = async_file{connfd};
            return do_read();
        }

        void do_read() {
            // 注意：TCP 基于流，可能粘包
            fmt::println("开始读取...");
            // 设置一个 3 秒的定时器，若 3
            // 秒内没有读到任何请求，则视为对方放弃，关闭连接
            stop_source stop_io(std::in_place);
            stop_source stop_timer(std::in_place);
            io_context::get().set_timeout(
                std::chrono::seconds(10),
                [stop_io] {
                    stop_io.request_stop(); // 定时器先完成时，取消读取
                },
                stop_timer);
            // 开始读取
            return m_conn.async_read(
                m_readbuf,
                [self = this->shared_from_this(),
                 stop_timer](expected<size_t> ret) {
                    stop_timer.request_stop(); // 读取先完成时，取消定时器
                    if (ret.error()) {
                        fmt::println("读取出错 {}，放弃连接",
                                     strerror(-ret.error()));
                        return;
                    }
                    size_t n = ret.value();
                    // 如果读到 EOF，说明对面，关闭了连接
                    if (n == 0) {
                        fmt::println("对面关闭了连接");
                        return;
                    }
                    fmt::println("读取到了 {} 个字节: {}", n,
                                 std::string_view{self->m_readbuf.data(), n});
                    // 成功读取，则推入解析
                    self->m_req_parser.push_chunk(
                        self->m_readbuf.subspan(0, n));
                    if (!self->m_req_parser.request_finished()) {
                        return self->do_read();
                    } else {
                        return self->do_handle();
                    }
                },
                stop_io);
        }

        void do_handle() {
            http_request request{
                m_req_parser.url(),
                m_req_parser.method(),
                std::move(m_req_parser.body()),
                &m_res_writer,
            };
            m_req_parser.reset_state();

            // fmt::println("我的响应头: {}", buffer);
            // fmt::println("我的响应正文: {}", body);
            fmt::println("正在响应");
            m_router->do_handle(request);
            return do_write(m_res_writer.buffer());
        }

        void do_write(bytes_const_view buffer) {
            return m_conn.async_write(buffer, [self = shared_from_this(),
                                               buffer](expected<size_t> ret) {
                if (ret.error()) {
                    fmt::println("写入错误，放弃连接");
                    return;
                }
                auto n = ret.value();

                if (buffer.size() == n) {
                    self->m_res_writer.reset_state();
                    return self->do_read();
                }
                return self->do_write(buffer.subspan(n));
            });
        }
    };

    async_file m_listening;
    address_resolver::address m_addr;
    http_router m_router;

    http_router &get_router() {
        return m_router;
    }

    void do_start(std::string name, std::string port) {
        address_resolver resolver;
        fmt::println("正在监听：http://{}:{}", name, port);
        auto entry = resolver.resolve(name, port);
        m_listening = async_file::async_bind(entry);
        return do_accept();
    }

    void do_accept() {
        return m_listening.async_accept(m_addr, [self = shared_from_this()](
                                                    expected<int> ret) {
            auto connfd = ret.expect("accept");

            fmt::println("接受了一个连接: {}", connfd);
            http_connection_handler::make()->do_start(&self->m_router, connfd);
            return self->do_accept();
        });
    }
};

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
                fmt::println("复用现有连接");
                do_compose();
                return;
            }
            m_parsed_url = std::move(parsed_url);
            fmt::println("连接到 {}，服务 {}，路径 {}", m_parsed_url.m_hostname,
                         m_parsed_url.m_scheme, m_request.url);
            // "http://142857.red/" 变成
            // m_hostname = "142857.red";
            // m_scheme = "http";
            // m_request.url = "/";
            address_resolver res;
            auto addr = _resolve_address(res);
            m_conn = async_file{addr.create_socket()};
            fmt::println("开始连接...");
            return m_conn.async_connect(
                addr,
                [self = shared_from_this()](expected<int> ret) mutable {
                    ret.expect("connect");
                    fmt::println("连接成功...");
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
            fmt::println("正在写入请求...");
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
                    fmt::println("写入 {} 字节", n);

                    if (buffer.size() == n) {
                        fmt::println("写入请求成功，开始读取");
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
                        fmt::println("读取出错 {}，放弃连接",
                                     strerror(-ret.error()));
                        return self->m_cb(ret.error(), {});
                    }
                    size_t n = ret.value();
                    // 如果读到 EOF，说明对面，关闭了连接
                    if (n == 0) {
                        fmt::println("对面关闭了连接");
                        return;
                    }
                    fmt::println("读取到了 {} 个字节: {}", n,
                                 std::string_view{self->m_readbuf.data(), n});
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
    // setlocale(LC_ALL, "zh_CN.UTF-8");
    try {
        client();
    } catch (std::system_error const &e) {
        fmt::println("{} ({}/{})", e.what(), e.code().category().name(),
                     e.code().value());
    }
    return 0;
}
