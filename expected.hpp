#pragma once

#include <type_traits>
#include <system_error>

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
            // fmt::println(stderr, "{}: {}", what, ec.message());
            throw std::system_error(ec, what);
        }
        return m_res;
    }

    T value() const {
        if (m_res < 0) {
            auto ec = error_code();
            // fmt::println(stderr, "{}", ec.message());
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
