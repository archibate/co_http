#pragma once

#include <cassert>
#include <type_traits>
#include <utility>
#include <memory>

inline constexpr struct multishot_call_t {
    explicit multishot_call_t() = default;
} multishot_call;

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

    void operator()(Args... args) {
        assert(m_base);
        m_base->_call(std::forward<Args>(args)...);
        m_base = nullptr; // 所有回调，只能调用一次
    }

    void operator()(multishot_call_t, Args... args) const {
        assert(m_base);
        m_base->_call(std::forward<Args>(args)...);
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
