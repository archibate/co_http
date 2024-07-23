#pragma once

#include <map>
#include <chrono>
#include "callback.hpp"
#include "stop_source.hpp"

struct timer_context {
    struct _timer_entry {
        callback<> m_cb;
        stop_source m_stop;
    };

    std::multimap<std::chrono::steady_clock::time_point, _timer_entry>
        m_timer_heap;

    timer_context() = default;
    timer_context(timer_context &&) = delete;

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
