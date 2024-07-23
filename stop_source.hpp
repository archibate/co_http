#pragma once

#include "callback.hpp"
#include <memory>

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
        m_control->m_cb = std::move(cb);
    }

    void clear_stop_callback() const noexcept {
        if (!m_control) {
            return;
        }
        m_control->m_cb = nullptr;
    }
};
