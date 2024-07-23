#pragma once

#include <cstddef>
#include <string_view>
#include <utility>

constexpr std::string_view _try_extract_value(std::string_view str) {
    auto critpos = str.find("CrItMaGiC = ") + 12;
    auto endpos = str.find_first_of(";]");
    auto slice = str.substr(critpos, endpos - critpos);
    return slice;
}

constexpr std::string_view _try_remove_prefix(std::string_view str, std::string_view prefix) {
    if (!str.empty()) {
        if (str.front() == '(') {
            return {};
        }
        if (str.find(prefix) == 0 && str.find("::", prefix.size(), 2) == prefix.size()) {
            return str.substr(prefix.size() + 2);
        }
    }
    return str;
}

template <class CrItMaGiC>
constexpr std::string_view _enum_type_name() {
    constexpr std::string_view name = _try_extract_value(__PRETTY_FUNCTION__);
    return name;
}

template <auto CrItMaGiC>
constexpr std::string_view _enum_value_name() {
    constexpr auto type = _enum_type_name<decltype(CrItMaGiC)>();
    constexpr std::string_view name = _try_remove_prefix(_try_extract_value(__PRETTY_FUNCTION__), type);
    return name;
}

#if __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wenum-constexpr-conversion"
#endif
template <class E, size_t I0, size_t I1>
constexpr size_t _enum_range_impl() {
    if constexpr (I0 + 1 == I1) {
        return I1;
    } else {
        constexpr size_t I = (I0 + I1) >> 1;
        if constexpr (!_enum_value_name<static_cast<E>(I)>().empty()) {
            return _enum_range_impl<E, I, I1>();
        } else {
            return _enum_range_impl<E, I0, I>();
        }
    }
}

template <class E>
constexpr size_t _enum_range() {
    return _enum_range_impl<E, 0, 256>();
}
#if __clang__
#pragma clang diagnostic pop
#endif

template <class E, size_t ...Is>
constexpr std::string_view _dump_enum_impl(E value, std::index_sequence<Is...>) {
    std::string_view ret;
    (void)((value == static_cast<E>(Is) && ((ret = _enum_value_name<static_cast<E>(Is)>()), false)) || ...);
    return ret;
}

template <class E>
constexpr std::string_view dump_enum(E value) {
    return _dump_enum_impl(value, std::make_index_sequence<_enum_range<E>()>());
}

template <class E, size_t ...Is>
constexpr E _parse_enum_impl(std::string_view name, std::index_sequence<Is...>) {
    size_t ret = static_cast<size_t>(-1);
    (void)((name == _enum_value_name<static_cast<E>(Is)>() && (ret = Is)) || ...);
    return static_cast<E>(ret);
}

template <class E>
constexpr E parse_enum(std::string_view name) {
    return _parse_enum_impl<E>(name, std::make_index_sequence<_enum_range<E>()>());
}
