#pragma once
#include "vendor/nlohmann/json.hpp"
#include <string>

namespace hh {

inline std::string luaEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:   out += c;
        }
    }
    return out;
}

inline std::string luaLongEscape(const std::string& s) {
    std::string safe;
    safe.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == ']' && i + 1 < s.size() && s[i + 1] == ']') {
            safe += "] ]";
            i++;
        } else {
            safe += s[i];
        }
    }
    return safe;
}

inline std::string boolLua(bool b) { return b ? "true" : "false"; }

inline std::string intArrayToLua(const std::vector<int>& arr) {
    std::string out = "{";
    for (size_t i = 0; i < arr.size(); i++) {
        if (i > 0) out += ",";
        out += std::to_string(arr[i]);
    }
    out += "}";
    return out;
}

inline std::string intArrayFromJson(const nlohmann::json& j, const std::string& key) {
    std::string out = "{";
    if (j.contains(key) && j[key].is_array()) {
        const auto& arr = j[key];
        for (size_t i = 0; i < arr.size(); i++) {
            if (i > 0) out += ",";
            out += std::to_string(arr[i].get<long long>());
        }
    }
    out += "}";
    return out;
}

inline std::string stringArrayFromJson(const nlohmann::json& j, const std::string& key) {
    std::string out = "{";
    if (j.contains(key) && j[key].is_array()) {
        const auto& arr = j[key];
        for (size_t i = 0; i < arr.size(); i++) {
            if (i > 0) out += ",";
            out += "\"" + luaEscape(arr[i].get<std::string>()) + "\"";
        }
    }
    out += "}";
    return out;
}

} // namespace hh
