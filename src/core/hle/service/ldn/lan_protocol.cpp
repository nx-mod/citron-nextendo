// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include <charconv>
#include <fstream>
#include <string>
#include <string_view>

#include "common/fs/path_util.h"
#include "common/logging.h"
#include "core/hle/service/ldn/lan_protocol.h"

namespace Service::LDN {

namespace {

/// Parses "a.b.c.d" into an IPv4Address. Returns false if malformed.
bool ParseIpv4(std::string_view text, Network::IPv4Address& out) {
    Network::IPv4Address parsed{};
    size_t index = 0;
    size_t pos = 0;

    while (index < 4) {
        const size_t dot = text.find('.', pos);
        const std::string_view part =
            text.substr(pos, dot == std::string_view::npos ? std::string_view::npos : dot - pos);
        if (part.empty()) {
            return false;
        }

        unsigned value = 0;
        const auto* begin = part.data();
        const auto* end = part.data() + part.size();
        const auto result = std::from_chars(begin, end, value);
        if (result.ec != std::errc{} || result.ptr != end || value > 255) {
            return false;
        }
        parsed[index++] = static_cast<u8>(value);

        if (dot == std::string_view::npos) {
            break;
        }
        pos = dot + 1;
    }

    if (index != 4) {
        return false;
    }
    out = parsed;
    return true;
}

std::string_view Trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '\r')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r')) {
        text.remove_suffix(1);
    }
    return text;
}

} // Anonymous namespace

LanNetworkConfig LoadLanNetworkConfig() {
    LanNetworkConfig config{};

    const auto path =
        Common::FS::GetCitronPath(Common::FS::CitronPath::ConfigDir) / "ldn_network.ini";
    std::ifstream file(path);
    if (!file) {
        LOG_INFO(Service_LDN,
                 "No ldn_network.ini at {}, using defaults: bind {}.{}.{}.{} broadcast "
                 "{}.{}.{}.{} port {}",
                 Common::FS::PathToUTF8String(path), config.bind_address[0], config.bind_address[1],
                 config.bind_address[2], config.bind_address[3], config.broadcast_address[0],
                 config.broadcast_address[1], config.broadcast_address[2],
                 config.broadcast_address[3], config.port);
        return config;
    }

    std::string line;
    while (std::getline(file, line)) {
        const std::string_view trimmed = Trim(line);
        if (trimmed.empty() || trimmed.front() == '#' || trimmed.front() == ';') {
            continue;
        }
        const size_t eq = trimmed.find('=');
        if (eq == std::string_view::npos) {
            continue;
        }
        const std::string_view key = Trim(trimmed.substr(0, eq));
        const std::string_view value = Trim(trimmed.substr(eq + 1));

        if (key == "bind_address") {
            if (!ParseIpv4(value, config.bind_address)) {
                LOG_WARNING(Service_LDN, "ldn_network.ini: bad bind_address '{}'", value);
            }
        } else if (key == "broadcast_address") {
            if (!ParseIpv4(value, config.broadcast_address)) {
                LOG_WARNING(Service_LDN, "ldn_network.ini: bad broadcast_address '{}'", value);
            }
        } else if (key == "virtual_ip") {
            if (!ParseIpv4(value, config.virtual_ip)) {
                LOG_WARNING(Service_LDN, "ldn_network.ini: bad virtual_ip '{}'", value);
            }
        } else if (key == "virtual_mask") {
            if (!ParseIpv4(value, config.virtual_mask)) {
                LOG_WARNING(Service_LDN, "ldn_network.ini: bad virtual_mask '{}'", value);
            }
        } else if (key == "port") {
            unsigned parsed_port = 0;
            const auto* begin = value.data();
            const auto* end = value.data() + value.size();
            const auto result = std::from_chars(begin, end, parsed_port);
            if (result.ec != std::errc{} || result.ptr != end || parsed_port == 0 ||
                parsed_port > 65535) {
                LOG_WARNING(Service_LDN, "ldn_network.ini: bad port '{}'", value);
            } else {
                config.port = static_cast<u16>(parsed_port);
            }
        } else {
            LOG_WARNING(Service_LDN, "ldn_network.ini: unknown key '{}'", key);
        }
    }

    LOG_INFO(Service_LDN,
             "Loaded ldn_network.ini: bind {}.{}.{}.{} broadcast {}.{}.{}.{} virtual_ip "
             "{}.{}.{}.{} port {}",
             config.bind_address[0], config.bind_address[1], config.bind_address[2],
             config.bind_address[3], config.broadcast_address[0], config.broadcast_address[1],
             config.broadcast_address[2], config.broadcast_address[3], config.virtual_ip[0],
             config.virtual_ip[1], config.virtual_ip[2], config.virtual_ip[3], config.port);
    return config;
}

size_t LanCompress(const u8* input, size_t input_size, u8* output, size_t output_capacity) {
    const u8* in = input;
    const u8* in_end = input + input_size;
    u8* out = output;
    u8* out_end = output + output_capacity;

    while (out < out_end && in < in_end) {
        const u8 c = *in++;
        u8 count = 0;

        if (c == 0) {
            // NB: ldn_mitm's original dereferences *in before checking
            // in < in_end; bounds are checked first here. Same output for
            // any valid input.
            while (in < in_end && *in == 0 && count < 0xFF) {
                count += 1;
                in++;
            }

            *out++ = 0;
            if (out == out_end) {
                return 0;
            }
            *out++ = count;
        } else {
            *out++ = c;
        }
    }

    if (in != in_end) {
        return 0;
    }
    return static_cast<size_t>(out - output);
}

bool LanDecompress(const u8* input, size_t input_size, u8* output, size_t output_capacity,
                   size_t& out_size) {
    const u8* in = input;
    const u8* in_end = input + input_size;
    u8* out = output;
    u8* out_end = output + output_capacity;

    while (in < in_end && out < out_end) {
        const u8 c = *in++;

        *out++ = c;
        if (c == 0) {
            if (in == in_end) {
                return false;
            }
            const u8 count = *in++;
            for (u8 i = 0; i < count; i++) {
                if (out == out_end) {
                    break;
                }
                *out++ = c;
            }
        }
    }

    out_size = static_cast<size_t>(out - output);
    return in == in_end;
}

bool ToLanPacketType(Network::LDNPacketType in, LanPacketType& out) {
    switch (in) {
    case Network::LDNPacketType::Scan:
        out = LanPacketType::Scan;
        return true;
    case Network::LDNPacketType::ScanResp:
        out = LanPacketType::ScanResp;
        return true;
    case Network::LDNPacketType::Connect:
        out = LanPacketType::Connect;
        return true;
    case Network::LDNPacketType::SyncNetwork:
        out = LanPacketType::SyncNetwork;
        return true;
    default:
        // Disconnect / DestroyNetwork have no wire representation -- real
        // hardware signals those by closing the TCP connection.
        return false;
    }
}

Network::LDNPacketType FromLanPacketType(LanPacketType in) {
    switch (in) {
    case LanPacketType::Scan:
        return Network::LDNPacketType::Scan;
    case LanPacketType::ScanResp:
        return Network::LDNPacketType::ScanResp;
    case LanPacketType::Connect:
        return Network::LDNPacketType::Connect;
    case LanPacketType::SyncNetwork:
    default:
        return Network::LDNPacketType::SyncNetwork;
    }
}

} // namespace Service::LDN
