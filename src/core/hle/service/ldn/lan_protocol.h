// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include "common/common_types.h"
#include "network/network.h"

// Native LDN wire protocol -- ported from ldn_mitm (real ldn_mitm sysmodule,
// spacemeowx2/ldn_mitm) so Eden can speak the exact same protocol a real
// Switch running ldn_mitm uses, instead of Eden's own internal ENet room
// protocol. This lets a real CFW Switch and Eden interoperate directly over
// a real/bridged LAN (see eden-ldn-vpn-bridge) without any payload
// translation -- NetworkInfo/NodeInfo/SecurityConfig are already the same
// real Horizon OS structures on both sides (see ldn_types.h).
//
// Reference: ldn_mitm/ldn_mitm/source/lan_protocol.{hpp,cpp} and
// lan_discovery.{hpp,cpp}.

namespace Service::LDN {

constexpr u16 LanProtocolPort = 11452; // ldn_mitm's LANDiscovery::DefaultPort
constexpr u32 LanProtocolMagic = 0x11451400;
constexpr size_t LanProtocolBufferSize = 2048;

/// Subnet broadcast address for the lan-play virtual LAN. switch-lan-play
/// hardcodes SUBNET_NET 10.13.0.0 / SUBNET_MASK 255.255.0.0 (its src/config.h)
/// and only forwards traffic it recognises as being on that subnet, so
/// discovery broadcasts must target 10.13.255.255 rather than 255.255.255.255.
/// On real hardware ldn_mitm derives the equivalent address from the console's
/// own interface config (LDUdpSocket::getBroadcast).
constexpr Network::IPv4Address LanBroadcastAddress{10, 13, 255, 255};

// Wire type tag -- matches ldn_mitm's LANPacketType exactly (Scan/ScanResp/
// Connect/SyncNetwork only). Eden's own Network::LDNPacketType additionally
// has Disconnect/DestroyNetwork, which have no wire representation on real
// hardware -- those are signaled by closing the TCP connection instead (see
// LanStation::OnClose / LANDiscovery::OnDisconnectFromHost).
enum class LanPacketType : u8 {
    Scan = 0,
    ScanResp = 1,
    Connect = 2,
    SyncNetwork = 3,
};

#pragma pack(push, 1)
struct LanPacketHeader {
    u32 magic;
    LanPacketType type;
    u8 compressed;
    u16 length;            // length of the (possibly compressed) payload that follows
    u16 decompress_length; // length after decompression
    u8 reserved[2];
};
#pragma pack(pop)
static_assert(sizeof(LanPacketHeader) == 12, "LanPacketHeader must match ldn_mitm's on-wire size");

/// Zero-run-length encoding, exactly matching ldn_mitm's LanSocket::compress.
/// Not real compression -- a run of N zero bytes becomes two bytes: 0x00, N
/// (N capped at 0xFF, longer runs become multiple two-byte pairs). Returns
/// the number of bytes written to output, or 0 if it doesn't fit.
size_t LanCompress(const u8* input, size_t input_size, u8* output, size_t output_capacity);

/// Inverse of LanCompress. Returns false if the input is malformed or the
/// output doesn't fit in output_capacity.
bool LanDecompress(const u8* input, size_t input_size, u8* output, size_t output_capacity,
                    size_t& out_size);

/// Maps the 4 real wire message types to/from Eden's own LDNPacketType.
/// Disconnect/DestroyNetwork have no wire equivalent -- callers must handle
/// those via TCP connection lifecycle, not this mapping.
bool ToLanPacketType(Network::LDNPacketType in, LanPacketType& out);
Network::LDNPacketType FromLanPacketType(LanPacketType in);

/// Runtime-tunable LDN network settings, so the local/broadcast addresses can
/// be changed without a rebuild. Read from "ldn_network.ini" in Eden's config
/// directory; every field falls back to the lan-play defaults above if the
/// file is missing or a key is absent.
///
///   # ldn_network.ini
///   bind_address=0.0.0.0
///   broadcast_address=10.13.255.255
///   virtual_ip=10.13.1.100
///   virtual_mask=255.255.0.0
///   port=11452
///
/// Deliberately parsed here rather than added to Common::Settings -- that
/// header is included tree-wide and touching it forces a full rebuild.
struct LanNetworkConfig {
    Network::IPv4Address bind_address{0, 0, 0, 0};
    Network::IPv4Address broadcast_address{LanBroadcastAddress};
    /// Address reported to peers in NodeInfo.ipv4Address, i.e. the address the
    /// other console will try to open its TCP connection to. Eden runs on a
    /// phone whose real address is on the hotspot LAN, not on the lan-play
    /// virtual LAN, so the real address is useless to a peer -- this is the
    /// address the PC-side bridge presents on Eden's behalf. All-zero means
    /// "unset": fall back to the socket's own address, matching what ldn_mitm
    /// reports on real hardware (where the console really is on 10.13.0.0/16).
    Network::IPv4Address virtual_ip{0, 0, 0, 0};
    /// Subnet mask reported alongside virtual_ip. Defaults to the lan-play
    /// virtual LAN's 255.255.0.0 (switch-lan-play's SUBNET_MASK); the phone's
    /// real mask is narrower and would make peers look off-subnet.
    Network::IPv4Address virtual_mask{255, 255, 0, 0};
    u16 port{LanProtocolPort};
};

/// Loads the config from disk. Never fails -- returns defaults on any problem,
/// logging what it used.
LanNetworkConfig LoadLanNetworkConfig();

} // namespace Service::LDN
