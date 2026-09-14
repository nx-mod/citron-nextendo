// SPDX-FileCopyrightText: Copyright 2022 yuzu Emulator Project
// SPDX-FileCopyrightText: Copyright 2026 citron Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <array>
#include <atomic>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <span>
#include <thread>
#include <unordered_map>

#include "common/logging.h"
#include "common/socket_types.h"
#include "core/hle/result.h"
#include "core/hle/service/ldn/lan_protocol.h"
#include "core/hle/service/ldn/ldn_results.h"
#include "core/hle/service/ldn/ldn_types.h"
#include "network/network.h"

namespace Network {
class SocketBase;
}

namespace Service::LDN {

class LANDiscovery;

class LanStation {
public:
    LanStation(s8 node_id_, LANDiscovery* discovery_);
    ~LanStation();

    void OnClose();
    NodeStatus GetStatus() const;
    void Reset();
    void OverrideInfo();

protected:
    friend class LANDiscovery;
    NodeInfo* node_info;
    NodeStatus status;
    s8 node_id;
    LANDiscovery* discovery;
    /// Per-station TCP connection (host role). Mirrors ldn_mitm's
    /// LanStation::socket -- a station disconnecting is signaled by this
    /// socket closing, there is no wire message for it.
    std::unique_ptr<Network::SocketBase> socket;
    /// Peer address of `socket`, recorded at accept time. Used to bind an
    /// incoming Connect packet to the station it actually arrived on.
    /// ldn_mitm does this implicitly by handling Connect inside
    /// LanStation::onRead (per-socket); Eden's handler is global, and its
    /// NodeStatus has no intermediate "Connect" state to claim the slot
    /// with, so without this two stations connecting before either sends
    /// Connect can land their NodeInfo in each other's slot.
    Ipv4Address peer_ip{};
};

class LANDiscovery {
public:
    using LanEventFunc = std::function<void()>;

    LANDiscovery(Network::RoomNetwork& room_network_);
    ~LANDiscovery();

    State GetState() const;
    void SetState(State new_state);

    Result GetNetworkInfo(NetworkInfo& out_network) const;
    Result GetNetworkInfo(NetworkInfo& out_network, std::span<NodeLatestUpdate> out_updates);

    DisconnectReason GetDisconnectReason() const;
    Result Scan(std::span<NetworkInfo> out_networks, s16& out_count, const ScanFilter& filter);
    Result SetAdvertiseData(std::span<const u8> data);

    Result OpenAccessPoint();
    Result CloseAccessPoint();

    Result OpenStation();
    Result CloseStation();

    Result CreateNetwork(const SecurityConfig& security_config, const UserConfig& user_config,
                         const NetworkConfig& network_config);
    Result DestroyNetwork();

    Result Connect(const NetworkInfo& network_info_, const UserConfig& user_config,
                   u16 local_communication_version);
    Result Disconnect();

    Result Initialize(LanEventFunc lan_event_ = empty_func, bool listening = true);
    Result Finalize();

    void ReceivePacket(const Network::LDNPacket& packet);

    /// Address and mask the game should believe it holds on the LDN network,
    /// for nn::ldn's GetIpv4Address. This is NOT the phone's real interface
    /// address: peers address us by whatever the bridge advertised on our
    /// behalf, so the game has to agree with them or it will treat every peer
    /// as off-subnet and drop the session immediately after joining.
    /// Returns false when no virtual_ip is configured, in which case the
    /// caller should fall back to the real interface.
    bool GetVirtualIpConfig(Network::IPv4Address& out_address,
                            Network::IPv4Address& out_mask) const;

protected:
    friend class LanStation;

    void InitNetworkInfo();
    void InitNodeStateChange();

    void ResetStations();
    void UpdateNodes();

    void OnSyncNetwork(const NetworkInfo& info);
    void OnDisconnectFromHost();
    void OnNetworkInfoChanged();

    bool IsNodeStateChanged();
    bool IsFlagSet(ScanFilterFlag flag, ScanFilterFlag search_flag) const;
    int GetStationCount() const;
    MacAddress GetFakeMac() const;
    Result GetNodeInfo(NodeInfo& node, const UserConfig& user_config,
                       u16 local_communication_version);

    Network::IPv4Address GetLocalIp() const;
    /// True if our own address appears in the current network_info node list.
    /// Used to confirm a join actually happened, rather than trusting that
    /// some SyncNetwork arrived. Caller must hold packet_mutex.
    bool IsSelfInNodeList() const;
    template <typename Data>
    void SendPacket(Network::LDNPacketType type, const Data& data, Ipv4Address remote_ip);
    void SendPacket(Network::LDNPacketType type, Ipv4Address remote_ip);
    template <typename Data>
    void SendBroadcast(Network::LDNPacketType type, const Data& data);
    void SendBroadcast(Network::LDNPacketType type);
    void SendPacket(const Network::LDNPacket& packet);

    // --- Native LDN transport (ldn_mitm wire protocol, see lan_protocol.h) ---
    // Replaces the previous ENet-room-based transport so Eden speaks the same
    // protocol a real Switch running ldn_mitm does: UDP broadcast on port
    // 11452 for Scan/ScanResp, TCP on 11452 for Connect/SyncNetwork.

    /// Opens the UDP (broadcast) and TCP (listen) sockets and starts the
    /// worker thread. Called from Initialize().
    bool OpenTransport();
    /// Stops the worker thread and closes every socket. Called from Finalize().
    void CloseTransport();
    /// Poll loop body -- services the UDP socket, the TCP listener, connected
    /// stations (host role) and the host connection (station role).
    void TransportWorker();
    void PollTransportOnce();
    /// Frames and writes one packet to an already-connected TCP socket.
    bool SendOverTcp(Network::SocketBase& socket, Network::LDNPacketType type,
                     std::span<const u8> data);
    /// Frames and sends one packet over UDP to addr (or broadcast if null).
    bool SendOverUdp(Network::LDNPacketType type, std::span<const u8> data,
                     const Ipv4Address* remote_ip);
    /// Parses one framed packet out of buf and dispatches it to ReceivePacket().
    void HandleLanData(std::span<const u8> buf, Ipv4Address remote_ip);
    /// Station role: connect our TCP socket to the host we're joining.
    bool ConnectToHost(Ipv4Address host, std::span<const u8> connect_payload);

    std::unique_ptr<Network::SocketBase> udp_socket;
    std::unique_ptr<Network::SocketBase> tcp_listen_socket;
    std::unique_ptr<Network::SocketBase> host_socket; ///< station role: link to host
    std::thread transport_thread;
    std::atomic<bool> transport_running{false};
    /// Runtime-tunable addresses/port, loaded from ldn_network.ini at
    /// OpenTransport() time so they can be changed without a rebuild.
    LanNetworkConfig lan_config{};

    static const LanEventFunc empty_func;
    /// Matches ldn_mitm's LANDiscovery::FakeSsid byte for byte (32 chars, the
    /// SsidLengthMax maximum) so a network Citron hosts is indistinguishable
    /// from one hosted by a real Switch running ldn_mitm -- the SSID travels
    /// in CommonNetworkInfo and is filterable via ScanFilterFlag::Ssid.
    static constexpr Ssid fake_ssid{"12345678123456781234567812345678"};

    bool inited{};
    mutable std::mutex packet_mutex;
    std::array<LanStation, StationCountMax> stations;
    std::array<NodeLatestUpdate, NodeCountMax> node_changes{};
    std::array<u8, NodeCountMax> node_last_states{};
    std::unordered_map<MacAddress, NetworkInfo, MACAddressHash> scan_results{};
    NodeInfo node_info{};
    NetworkInfo network_info{};
    State state{State::None};
    DisconnectReason disconnect_reason{DisconnectReason::None};

    // TODO (flTobi): Should this be an std::set?
    std::vector<Ipv4Address> connected_clients;
    std::optional<Ipv4Address> host_ip;

    LanEventFunc lan_event;

    Network::RoomNetwork& room_network;
};
} // namespace Service::LDN
