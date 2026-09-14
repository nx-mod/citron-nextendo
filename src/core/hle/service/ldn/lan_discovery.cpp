// SPDX-FileCopyrightText: Copyright 2022 yuzu Emulator Project
// SPDX-FileCopyrightText: Copyright 2025 citron Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <chrono>
#include <vector>

#include "core/hle/service/ldn/lan_discovery.h"
#include "core/hle/service/ldn/lan_protocol.h"
#include "core/internal_network/network.h"
#include "core/internal_network/network_interface.h"
#include "core/internal_network/sockets.h"

namespace Service::LDN {

LanStation::LanStation(s8 node_id_, LANDiscovery* discovery_)
    : node_info(nullptr), status(NodeStatus::Disconnected), node_id(node_id_),
      discovery(discovery_) {}

LanStation::~LanStation() = default;

NodeStatus LanStation::GetStatus() const {
    return status;
}

void LanStation::OnClose() {
    LOG_INFO(Service_LDN, "OnClose {}", node_id);
    Reset();
    discovery->UpdateNodes();
}

void LanStation::Reset() {
    status = NodeStatus::Disconnected;
};

void LanStation::OverrideInfo() {
    bool connected = GetStatus() == NodeStatus::Connected;
    node_info->node_id = node_id;
    node_info->is_connected = connected ? 1 : 0;
}

LANDiscovery::LANDiscovery(Network::RoomNetwork& room_network_)
    // Braced (not parenthesised) init: LanStation now holds a unique_ptr and so
    // is non-copyable, and the parenthesised form copy-constructs from a
    // temporary array. This direct-initialises each element in place.
    : stations{{{1, this}, {2, this}, {3, this}, {4, this}, {5, this}, {6, this}, {7, this}}},
      room_network{room_network_} {}

LANDiscovery::~LANDiscovery() {
    if (inited) {
        Result rc = Finalize();
        LOG_INFO(Service_LDN, "Finalize: {}", rc.raw);
    }
}

void LANDiscovery::InitNetworkInfo() {
    network_info.common.bssid = GetFakeMac();
    network_info.common.channel = WifiChannel::Wifi24_6;
    network_info.common.link_level = LinkLevel::Good;
    network_info.common.network_type = PackedNetworkType::Ldn;
    network_info.common.ssid = fake_ssid;

    auto& nodes = network_info.ldn.nodes;
    for (std::size_t i = 0; i < NodeCountMax; i++) {
        nodes[i].node_id = static_cast<s8>(i);
        nodes[i].is_connected = 0;
    }
}

void LANDiscovery::InitNodeStateChange() {
    for (auto& node_update : node_changes) {
        node_update.state_change = NodeStateChange::None;
    }
    for (auto& node_state : node_last_states) {
        node_state = 0;
    }
}

State LANDiscovery::GetState() const {
    return state;
}

void LANDiscovery::SetState(State new_state) {
    state = new_state;
}

Result LANDiscovery::GetNetworkInfo(NetworkInfo& out_network) const {
    std::scoped_lock lock{packet_mutex};
    if (state == State::AccessPointCreated || state == State::StationConnected) {
        std::memcpy(&out_network, &network_info, sizeof(network_info));
        return ResultSuccess;
    }
    return ResultBadState;
}

Result LANDiscovery::GetNetworkInfo(NetworkInfo& out_network,
                                    std::span<NodeLatestUpdate> out_updates) {
    std::scoped_lock lock{packet_mutex};
    if (out_updates.size() > NodeCountMax) {
        return ResultInvalidBufferCount;
    }

    if (state == State::AccessPointCreated || state == State::StationConnected) {
        std::memcpy(&out_network, &network_info, sizeof(network_info));
        for (std::size_t i = 0; i < out_updates.size(); i++) {
            out_updates[i].state_change = node_changes[i].state_change;
            node_changes[i].state_change = NodeStateChange::None;
        }
        return ResultSuccess;
    }

    return ResultBadState;
}

DisconnectReason LANDiscovery::GetDisconnectReason() const {
    return disconnect_reason;
}

Result LANDiscovery::Scan(std::span<NetworkInfo> out_networks, s16& out_count,
                          const ScanFilter& filter) {
    {
        std::scoped_lock lock{packet_mutex};
        scan_results.clear();

        SendBroadcast(Network::LDNPacketType::Scan);
    }

    LOG_INFO(Service_LDN, "Waiting for scan replies");
    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::scoped_lock lock{packet_mutex};
    for (const auto& [key, info] : scan_results) {
        if (out_count >= static_cast<s16>(out_networks.size())) {
            break;
        }

        if (IsFlagSet(filter.flag, ScanFilterFlag::LocalCommunicationId)) {
            if (filter.network_id.intent_id.local_communication_id !=
                info.network_id.intent_id.local_communication_id) {
                continue;
            }
        }
        if (IsFlagSet(filter.flag, ScanFilterFlag::SessionId)) {
            if (filter.network_id.session_id != info.network_id.session_id) {
                continue;
            }
        }
        if (IsFlagSet(filter.flag, ScanFilterFlag::NetworkType)) {
            if (filter.network_type != static_cast<NetworkType>(info.common.network_type)) {
                continue;
            }
        }
        if (IsFlagSet(filter.flag, ScanFilterFlag::Ssid)) {
            if (filter.ssid != info.common.ssid) {
                continue;
            }
        }
        if (IsFlagSet(filter.flag, ScanFilterFlag::SceneId)) {
            if (filter.network_id.intent_id.scene_id != info.network_id.intent_id.scene_id) {
                continue;
            }
        }

        out_networks[out_count++] = info;
    }

    return ResultSuccess;
}

Result LANDiscovery::SetAdvertiseData(std::span<const u8> data) {
    std::scoped_lock lock{packet_mutex};
    const std::size_t size = data.size();
    if (size > AdvertiseDataSizeMax) {
        return ResultAdvertiseDataTooLarge;
    }

    std::memcpy(network_info.ldn.advertise_data.data(), data.data(), size);
    network_info.ldn.advertise_data_size = static_cast<u16>(size);

    UpdateNodes();

    return ResultSuccess;
}

Result LANDiscovery::OpenAccessPoint() {
    std::scoped_lock lock{packet_mutex};
    disconnect_reason = DisconnectReason::None;
    if (state == State::None) {
        return ResultBadState;
    }

    ResetStations();
    SetState(State::AccessPointOpened);

    return ResultSuccess;
}

Result LANDiscovery::CloseAccessPoint() {
    std::scoped_lock lock{packet_mutex};
    if (state == State::None) {
        return ResultBadState;
    }

    if (state == State::AccessPointCreated) {
        DestroyNetwork();
    }

    ResetStations();
    SetState(State::Initialized);

    return ResultSuccess;
}

Result LANDiscovery::OpenStation() {
    std::scoped_lock lock{packet_mutex};
    disconnect_reason = DisconnectReason::None;
    if (state == State::None) {
        return ResultBadState;
    }

    ResetStations();
    SetState(State::StationOpened);

    return ResultSuccess;
}

Result LANDiscovery::CloseStation() {
    std::scoped_lock lock{packet_mutex};
    if (state == State::None) {
        return ResultBadState;
    }

    if (state == State::StationConnected) {
        Disconnect();
    }

    ResetStations();
    SetState(State::Initialized);

    return ResultSuccess;
}

Result LANDiscovery::CreateNetwork(const SecurityConfig& security_config,
                                   const UserConfig& user_config,
                                   const NetworkConfig& network_config) {
    std::scoped_lock lock{packet_mutex};

    if (state != State::AccessPointOpened) {
        return ResultBadState;
    }

    InitNetworkInfo();
    network_info.ldn.node_count_max = network_config.node_count_max;
    network_info.ldn.security_mode = security_config.security_mode;

    if (network_config.channel == WifiChannel::Default) {
        network_info.common.channel = WifiChannel::Wifi24_6;
    } else {
        network_info.common.channel = network_config.channel;
    }

    std::independent_bits_engine<std::mt19937, 64, u64> bits_engine;
    network_info.network_id.session_id.high = bits_engine();
    network_info.network_id.session_id.low = bits_engine();
    network_info.network_id.intent_id = network_config.intent_id;

    NodeInfo& node0 = network_info.ldn.nodes[0];
    const Result rc2 = GetNodeInfo(node0, user_config, network_config.local_communication_version);
    if (rc2.IsError()) {
        return ResultAccessPointConnectionFailed;
    }

    SetState(State::AccessPointCreated);

    InitNodeStateChange();
    node0.is_connected = 1;
    UpdateNodes();

    return rc2;
}

Result LANDiscovery::DestroyNetwork() {
    for (auto local_ip : connected_clients) {
        SendPacket(Network::LDNPacketType::DestroyNetwork, local_ip);
    }

    ResetStations();

    SetState(State::AccessPointOpened);
    lan_event();

    return ResultSuccess;
}

Result LANDiscovery::Connect(const NetworkInfo& network_info_, const UserConfig& user_config,
                             u16 local_communication_version) {
    // The setup below needs packet_mutex, but the wait afterwards must NOT
    // hold it -- see the comment on that wait.
    {
        std::scoped_lock lock{packet_mutex};
        if (network_info_.ldn.node_count == 0) {
            return ResultInvalidNodeCount;
        }

        Result rc = GetNodeInfo(node_info, user_config, local_communication_version);
        if (rc.IsError()) {
            return ResultConnectionFailed;
        }

        Ipv4Address node_host = network_info_.ldn.nodes[0].ipv4_address;
        std::reverse(std::begin(node_host), std::end(node_host)); // htonl
        host_ip = node_host;
        SendPacket(Network::LDNPacketType::Connect, node_info, *host_ip);

        InitNodeStateChange();
    }

    // Wait for the host's SyncNetwork instead of ldn_mitm's blind one-second
    // sleep, which this was ported from.
    //
    // That sleep is wrong here in a way it is not on real hardware. ldn_mitm
    // sleeps without holding anything, so SyncNetwork is processed while it
    // sleeps and the state is already StationConnected when connect() returns.
    // Eden's ReceivePacket() takes packet_mutex for its whole body, so sleeping
    // while holding that lock blocks the poll thread from processing the reply
    // at all: the packet cannot be handled until the sleep ends, no matter how
    // fast the host answered. Measured against a real Switch, SyncNetwork was
    // consistently "received" 1.01s after Connect -- that was the lock
    // releasing, not the network.
    //
    // So: poll outside the lock, and confirm we are actually in the node list
    // rather than trusting that any SyncNetwork arrived -- a stale or unrelated
    // sync must not be mistaken for a successful join.
    constexpr auto kPollInterval = std::chrono::milliseconds(10);
    constexpr int kPollAttempts = 300; // 3s, vs ldn_mitm's fixed 1s
    for (int attempt = 0; attempt < kPollAttempts; attempt++) {
        {
            std::scoped_lock lock{packet_mutex};
            if (state == State::StationConnected && IsSelfInNodeList()) {
                LOG_INFO(Service_LDN, "LDN join confirmed after {}ms",
                         attempt * kPollInterval.count());
                return ResultSuccess;
            }
        }
        std::this_thread::sleep_for(kPollInterval);
    }

    // The original returned success unconditionally. If the host never syncs,
    // that tells the game it joined and leaves it waiting on nodes forever;
    // failing lets it surface a proper error instead.
    LOG_ERROR(Service_LDN, "LDN join timed out: no SyncNetwork listing us after {}ms",
              kPollAttempts * kPollInterval.count());
    {
        std::scoped_lock lock{packet_mutex};
        if (host_socket) {
            host_socket->Close();
            host_socket.reset();
        }
        host_ip = std::nullopt;
    }
    return ResultConnectionFailed;
}

bool LANDiscovery::IsSelfInNodeList() const {
    // Node entries carry ipv4_address byte-reversed (see GetNodeInfo, which
    // reverses on the way out), so compare in that same form rather than
    // reversing a copy of every entry.
    Ipv4Address self = GetLocalIp();
    std::reverse(std::begin(self), std::end(self));

    const auto count = std::min<size_t>(network_info.ldn.node_count, NodeCountMax);
    for (size_t i = 0; i < count; i++) {
        if (network_info.ldn.nodes[i].ipv4_address == self) {
            return true;
        }
    }
    return false;
}

Result LANDiscovery::Disconnect() {
    if (host_ip) {
        SendPacket(Network::LDNPacketType::Disconnect, node_info, *host_ip);
    }

    SetState(State::StationOpened);
    lan_event();

    return ResultSuccess;
}

Result LANDiscovery::Initialize(LanEventFunc lan_event_, bool listening) {
    std::scoped_lock lock{packet_mutex};
    if (inited) {
        return ResultSuccess;
    }

    for (auto& station : stations) {
        station.discovery = this;
        station.node_info = &network_info.ldn.nodes[station.node_id];
        station.Reset();
    }

    connected_clients.clear();
    lan_event = lan_event_;

    if (!OpenTransport()) {
        LOG_ERROR(Service_LDN, "LDN native transport failed to start; LDN will not work");
    }

    SetState(State::Initialized);

    inited = true;
    LOG_INFO(Service_LDN, "LANDiscovery initialized (listening={})", listening);
    return ResultSuccess;
}

Result LANDiscovery::Finalize() {
    // Stop the worker before taking packet_mutex: the worker acquires that same
    // mutex, so joining while holding it would deadlock.
    transport_running = false;
    if (transport_thread.joinable()) {
        transport_thread.join();
    }

    std::scoped_lock lock{packet_mutex};
    Result rc = ResultSuccess;

    if (inited) {
        if (state == State::AccessPointCreated) {
            DestroyNetwork();
        }
        if (state == State::StationConnected) {
            Disconnect();
        }

        ResetStations();
        inited = false;
    }

    CloseTransport();
    SetState(State::None);

    LOG_INFO(Service_LDN, "LANDiscovery finalized");
    return rc;
}

void LANDiscovery::ResetStations() {
    for (auto& station : stations) {
        station.Reset();
    }
    connected_clients.clear();
}

void LANDiscovery::UpdateNodes() {
    u8 count = 0;
    for (auto& station : stations) {
        bool connected = station.GetStatus() == NodeStatus::Connected;
        if (connected) {
            count++;
        }
        station.OverrideInfo();
    }

    // Node Count Guard: Ensure we always report at least 1 node
    network_info.ldn.node_count = std::max<u8>(1, count + 1);

    for (auto local_ip : connected_clients) {
        SendPacket(Network::LDNPacketType::SyncNetwork, network_info, local_ip);
    }

    OnNetworkInfoChanged();
}

void LANDiscovery::OnSyncNetwork(const NetworkInfo& info) {
    network_info = info;

    if (state == State::StationOpened) {
        SetState(State::StationConnected);
    }
    OnNetworkInfoChanged();
}

void LANDiscovery::OnDisconnectFromHost() {
    LOG_INFO(Service_LDN, "OnDisconnectFromHost state: {}", static_cast<int>(state));
    host_ip = std::nullopt;
    if (state == State::StationConnected) {
        SetState(State::StationOpened);
        lan_event();
    }
}

void LANDiscovery::OnNetworkInfoChanged() {
    if (IsNodeStateChanged()) {
        lan_event();
    }
    return;
}

bool LANDiscovery::GetVirtualIpConfig(Network::IPv4Address& out_address,
                                      Network::IPv4Address& out_mask) const {
    if (lan_config.virtual_ip == Network::IPv4Address{0, 0, 0, 0}) {
        return false;
    }
    out_address = lan_config.virtual_ip;
    out_mask = lan_config.virtual_mask;
    return true;
}

Network::IPv4Address LANDiscovery::GetLocalIp() const {
    // This address goes into NodeInfo.ipv4Address, which is what a peer console
    // dials when it opens its TCP connection back to us -- so it has to be an
    // address that is reachable *on the lan-play virtual LAN*, not merely one
    // that is correct locally.
    //
    // On real hardware those are the same thing: ldn_mitm calls
    // nifmGetCurrentIpAddress and the console really is sitting on 10.13.0.0/16,
    // because its system network settings were configured that way by hand.
    // Eden cannot do that -- Android does not allow the system IP to be
    // overridden, so our sockets are bound on the phone's hotspot address
    // (10.149.x.x), which means nothing to a real Switch. The PC-side bridge
    // represents us on the virtual LAN instead, and virtual_ip is the address
    // it presents on our behalf. Report that, or the peer will try to connect
    // to an address that does not exist on its network and the session will
    // die silently after a successful scan.
    if (lan_config.virtual_ip != Network::IPv4Address{0, 0, 0, 0}) {
        return lan_config.virtual_ip;
    }

    // Unset: fall back to the socket's own address, which is correct whenever
    // Eden really is on the virtual LAN (a desktop build with a 10.13.x.y
    // interface, or a future Android VpnService).
    Network::IPv4Address local_ip{0xFF, 0xFF, 0xFF, 0xFF};
    if (udp_socket) {
        const auto [addr, err] = udp_socket->GetSockName();
        if (err == Network::Errno::SUCCESS && addr.ip != Network::IPv4Address{0, 0, 0, 0}) {
            return addr.ip;
        }
    }
    if (const auto host_ipv4 = Network::GetHostIPv4Address()) {
        local_ip = *host_ipv4;
    }
    return local_ip;
}

template <typename Data>
void LANDiscovery::SendPacket(Network::LDNPacketType type, const Data& data,
                              Ipv4Address remote_ip) {
    Network::LDNPacket packet;
    packet.type = type;

    packet.broadcast = false;
    packet.local_ip = GetLocalIp();
    packet.remote_ip = remote_ip;

    packet.data.resize(sizeof(data));
    std::memcpy(packet.data.data(), &data, sizeof(data));
    SendPacket(packet);
}

void LANDiscovery::SendPacket(Network::LDNPacketType type, Ipv4Address remote_ip) {
    Network::LDNPacket packet;
    packet.type = type;

    packet.broadcast = false;
    packet.local_ip = GetLocalIp();
    packet.remote_ip = remote_ip;

    SendPacket(packet);
}

template <typename Data>
void LANDiscovery::SendBroadcast(Network::LDNPacketType type, const Data& data) {
    Network::LDNPacket packet;
    packet.type = type;

    packet.broadcast = true;
    packet.local_ip = GetLocalIp();

    packet.data.resize(sizeof(data));
    std::memcpy(packet.data.data(), &data, sizeof(data));
    SendPacket(packet);
}

void LANDiscovery::SendBroadcast(Network::LDNPacketType type) {
    Network::LDNPacket packet;
    packet.type = type;

    packet.broadcast = true;
    packet.local_ip = GetLocalIp();

    SendPacket(packet);
}

void LANDiscovery::SendPacket(const Network::LDNPacket& packet) {
    // Route by message type, exactly as ldn_mitm does on real hardware:
    //   Scan / ScanResp   -> UDP (broadcast for Scan, unicast reply for ScanResp)
    //   Connect           -> TCP, station -> host
    //   SyncNetwork       -> TCP, host -> each connected station
    //   Disconnect /
    //   DestroyNetwork    -> no wire message; close the TCP connection instead
    switch (packet.type) {
    case Network::LDNPacketType::Scan:
        SendOverUdp(packet.type, packet.data, nullptr);
        return;
    case Network::LDNPacketType::ScanResp:
        SendOverUdp(packet.type, packet.data, &packet.remote_ip);
        return;
    case Network::LDNPacketType::Connect:
        ConnectToHost(packet.remote_ip, packet.data);
        return;
    case Network::LDNPacketType::SyncNetwork: {
        for (auto& station : stations) {
            if (station.GetStatus() == NodeStatus::Connected && station.socket) {
                SendOverTcp(*station.socket, packet.type, packet.data);
            }
        }
        return;
    }
    case Network::LDNPacketType::Disconnect:
    case Network::LDNPacketType::DestroyNetwork:
    default:
        // Teardown is signaled by closing the connection, never by a packet.
        if (host_socket) {
            host_socket->Close();
            host_socket.reset();
        }
        for (auto& station : stations) {
            if (station.socket) {
                station.socket->Close();
                station.socket.reset();
            }
        }
        return;
    }
}

bool LANDiscovery::SendOverUdp(Network::LDNPacketType type, std::span<const u8> data,
                               const Ipv4Address* remote_ip) {
    if (!udp_socket) {
        return false;
    }
    LanPacketType wire_type{};
    if (!ToLanPacketType(type, wire_type)) {
        return false;
    }

    std::array<u8, LanProtocolBufferSize> buffer{};
    if (sizeof(LanPacketHeader) + data.size() > buffer.size()) {
        LOG_ERROR(Service_LDN, "LDN packet too large to send: {}", data.size());
        return false;
    }

    auto* header = reinterpret_cast<LanPacketHeader*>(buffer.data());
    header->magic = LanProtocolMagic;
    header->type = wire_type;
    header->compressed = 0;
    header->length = static_cast<u16>(data.size());
    header->decompress_length = static_cast<u16>(data.size());
    header->reserved[0] = 0;
    header->reserved[1] = 0;

    if (!data.empty()) {
        std::memcpy(buffer.data() + sizeof(LanPacketHeader), data.data(), data.size());
    }
    const size_t total = sizeof(LanPacketHeader) + data.size();

    Network::SockAddrIn addr{};
    addr.family = Network::Domain::INET;
    addr.portno = lan_config.port;
    addr.ip = remote_ip ? *remote_ip : lan_config.broadcast_address;

    const auto [sent, err] = udp_socket->SendTo(0, std::span<const u8>(buffer.data(), total), &addr);
    if (err != Network::Errno::SUCCESS) {
        LOG_ERROR(Service_LDN, "LDN UDP send FAILED type={} payload={} to {}.{}.{}.{}:{} errno={}",
                  static_cast<int>(wire_type), data.size(), addr.ip[0], addr.ip[1], addr.ip[2],
                  addr.ip[3], addr.portno, static_cast<int>(err));
        return false;
    }
    LOG_DEBUG(Service_LDN, "LDN UDP sent type={} payload={} total={} to {}.{}.{}.{}:{}",
              static_cast<int>(wire_type), data.size(), total, addr.ip[0], addr.ip[1], addr.ip[2],
              addr.ip[3], addr.portno);
    return sent > 0;
}

bool LANDiscovery::SendOverTcp(Network::SocketBase& socket, Network::LDNPacketType type,
                               std::span<const u8> data) {
    LanPacketType wire_type{};
    if (!ToLanPacketType(type, wire_type)) {
        return false;
    }

    std::array<u8, LanProtocolBufferSize> buffer{};
    if (sizeof(LanPacketHeader) + data.size() > buffer.size()) {
        LOG_ERROR(Service_LDN, "LDN packet too large to send: {}", data.size());
        return false;
    }

    auto* header = reinterpret_cast<LanPacketHeader*>(buffer.data());
    header->magic = LanProtocolMagic;
    header->type = wire_type;
    header->compressed = 0;
    header->length = static_cast<u16>(data.size());
    header->decompress_length = static_cast<u16>(data.size());
    header->reserved[0] = 0;
    header->reserved[1] = 0;

    if (!data.empty()) {
        std::memcpy(buffer.data() + sizeof(LanPacketHeader), data.data(), data.size());
    }
    const size_t total = sizeof(LanPacketHeader) + data.size();

    const auto [sent, err] = socket.Send(std::span<const u8>(buffer.data(), total), 0);
    if (err != Network::Errno::SUCCESS) {
        LOG_ERROR(Service_LDN, "LDN TCP send FAILED type={} payload={} errno={}",
                  static_cast<int>(wire_type), data.size(), static_cast<int>(err));
        return false;
    }
    LOG_DEBUG(Service_LDN, "LDN TCP sent type={} payload={} total={}", static_cast<int>(wire_type),
              data.size(), total);
    return sent > 0;
}

bool LANDiscovery::ConnectToHost(Ipv4Address host, std::span<const u8> connect_payload) {
    auto socket = std::make_unique<Network::Socket>();
    if (socket->Initialize(Network::Domain::INET, Network::Type::STREAM, Network::Protocol::TCP) !=
        Network::Errno::SUCCESS) {
        LOG_ERROR(Service_LDN, "Failed to create LDN host socket");
        return false;
    }

    Network::SockAddrIn addr{};
    addr.family = Network::Domain::INET;
    addr.portno = lan_config.port;
    addr.ip = host;

    LOG_INFO(Service_LDN, "LDN connecting to host {}.{}.{}.{}:{}", host[0], host[1], host[2],
             host[3], lan_config.port);
    if (const auto err = socket->Connect(addr); err != Network::Errno::SUCCESS) {
        LOG_ERROR(Service_LDN, "Failed to connect to LDN host {}.{}.{}.{}:{} errno={}", host[0],
                  host[1], host[2], host[3], lan_config.port, static_cast<int>(err));
        return false;
    }
    LOG_INFO(Service_LDN, "LDN connected to host, sending Connect ({} bytes)",
             connect_payload.size());

    host_socket = std::move(socket);
    return SendOverTcp(*host_socket, Network::LDNPacketType::Connect, connect_payload);
}

void LANDiscovery::HandleLanData(std::span<const u8> buf, Ipv4Address remote_ip) {
    if (buf.size() < sizeof(LanPacketHeader)) {
        return;
    }
    LanPacketHeader header{};
    std::memcpy(&header, buf.data(), sizeof(header));
    if (header.magic != LanProtocolMagic) {
        LOG_WARNING(Service_LDN, "Dropping LDN packet with bad magic {:#x}", header.magic);
        return;
    }

    const std::span<const u8> body = buf.subspan(sizeof(LanPacketHeader));
    if (body.size() < header.length) {
        LOG_WARNING(Service_LDN, "Truncated LDN packet: have {}, want {}", body.size(),
                    header.length);
        return;
    }

    LOG_DEBUG(Service_LDN,
              "LDN recv type={} compressed={} len={} declen={} from {}.{}.{}.{}",
              static_cast<int>(header.type), header.compressed, header.length,
              header.decompress_length, remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3]);

    Network::LDNPacket packet;
    packet.type = FromLanPacketType(header.type);
    packet.remote_ip = remote_ip;
    packet.local_ip = remote_ip; // sender's address, as the state machine expects
    packet.broadcast = false;

    if (header.compressed) {
        std::array<u8, LanProtocolBufferSize> out{};
        size_t out_size = 0;
        if (!LanDecompress(body.data(), header.length, out.data(), out.size(), out_size)) {
            LOG_WARNING(Service_LDN, "Failed to decompress LDN packet");
            return;
        }
        packet.data.assign(out.begin(), out.begin() + out_size);
    } else {
        packet.data.assign(body.begin(), body.begin() + header.length);
    }

    ReceivePacket(packet);
}

bool LANDiscovery::OpenTransport() {
    lan_config = LoadLanNetworkConfig();

    auto udp = std::make_unique<Network::Socket>();
    if (udp->Initialize(Network::Domain::INET, Network::Type::DGRAM, Network::Protocol::UDP) !=
        Network::Errno::SUCCESS) {
        LOG_ERROR(Service_LDN, "Failed to create LDN UDP socket");
        return false;
    }
    udp->SetReuseAddr(true);
    udp->SetBroadcast(true);
    udp->SetNonBlock(true);

    Network::SockAddrIn bind_addr{};
    bind_addr.family = Network::Domain::INET;
    bind_addr.portno = lan_config.port;
    bind_addr.ip = lan_config.bind_address;
    if (udp->Bind(bind_addr) != Network::Errno::SUCCESS) {
        LOG_ERROR(Service_LDN, "Failed to bind LDN UDP socket on {}.{}.{}.{}:{}",
                  bind_addr.ip[0], bind_addr.ip[1], bind_addr.ip[2], bind_addr.ip[3],
                  lan_config.port);
        return false;
    }

    auto tcp = std::make_unique<Network::Socket>();
    if (tcp->Initialize(Network::Domain::INET, Network::Type::STREAM, Network::Protocol::TCP) !=
        Network::Errno::SUCCESS) {
        LOG_ERROR(Service_LDN, "Failed to create LDN TCP socket");
        return false;
    }
    tcp->SetReuseAddr(true);
    tcp->SetNonBlock(true);
    if (tcp->Bind(bind_addr) != Network::Errno::SUCCESS) {
        LOG_ERROR(Service_LDN, "Failed to bind LDN TCP socket on {}.{}.{}.{}:{}", bind_addr.ip[0],
                  bind_addr.ip[1], bind_addr.ip[2], bind_addr.ip[3], lan_config.port);
        return false;
    }
    if (tcp->Listen(StationCountMax) != Network::Errno::SUCCESS) {
        LOG_ERROR(Service_LDN, "Failed to listen on LDN TCP socket");
        return false;
    }

    udp_socket = std::move(udp);
    tcp_listen_socket = std::move(tcp);

    transport_running = true;
    transport_thread = std::thread(&LANDiscovery::TransportWorker, this);

    LOG_INFO(Service_LDN,
             "LDN native transport up: bind {}.{}.{}.{} port {} (udp+tcp), broadcast "
             "{}.{}.{}.{}",
             lan_config.bind_address[0], lan_config.bind_address[1], lan_config.bind_address[2],
             lan_config.bind_address[3], lan_config.port, lan_config.broadcast_address[0],
             lan_config.broadcast_address[1], lan_config.broadcast_address[2],
             lan_config.broadcast_address[3]);
    return true;
}

void LANDiscovery::CloseTransport() {
    transport_running = false;
    if (transport_thread.joinable()) {
        transport_thread.join();
    }
    if (host_socket) {
        host_socket->Close();
        host_socket.reset();
    }
    for (auto& station : stations) {
        if (station.socket) {
            station.socket->Close();
            station.socket.reset();
        }
    }
    if (tcp_listen_socket) {
        tcp_listen_socket->Close();
        tcp_listen_socket.reset();
    }
    if (udp_socket) {
        udp_socket->Close();
        udp_socket.reset();
    }
}

void LANDiscovery::TransportWorker() {
    while (transport_running) {
        PollTransportOnce();
    }
}

void LANDiscovery::PollTransportOnce() {
    std::vector<Network::PollFD> poll_fds;
    std::vector<Network::SocketBase*> sources;

    const auto add = [&](Network::SocketBase* socket) {
        if (socket == nullptr) {
            return;
        }
        poll_fds.push_back(Network::PollFD{socket, Network::PollEvents::In, {}});
        sources.push_back(socket);
    };

    {
        std::scoped_lock lock{packet_mutex};
        add(udp_socket.get());
        add(tcp_listen_socket.get());
        add(host_socket.get());
        for (auto& station : stations) {
            add(station.socket.get());
        }
    }

    if (poll_fds.empty()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return;
    }

    const auto [count, err] = Network::Poll(poll_fds, 100);
    if (err != Network::Errno::SUCCESS || count <= 0) {
        return;
    }

    for (size_t i = 0; i < poll_fds.size(); i++) {
        if ((poll_fds[i].revents & Network::PollEvents::In) == Network::PollEvents{}) {
            continue;
        }
        Network::SocketBase* socket = sources[i];

        if (socket == udp_socket.get()) {
            std::array<u8, LanProtocolBufferSize> buffer{};
            Network::SockAddrIn from{};
            const auto [received, recv_err] = socket->RecvFrom(0, buffer, &from);
            if (recv_err == Network::Errno::SUCCESS && received > 0) {
                HandleLanData(std::span<const u8>(buffer.data(), static_cast<size_t>(received)),
                              from.ip);
            }
            continue;
        }

        if (socket == tcp_listen_socket.get()) {
            auto [result, accept_err] = socket->Accept();
            if (accept_err != Network::Errno::SUCCESS || !result.socket) {
                continue;
            }
            std::scoped_lock lock{packet_mutex};
            bool placed = false;
            for (auto& station : stations) {
                if (!station.socket) {
                    result.socket->SetNonBlock(true);
                    station.socket = std::move(result.socket);
                    station.peer_ip = result.sockaddr_in.ip;
                    placed = true;
                    LOG_INFO(Service_LDN, "LDN station connected: node_id={} from {}.{}.{}.{}",
                             station.node_id, result.sockaddr_in.ip[0], result.sockaddr_in.ip[1],
                             result.sockaddr_in.ip[2], result.sockaddr_in.ip[3]);
                    break;
                }
            }
            if (!placed) {
                LOG_WARNING(Service_LDN, "Rejecting LDN station, all slots full");
                result.socket->Close();
            }
            continue;
        }

        // Station connection (host role) or the host connection (station role).
        std::array<u8, LanProtocolBufferSize> buffer{};
        const auto [received, recv_err] = socket->Recv(0, buffer);
        if (recv_err != Network::Errno::SUCCESS || received <= 0) {
            // Closed connection == disconnect. There is no wire message.
            std::scoped_lock lock{packet_mutex};
            if (socket == host_socket.get()) {
                LOG_INFO(Service_LDN, "LDN host connection closed (errno={}, received={})",
                         static_cast<int>(recv_err), received);
                host_socket->Close();
                host_socket.reset();
                OnDisconnectFromHost();
            } else {
                for (auto& station : stations) {
                    if (station.socket.get() == socket) {
                        LOG_INFO(Service_LDN, "LDN station {} disconnected (errno={})",
                                 station.node_id, static_cast<int>(recv_err));
                        station.socket->Close();
                        station.socket.reset();
                        station.peer_ip = Ipv4Address{};
                        station.OnClose();
                        break;
                    }
                }
            }
            continue;
        }

        const auto [peer, peer_err] = socket->GetPeerName();
        const Ipv4Address peer_ip =
            peer_err == Network::Errno::SUCCESS ? peer.ip : Ipv4Address{0, 0, 0, 0};
        HandleLanData(std::span<const u8>(buffer.data(), static_cast<size_t>(received)), peer_ip);
    }
}

void LANDiscovery::ReceivePacket(const Network::LDNPacket& packet) {
    std::scoped_lock lock{packet_mutex};
    switch (packet.type) {
    case Network::LDNPacketType::Scan: {
        LOG_INFO(Frontend, "Scan packet received!");
        if (state == State::AccessPointCreated) {
            // Reply to the sender
            SendPacket(Network::LDNPacketType::ScanResp, network_info, packet.local_ip);
        }
        break;
    }
    case Network::LDNPacketType::ScanResp: {
        LOG_INFO(Frontend, "ScanResp packet received! Data size: {}", packet.data.size());

        if (packet.data.size() < sizeof(NetworkInfo)) {
            LOG_WARNING(Service_LDN, "ScanResp packet data too small: {} bytes, expected: {} bytes",
                       packet.data.size(), sizeof(NetworkInfo));
            break;
        }

        NetworkInfo info{};
        std::memcpy(&info, packet.data.data(), sizeof(NetworkInfo));
        scan_results.insert({info.common.bssid, info});

        LOG_DEBUG(Service_LDN, "ScanResp added to results. BSSID: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}, "
                  "Total results: {}",
                  info.common.bssid.raw[0], info.common.bssid.raw[1], info.common.bssid.raw[2],
                  info.common.bssid.raw[3], info.common.bssid.raw[4], info.common.bssid.raw[5],
                  scan_results.size());

        break;
    }
    case Network::LDNPacketType::Connect: {
        LOG_INFO(Frontend, "Connect packet received! Data size: {}", packet.data.size());

        if (packet.data.size() < sizeof(NodeInfo)) {
            LOG_WARNING(Service_LDN, "Connect packet data too small: {} bytes, expected: {} bytes",
                       packet.data.size(), sizeof(NodeInfo));
            break;
        }

        NodeInfo info{};
        std::memcpy(&info, packet.data.data(), sizeof(NodeInfo));

        connected_clients.push_back(packet.local_ip);

        // Prefer the station whose accepted socket this actually arrived on.
        // Picking "first station that isn't Connected" (the original
        // behaviour) races when two stations connect before either sends its
        // Connect packet, landing NodeInfo in the wrong slot.
        LanStation* target = nullptr;
        for (LanStation& station : stations) {
            if (station.socket && station.peer_ip == packet.local_ip) {
                target = &station;
                break;
            }
        }
        if (target == nullptr) {
            for (LanStation& station : stations) {
                if (station.status != NodeStatus::Connected) {
                    target = &station;
                    break;
                }
            }
        }
        if (target != nullptr) {
            *target->node_info = info;
            target->status = NodeStatus::Connected;
        } else {
            LOG_WARNING(Service_LDN, "Connect received but no free station slot");
        }

        UpdateNodes();

        break;
    }
    case Network::LDNPacketType::Disconnect: {
        LOG_INFO(Frontend, "Disconnect packet received! Data size: {}", packet.data.size());

        connected_clients.erase(
            std::remove(connected_clients.begin(), connected_clients.end(), packet.local_ip),
            connected_clients.end());

        if (packet.data.size() < sizeof(NodeInfo)) {
            LOG_WARNING(Service_LDN, "Disconnect packet data too small: {} bytes, expected: {} bytes",
                       packet.data.size(), sizeof(NodeInfo));
            break;
        }

        NodeInfo info{};
        std::memcpy(&info, packet.data.data(), sizeof(NodeInfo));

        for (LanStation& station : stations) {
            if (station.status == NodeStatus::Connected &&
                station.node_info->mac_address == info.mac_address) {
                station.OnClose();
                break;
            }
        }

        break;
    }
    case Network::LDNPacketType::DestroyNetwork: {
        ResetStations();
        OnDisconnectFromHost();
        break;
    }
    case Network::LDNPacketType::SyncNetwork: {
        if (state == State::StationOpened || state == State::StationConnected) {
            if (packet.data.size() < sizeof(NetworkInfo)) {
                break;
            }

            NetworkInfo info{};
            std::memcpy(&info, packet.data.data(), sizeof(NetworkInfo));

            if (state == State::StationConnected) {
                if (std::memcmp(&info.network_id.session_id, &network_info.network_id.session_id, sizeof(SessionId)) != 0) {
                    break;
                }
            }

            LOG_INFO(Frontend, "SyncNetwork packet received!");
            OnSyncNetwork(info);
        } else {
            LOG_INFO(Frontend, "SyncNetwork packet received but in wrong State!");
        }

        break;
    }
    default: {
        LOG_INFO(Frontend, "ReceivePacket unhandled type {}", static_cast<int>(packet.type));
        break;
    }
    }
}

bool LANDiscovery::IsNodeStateChanged() {
    bool changed = false;
    const auto& nodes = network_info.ldn.nodes;
    for (int i = 0; i < NodeCountMax; i++) {
        if (nodes[i].is_connected != node_last_states[i]) {
            if (nodes[i].is_connected) {
                node_changes[i].state_change |= NodeStateChange::Connect;
            } else {
                node_changes[i].state_change |= NodeStateChange::Disconnect;
            }
            node_last_states[i] = nodes[i].is_connected;
            changed = true;
        }
    }
    return changed;
}

bool LANDiscovery::IsFlagSet(ScanFilterFlag flag, ScanFilterFlag search_flag) const {
    const auto flag_value = static_cast<u32>(flag);
    const auto search_flag_value = static_cast<u32>(search_flag);
    return (flag_value & search_flag_value) == search_flag_value;
}

int LANDiscovery::GetStationCount() const {
    return static_cast<int>(
        std::count_if(stations.begin(), stations.end(), [](const auto& station) {
            return station.GetStatus() != NodeStatus::Disconnected;
        }));
}

MacAddress LANDiscovery::GetFakeMac() const {
    MacAddress mac{};
    mac.raw[0] = 0x02;
    mac.raw[1] = 0x00;

    const auto ip = GetLocalIp();
    memcpy(mac.raw.data() + 2, &ip, sizeof(ip));

    return mac;
}

Result LANDiscovery::GetNodeInfo(NodeInfo& node, const UserConfig& userConfig,
                                 u16 localCommunicationVersion) {
    const auto network_interface = Network::GetSelectedNetworkInterface();

    if (!network_interface) {
        LOG_ERROR(Service_LDN, "No network interface available");
        return ResultNoIpAddress;
    }

    node.mac_address = GetFakeMac();
    node.is_connected = 1;
    std::memcpy(node.user_name.data(), userConfig.user_name.data(), UserNameBytesMax + 1);
    node.local_communication_version = localCommunicationVersion;

    Ipv4Address current_address = GetLocalIp();
    std::reverse(std::begin(current_address), std::end(current_address)); // ntohl
    node.ipv4_address = current_address;

    return ResultSuccess;
}

} // namespace Service::LDN
