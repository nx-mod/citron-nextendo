// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

package org.citron.citron_emu.utils

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import org.citron.citron_emu.R
import org.citron.citron_emu.activities.EmulationActivity
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Gives Eden a real address on the LDN virtual network.
 *
 * Android does not let an app change the system IP, so Eden's own address is
 * the phone's Wi-Fi address -- useless to a peer that expects everyone on
 * 10.13.0.0/16. Earlier attempts had a PC-side bridge rewrite addresses in
 * flight instead; that carries the LDN control protocol fine (discovery, join
 * and node admission all worked against a real Switch) but cannot carry the
 * game itself, because Pia's AES-GCM nonce embeds the sender's own source IP,
 * so a rewritten address breaks session decryption at the far end.
 *
 * This takes the address problem away rather than working around it. The TUN
 * established here gives the process a genuine 10.13.x.y identity, so
 * lan_discovery.cpp's ordinary OS sockets bind and report it with no
 * translation anywhere, and NodeInfo.ipv4Address is simply true.
 *
 * Raw IP packets the kernel routes into that range are forwarded to a bridge
 * on the PC over a plain TCP socket, length-prefixed, and injected onto the
 * LAN there so switch-lan-play sees Eden exactly as it sees the Switch.
 * Traffic to everything else is untouched, so normal Wi-Fi and mobile data
 * keep working.
 *
 * Ported from an earlier nx-mod branch, with configuration read from
 * ldn_network.ini instead of Settings.
 */
class LdnVpnService : VpnService() {
    companion object {
        const val ACTION_STOP = "org.citron.citron_emu.LDN_VPN_STOP"
        const val REQUEST_CODE_PREPARE = 0x4c44 // "LD"
        private const val NOTIFICATION_ID = 0x1001
        private const val BRIDGE_PORT = 24680

        // 1400, not the console's 1500, because every packet from this TUN
        // is re-encapsulated in a UDP datagram to the bridge. A 1500-byte
        // inner packet becomes 1500 + 8 (UDP) + 20 (IP) = 1528 on the wire,
        // over the LAN's own 1500 MTU, so the biggest and most important game
        // packets are dropped or fragmented rather than delivered.
        //
        // Measured: with the TUN at 1500 the game's 1460-byte payloads simply
        // stopped arriving -- the bridge saw to_lan fall from 1204 to 186
        // against an unchanged inbound rate. The TCP tunnel hid this by
        // segmenting the stream; UDP cannot.
        //
        // 1400 leaves room for that 28-byte overhead and happens to match the
        // relay's own RELAY_MTU, so packets that later cross the relay hop do
        // not need fragmenting there either.
        private const val TUNNEL_MTU = 1400
        private const val DEFAULT_ADDRESS = "10.13.37.100"
        private const val DEFAULT_MASK = "255.255.0.0"
        private const val RECONNECT_DELAY_MS = 2000L

        /**
         * Call from an Activity before emulation starts. Launches the system VPN consent
         * dialog if needed; once granted (or if already granted), starts the tunnel.
         * Returns true if the service was started immediately, false if consent is pending
         * (the activity's onActivityResult for REQUEST_CODE_PREPARE should retry this call).
         */
        fun prepareAndStart(activity: Activity): Boolean {
            val consentIntent = VpnService.prepare(activity)
            if (consentIntent != null) {
                activity.startActivityForResult(consentIntent, REQUEST_CODE_PREPARE)
                return false
            }
            activity.startService(Intent(activity, LdnVpnService::class.java))
            return true
        }

        /**
         * True when ldn_network.ini names a usable bridge host. Checked before
         * the consent dialog so users who never use LDN are not prompted.
         */
        fun isConfigured(): Boolean {
            val dir = DirectoryInitialization.userDirectory ?: return false
            val file = File("$dir/config/ldn_network.ini")
            if (!file.exists()) return false
            return try {
                file.readLines().any {
                    val line = it.trim()
                    !line.startsWith("#") && !line.startsWith(";") &&
                        line.startsWith("bridge_host") && line.contains('=') &&
                        line.substringAfter('=').trim().let { v ->
                            v.isNotEmpty() && !v.startsWith("127.")
                        }
                }
            } catch (e: Exception) {
                false
            }
        }

        fun stop(activity: Activity) {
            val stopIntent = Intent(activity, LdnVpnService::class.java)
            stopIntent.action = ACTION_STOP
            activity.startService(stopIntent)
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var bridgeSocket: DatagramSocket? = null
    private val running = AtomicBoolean(false)
    private var worker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            stopSelf()
            return START_NOT_STICKY
        }

        // A null intent means the system restarted this START_STICKY service
        // after killing our process. If the game is closed (the activity
        // cleared the session flag on stop) there is nothing to bridge --
        // do not resurrect the tunnel, or the "LDN bridge active" notification
        // and the reconnect loop keep running after Eden is gone. Restart for
        // real is kicked off by the activity next time emulation begins.
        if (intent == null && !EmulationActivity.isEmulationSessionActive()) {
            stopSelf()
            return START_NOT_STICKY
        }

        if (running.compareAndSet(false, true)) {
            showNotification()
            worker = Thread { runTunnel() }.also { it.start() }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    override fun onBind(intent: Intent?): android.os.IBinder? = super.onBind(intent)

    private fun runTunnel() {
        try {
            // Config comes from ldn_network.ini, the same file the C++ LDN
            // transport reads, rather than from Settings. One source of truth,
            // and it sidesteps a bug seen in the original of this service:
            // getString("ldn_bridge_host") could return the compiled default
            // "127.0.0.1" even with a real value saved, so the tunnel silently
            // dialled the phone's own loopback and was never reachable.
            val cfg = readLdnConfig()
            val address = cfg["virtual_ip"] ?: DEFAULT_ADDRESS
            val mask = cfg["virtual_mask"] ?: DEFAULT_MASK
            val bridgeHost = cfg["bridge_host"] ?: ""
            if (bridgeHost.isBlank() || bridgeHost.startsWith("127.")) {
                Log.error("[LdnVpnService] no usable bridge_host in ldn_network.ini " +
                    "(got '$bridgeHost') -- set it to the PC's address on this LAN. " +
                    "Not starting the tunnel.")
                return
            }
            Log.info("[LdnVpnService] tunnel $address/$mask -> bridge $bridgeHost:$BRIDGE_PORT")
            val prefixLen = maskToPrefixLength(mask)

            // Deliberately scoped to ONLY the fake LDN subnet -- a wider
            // RFC1918 route was tried here to fix the kernel's auto SYN-ACK
            // routing back to a real peer's real address, but it overlaps
            // the phone's own hotspot subnet (this setup's PC/Switch are
            // hotspot clients, e.g. 10.21.72.0/24), which pulled the
            // bridge-connection socket itself into the tunnel despite
            // protect() -- confirmed live: that socket's local address
            // showed up as the TUN's own 10.13.x.x address instead of the
            // phone's real one, and every reconnect timed out. Reverted;
            // the real fix needs a narrower, peer-specific route (or a
            // different mechanism entirely), not a blanket private-range one.
            val builder = Builder()
                .setSession("Eden LDN")
                .addAddress(address, prefixLen)
                .addRoute(networkAddress(address, prefixLen), prefixLen)
                // Real ldn_mitm sets the console's link MTU to 1500
                // (lan_discovery.cpp), and on real LDN hardware that is
                // correct. Here the path is not a real link: every packet is
                // re-encapsulated as a relay forwarder frame, and anything
                // over RELAY_MTU (1400) has to be split into Ipv4Frag chunks
                // and reassembled by the peer. At 1500 roughly 44% of the
                // game's packets needed fragmenting, and gameplay starved a
                // few seconds in. Advertising a smaller MTU makes the game's
                // own stack emit packets that fit a single relay frame, so
                // the fragmentation path is bypassed for ordinary traffic
                // rather than exercised constantly.
                .setMtu(TUNNEL_MTU)
            val iface = builder.establish()

            if (iface == null) {
                Log.error("[LdnVpnService] VpnService.Builder.establish() returned null")
                return
            }
            vpnInterface = iface

            while (running.get()) {
                try {
                    pumpUntilDisconnected(iface, bridgeHost)
                } catch (e: IOException) {
                    Log.warning("[LdnVpnService] bridge connection lost: ${e.message}")
                }
                if (running.get()) Thread.sleep(RECONNECT_DELAY_MS)
            }
        } catch (e: Exception) {
            Log.error("[LdnVpnService] tunnel failed: ${e.message}")
        } finally {
            running.set(false)
            vpnInterface?.let { runCatching { it.close() } }
            vpnInterface = null
        }
    }

    private fun pumpUntilDisconnected(iface: ParcelFileDescriptor, bridgeHost: String) {
        // UDP, not TCP. The tunnel carries a game's own UDP traffic, which is
        // loss-tolerant: a dropped position update should be discarded, not
        // retransmitted late. Over TCP a single lost segment blocks every
        // packet queued behind it -- head-of-line blocking -- so one loss
        // stalls the whole session for a round trip even though the packets
        // behind it arrived fine. That was still causing heavy in-race lag
        // after disabling Nagle. Datagram boundaries also give us framing for
        // free, so the length prefix TCP needed is gone.
        val socket = DatagramSocket(null)
        socket.reuseAddress = true
        protect(socket)
        // protect() only exempts this socket from the VPN tunnel -- it still
        // routes via whatever the SYSTEM's default network is, per its own
        // docs ("bound to the current default network interface"). With
        // hotspot mode active and no separate WiFi-client connection, that
        // default is cellular data, not the hotspot's own local interface --
        // confirmed live via the connect failure's own local address showing
        // 192.0.0.2, Android's well-known CLAT/464XLAT address used when
        // routing over an IPv6-only cellular network. Cellular obviously has
        // no path to a private LAN peer. Binding this socket's local address
        // to whatever real interface actually owns the target's subnet
        // forces the kernel to route out that interface directly instead of
        // consulting "default network" at all.
        val local = findLocalAddressForPeer(bridgeHost)
        socket.bind(InetSocketAddress(local ?: java.net.InetAddress.getByName("0.0.0.0"), 0))
        val peer = InetSocketAddress(java.net.InetAddress.getByName(bridgeHost), BRIDGE_PORT)
        bridgeSocket = socket

        val tunIn = FileInputStream(iface.fileDescriptor)
        val tunOut = FileOutputStream(iface.fileDescriptor)

        // Announce ourselves so the bridge learns where to send replies. UDP
        // has no connection for it to accept, so until it has heard from us it
        // has nowhere to put inbound traffic. Repeated below on a timer in
        // case the bridge restarts mid-session.
        val hello = ByteArray(0)
        runCatching { socket.send(DatagramPacket(hello, 0, peer)) }

        val tunToBridge = Thread {
            val buf = ByteArray(TUNNEL_MTU + 64)
            try {
                while (running.get() && !socket.isClosed) {
                    val len = tunIn.read(buf)
                    if (len <= 0) continue
                    socket.send(DatagramPacket(buf, len, peer))
                }
            } catch (_: IOException) {
                // socket closed from the other thread below; fall through and exit.
            }
        }
        tunToBridge.start()

        try {
            val buf = ByteArray(TUNNEL_MTU + 64)
            while (running.get()) {
                val dp = DatagramPacket(buf, buf.size)
                socket.receive(dp)
                if (dp.length <= 0) continue
                tunOut.write(buf, 0, dp.length)
            }
        } finally {
            runCatching { socket.close() }
            tunToBridge.interrupt()
            tunToBridge.join(1000)
        }
    }

    private fun lengthPrefix(len: Int): ByteArray = byteArrayOf(
        (len ushr 24).toByte(),
        (len ushr 16).toByte(),
        (len ushr 8).toByte(),
        len.toByte()
    )

    private fun readFully(input: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val read = input.read(buf, off, buf.size - off)
            if (read < 0) throw IOException("bridge socket closed")
            off += read
        }
    }

    private fun stopTunnel() {
        running.set(false)
        runCatching { bridgeSocket?.close() }
        runCatching { vpnInterface?.close() }
        vpnInterface = null
        worker?.interrupt()
        worker = null
        NotificationManagerCompat.from(this).cancel(NOTIFICATION_ID)
    }

    private fun showNotification() {
        val builder = NotificationCompat.Builder(this, getString(R.string.notice_notification_channel_id))
            .setSmallIcon(R.drawable.ic_stat_notification_logo)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.ldn_bridge_notification))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setVibrate(null)
            .setSound(null)
        startForeground(NOTIFICATION_ID, builder.build())
    }

    /**
     * Finds a real (non-VPN) local IPv4 address whose own interface subnet
     * contains [peerHost], so the bridge socket can be bound to it directly
     * instead of trusting protect()'s "default network" choice. Skips the
     * VPN's own TUN interface (that address is the fake 10.13.x.x one, not
     * a real route to anything) and loopback/down interfaces.
     */
    private fun findLocalAddressForPeer(peerHost: String): Inet4Address? {
        try {
            val peer = parseIpv4(peerHost)
            var fallback: Inet4Address? = null
            val interfaces = NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val iface = interfaces.nextElement()
                if (!iface.isUp || iface.isLoopback || iface.isVirtual) continue
                for (ifaceAddr in iface.interfaceAddresses) {
                    val addr = ifaceAddr.address as? Inet4Address ?: continue
                    // Skip this app's own TUN address -- it is the fake LDN
                    // address, not a real route to anything.
                    if (addr.hostAddress?.startsWith("10.13.") == true) continue
                    if (fallback == null) fallback = addr
                    if (peer == null) continue
                    val prefix = ifaceAddr.networkPrefixLength.toInt()
                    val mask = if (prefix == 0) 0 else (-1 shl (32 - prefix))
                    val addrInt = ipv4ToInt(addr.address)
                    if ((addrInt and mask) == (peer and mask)) return addr
                }
            }
            return fallback
        } catch (e: Exception) {
            return null
        }
    }

    /**
     * Reads key=value pairs out of ldn_network.ini in Eden's config directory.
     * Comment lines (# or ;) and anything without an '=' are ignored, matching
     * how lan_protocol.cpp parses the same file. Returns an empty map if the
     * file is missing, which the caller treats as "do not start".
     */
    private fun readLdnConfig(): Map<String, String> {
        val dir = DirectoryInitialization.userDirectory
            ?: run {
                Log.error("[LdnVpnService] user directory unavailable")
                return emptyMap()
            }
        val file = File("$dir/config/ldn_network.ini")
        if (!file.exists()) {
            Log.error("[LdnVpnService] no ldn_network.ini at ${'$'}{file.absolutePath}")
            return emptyMap()
        }
        val out = HashMap<String, String>()
        try {
            file.forEachLine { raw ->
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) return@forEachLine
                val eq = line.indexOf('=')
                if (eq <= 0) return@forEachLine
                out[line.substring(0, eq).trim()] = line.substring(eq + 1).trim()
            }
        } catch (e: Exception) {
            Log.error("[LdnVpnService] failed reading ldn_network.ini: ${'$'}{e.message}")
        }
        return out
    }

    private fun parseIpv4(host: String): Int? = try {
        ipv4ToInt(host.split(".").map { it.toInt().toByte() }.toByteArray())
    } catch (e: Exception) {
        null
    }

    private fun ipv4ToInt(bytes: ByteArray): Int {
        var v = 0
        for (b in bytes) v = (v shl 8) or (b.toInt() and 0xFF)
        return v
    }

    private fun maskToPrefixLength(mask: String): Int = try {
        mask.split(".").sumOf { Integer.bitCount(it.toInt() and 0xFF) }
    } catch (e: Exception) {
        16
    }

    private fun networkAddress(address: String, prefixLen: Int): String = try {
        var addr = 0
        for (part in address.split(".")) addr = (addr shl 8) or (part.toInt() and 0xFF)
        val maskBits = if (prefixLen == 0) 0 else (-1 shl (32 - prefixLen))
        val net = addr and maskBits
        "${(net ushr 24) and 0xFF}.${(net ushr 16) and 0xFF}.${(net ushr 8) and 0xFF}.${net and 0xFF}"
    } catch (e: Exception) {
        address
    }
}
