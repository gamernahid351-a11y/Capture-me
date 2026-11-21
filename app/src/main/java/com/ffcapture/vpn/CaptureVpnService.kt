package com.ffcapture.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.ffcapture.R
import com.ffcapture.decoder.MessageIds
import com.ffcapture.decoder.PacketDecoder
import com.ffcapture.decoder.toHexString
import com.ffcapture.model.CaptureRepository
import com.ffcapture.model.Constants
import com.ffcapture.model.SessionKey
import com.ffcapture.ui.MainActivity
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * Android VPN-based packet capture service.
 *
 * Uses VpnService to create a TUN interface. All IP packets from allowed
 * apps (Free Fire) are routed through this service. We read raw IP packets,
 * identify TCP/UDP flows, decode payloads using the FF AES+Protobuf logic,
 * and forward them to the real destination while storing decoded packets in
 * CaptureRepository.
 *
 * Architecture:
 *   TUN fd  ──read──▶  IP parser  ──▶  TCP/UDP forwarder  ──▶  real server
 *                           │
 *                           └──▶  PacketDecoder  ──▶  CaptureRepository
 */
class CaptureVpnService : VpnService() {

    companion object {
        private const val TAG = "FFCaptureVPN"
        const val ACTION_START = "com.ffcapture.START_VPN"
        const val ACTION_STOP  = "com.ffcapture.STOP_VPN"
        private const val VPN_ADDRESS   = "10.0.0.2"
        private const val VPN_ROUTE     = "0.0.0.0"
        private const val VPN_DNS       = "8.8.8.8"
        private val ts = DateTimeFormatter
            .ofPattern("HH:mm:ss.SSS")
            .withZone(ZoneId.systemDefault())

        @Volatile var isRunning = false
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Active TCP/UDP connections tracked by 5-tuple
    private val tcpSessions = mutableMapOf<String, TcpSession>()
    private val udpSessions = mutableMapOf<String, UdpSession>()
    private val sessionLock = Any()

    // ─────────────────────────────────────────────────────────
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopCapture(); return START_NOT_STICKY
            }
        }
        startForeground(Constants.NOTIFICATION_ID, buildNotification())
        startCapture()
        return START_STICKY
    }

    override fun onDestroy() {
        stopCapture()
        scope.cancel()
        super.onDestroy()
    }

    // ─────────────────────────────────────────────────────────
    // VPN setup
    // ─────────────────────────────────────────────────────────
    private fun startCapture() {
        if (isRunning) return
        isRunning = true

        try {
            val builder = Builder()
                .setSession("FFCapture")
                .addAddress(VPN_ADDRESS, 24)
                .addRoute(VPN_ROUTE, 0)
                .addDnsServer(VPN_DNS)
                .setMtu(1500)

            // Restrict to Free Fire packages only
            listOf(
                "com.dts.freefireth",
                "com.dts.freefiremax"
            ).forEach { pkg ->
                try { builder.addAllowedApplication(pkg) }
                catch (_: Exception) { /* package not installed */ }
            }

            vpnInterface = builder.establish()
            Log.i(TAG, "VPN interface established")

            // Launch packet read loop
            vpnJob = scope.launch { packetLoop() }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN: ${e.message}")
            isRunning = false
        }
    }

    private fun stopCapture() {
        isRunning = false
        vpnJob?.cancel()
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
        synchronized(sessionLock) {
            tcpSessions.values.forEach { it.close() }
            tcpSessions.clear()
            udpSessions.values.forEach { it.close() }
            udpSessions.clear()
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "VPN stopped")
    }

    // ─────────────────────────────────────────────────────────
    // Main packet loop — reads raw IP packets from TUN fd
    // ─────────────────────────────────────────────────────────
    private suspend fun packetLoop() = withContext(Dispatchers.IO) {
        val fd = vpnInterface?.fileDescriptor ?: return@withContext
        val input  = FileInputStream(fd)
        val output = FileOutputStream(fd)
        val buf = ByteBuffer.allocate(32768)

        while (isRunning && isActive) {
            try {
                buf.clear()
                val len = input.channel.read(buf)
                if (len <= 0) { delay(1); continue }
                buf.flip()
                val packet = ByteArray(len).also { buf.get(it) }
                processIpPacket(packet, output)
            } catch (e: Exception) {
                if (isActive) Log.w(TAG, "packet loop error: ${e.message}")
            }
        }
    }

    // ─────────────────────────────────────────────────────────
    // IP packet parsing (IPv4 only)
    // ─────────────────────────────────────────────────────────
    private fun processIpPacket(packet: ByteArray, output: FileOutputStream) {
        if (packet.size < 20) return
        val version = (packet[0].toInt() and 0xFF) ushr 4
        if (version != 4) return                       // IPv6 not handled

        val ihl     = (packet[0].toInt() and 0x0F) * 4
        val proto   = packet[9].toInt() and 0xFF
        val srcIp   = packet.copyOfRange(12, 16)
        val dstIp   = packet.copyOfRange(16, 20)

        when (proto) {
            6  -> handleTcp(packet, ihl, srcIp, dstIp, output)
            17 -> handleUdp(packet, ihl, srcIp, dstIp, output)
        }
    }

    // ─────────────────────────────────────────────────────────
    // TCP handling
    // ─────────────────────────────────────────────────────────
    private fun handleTcp(
        packet: ByteArray, ihl: Int,
        srcIp: ByteArray, dstIp: ByteArray,
        output: FileOutputStream
    ) {
        if (packet.size < ihl + 20) return
        val srcPort = readUShort(packet, ihl)
        val dstPort = readUShort(packet, ihl + 2)
        val dataOff = ((packet[ihl + 12].toInt() and 0xFF) ushr 4) * 4
        val payload = packet.copyOfRange(ihl + dataOff, packet.size)

        if (payload.isEmpty()) return

        val dstIpStr = dstIp.joinToString(".") { (it.toInt() and 0xFF).toString() }
        val key = "${srcIp.toHexString()}:$srcPort-${dstIp.toHexString()}:$dstPort"

        val channel = when (dstPort) {
            Constants.TCP_ONLINE_PORT -> "TCP-online"
            Constants.TCP_CHAT_PORT   -> "TCP-chat"
            else                      -> "TCP-$dstPort"
        }

        // Decode the payload
        scope.launch { decodeTcpPayload(payload, channel, "C2S") }

        // Forward to real server
        scope.launch {
            forwardTcp(dstIpStr, dstPort, payload, channel, output, packet, ihl, srcIp, srcPort)
        }
    }

    private suspend fun decodeTcpPayload(payload: ByteArray, channel: String, direction: String) {
        try {
            val ptype = PacketDecoder.parseTcpType(payload) ?: "????"
            if (ptype in Constants.SKIP_PACKET_TYPES) return

            val isMajorLogin = channel == "TCP-online" && ptype == "0101"
            val dec = PacketDecoder.decode(payload, isMajorLogin)

            // Check for session key in MajorLogin response
            if (isMajorLogin && dec.protobufFlat != null) {
                extractSessionKey(dec.protobufFlat)
            }

            val p = CaptureRepository.makePacket(
                channel       = Constants.CHANNEL_TCP,
                direction     = direction,
                type          = ptype,
                rawHex        = payload.toHexString(),
                aesUsed       = dec.aesUsed,
                decryptedHex  = dec.plainHex,
                protobufFlat  = dec.protobufFlat,
                protobufTree  = dec.protobufTree,
                deepScan      = dec.deepScan.ifEmpty { null }
            )
            CaptureRepository.addPacket(p)
        } catch (e: Exception) {
            Log.w(TAG, "TCP decode error: ${e.message}")
        }
    }

    // ─────────────────────────────────────────────────────────
    // UDP handling
    // ─────────────────────────────────────────────────────────
    private fun handleUdp(
        packet: ByteArray, ihl: Int,
        srcIp: ByteArray, dstIp: ByteArray,
        output: FileOutputStream
    ) {
        if (packet.size < ihl + 8) return
        val srcPort = readUShort(packet, ihl)
        val dstPort = readUShort(packet, ihl + 2)
        val payload = packet.copyOfRange(ihl + 8, packet.size)
        if (payload.isEmpty()) return

        val dstIpStr = dstIp.joinToString(".") { (it.toInt() and 0xFF).toString() }

        scope.launch { decodeUdpPayload(payload, dstPort) }
        scope.launch { forwardUdp(dstIpStr, dstPort, payload, output, packet, ihl, srcIp, srcPort) }
    }

    private suspend fun decodeUdpPayload(payload: ByteArray, dstPort: Int) {
        try {
            val msgId   = PacketDecoder.parseUdpMsgId(payload) ?: return
            val msgName = MessageIds.getName(msgId)
            val dec     = PacketDecoder.decode(payload)
            val p = CaptureRepository.makePacket(
                channel       = Constants.CHANNEL_UDP,
                direction     = "C2S",
                type          = msgId.toString(16).padStart(4, '0'),
                msgName       = msgName,
                rawHex        = payload.toHexString(),
                aesUsed       = dec.aesUsed,
                decryptedHex  = dec.plainHex,
                protobufFlat  = dec.protobufFlat,
                protobufTree  = dec.protobufTree,
                deepScan      = dec.deepScan.ifEmpty { null }
            )
            CaptureRepository.addPacket(p)
        } catch (e: Exception) {
            Log.w(TAG, "UDP decode error: ${e.message}")
        }
    }

    // ─────────────────────────────────────────────────────────
    // Session key extraction from MajorLogin response
    // ─────────────────────────────────────────────────────────
    private fun extractSessionKey(flat: Map<String, Any>) {
        // Session key is typically field 3 (key) and field 4 (iv) in bytes
        val keyHex = flat["f3_bytes"] as? String ?: return
        val ivHex  = flat["f4_bytes"] as? String ?: flat["f3_bytes"] as? String ?: return
        if (keyHex.length != 32 || ivHex.length != 32) return

        val key = keyHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val iv  = ivHex.chunked(2).map  { it.toInt(16).toByte() }.toByteArray()
        PacketDecoder.sessionKey = key
        PacketDecoder.sessionIv  = iv

        val sk = SessionKey(
            timestamp = ts.format(Instant.now()),
            keyHex    = keyHex.uppercase(),
            ivHex     = ivHex.uppercase()
        )
        CaptureRepository.addSessionKey(sk)
        Log.i(TAG, "🔑 Session key captured: ${keyHex.uppercase()}")
    }

    // ─────────────────────────────────────────────────────────
    // Simple TCP/UDP forwarders (protect() bypasses the VPN)
    // ─────────────────────────────────────────────────────────
    private suspend fun forwardTcp(
        dstIp: String, dstPort: Int, payload: ByteArray,
        channel: String, output: FileOutputStream,
        origPacket: ByteArray, ihl: Int,
        srcIp: ByteArray, srcPort: Int
    ) {
        try {
            val ch = java.nio.channels.SocketChannel.open()
            protect(ch.socket())
            ch.connect(InetSocketAddress(dstIp, dstPort))
            ch.write(ByteBuffer.wrap(payload))
            val buf = ByteBuffer.allocate(65536)
            val len = ch.read(buf)
            if (len > 0) {
                buf.flip()
                val resp = ByteArray(len).also { buf.get(it) }
                // Decode S2C
                scope.launch { decodeTcpPayload(resp, channel, "S2C") }
                // Write response back through TUN (simplified — real impl needs IP header rebuild)
            }
            ch.close()
        } catch (_: Exception) {}
    }

    private suspend fun forwardUdp(
        dstIp: String, dstPort: Int, payload: ByteArray,
        output: FileOutputStream,
        origPacket: ByteArray, ihl: Int,
        srcIp: ByteArray, srcPort: Int
    ) {
        try {
            val ch = DatagramChannel.open()
            protect(ch.socket())
            ch.connect(InetSocketAddress(dstIp, dstPort))
            ch.write(ByteBuffer.wrap(payload))
            val buf = ByteBuffer.allocate(65536)
            val len = ch.read(buf)
            if (len > 0) {
                buf.flip()
                val resp = ByteArray(len).also { buf.get(it) }
                scope.launch { decodeUdpPayload(resp, dstPort) }
            }
            ch.close()
        } catch (_: Exception) {}
    }

    // ─────────────────────────────────────────────────────────
    // Notification
    // ─────────────────────────────────────────────────────────
    private fun buildNotification(): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(
                    Constants.NOTIFICATION_CHANNEL_ID,
                    "FF Capture",
                    NotificationManager.IMPORTANCE_LOW
                )
            )
        }
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, Constants.NOTIFICATION_CHANNEL_ID)
            .setContentTitle("FF Capture Active")
            .setContentText("Capturing Free Fire packets…")
            .setSmallIcon(R.drawable.ic_vpn)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    // ─────────────────────────────────────────────────────────
    private fun readUShort(buf: ByteArray, offset: Int): Int =
        ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)

    // Simple session holders (extend for full stateful tracking)
    inner class TcpSession { fun close() {} }
    inner class UdpSession { fun close() {} }
}
