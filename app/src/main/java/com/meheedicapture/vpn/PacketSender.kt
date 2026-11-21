package com.meheedicapture.vpn

import android.net.VpnService
import android.util.Log
import com.meheedicapture.decoder.PacketBuilder
import com.meheedicapture.decoder.PacketDecoder
import com.meheedicapture.decoder.RawField
import com.meheedicapture.decoder.fromHex
import com.meheedicapture.decoder.toHexString
import com.meheedicapture.model.CaptureRepository
import com.meheedicapture.model.Constants
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel

/**
 * Sends (re-sends) a crafted / edited packet over TCP or UDP.
 * Requires the VPN service to protect() the socket so it bypasses the TUN.
 */
object PacketSender {

    private const val TAG = "PacketSender"

    data class SendResult(
        val ok: Boolean,
        val sentHex: String,
        val responseHex: String?,
        val error: String? = null
    )

    // ─────────────────────────────────────────────────────────
    // Send raw hex over UDP to target
    // ─────────────────────────────────────────────────────────
    suspend fun sendUdp(
        rawHex: String,
        targetHost: String,
        targetPort: Int,
        vpnService: VpnService? = null
    ): SendResult = withContext(Dispatchers.IO) {
        try {
            val data = rawHex.fromHex()
            val sock = DatagramSocket()
            vpnService?.protect(sock)                     // bypass TUN
            val addr = InetAddress.getByName(targetHost)
            sock.send(DatagramPacket(data, data.size, addr, targetPort))

            // Try to read response (500 ms timeout)
            sock.soTimeout = 500
            val respBuf = ByteArray(65536)
            val respPkt = DatagramPacket(respBuf, respBuf.size)
            val respHex = try {
                sock.receive(respPkt)
                respBuf.copyOf(respPkt.length).toHexString()
            } catch (_: Exception) { null }

            sock.close()
            Log.i(TAG, "UDP sent ${data.size}B → $targetHost:$targetPort")
            SendResult(true, rawHex, respHex)
        } catch (e: Exception) {
            SendResult(false, rawHex, null, e.message)
        }
    }

    // ─────────────────────────────────────────────────────────
    // Send raw hex over TCP to target
    // ─────────────────────────────────────────────────────────
    suspend fun sendTcp(
        rawHex: String,
        targetHost: String,
        targetPort: Int,
        vpnService: VpnService? = null
    ): SendResult = withContext(Dispatchers.IO) {
        try {
            val data = rawHex.fromHex()
            val ch = SocketChannel.open()
            vpnService?.protect(ch.socket())
            ch.connect(InetSocketAddress(targetHost, targetPort))
            ch.write(ByteBuffer.wrap(data))

            // Try read response
            val buf = ByteBuffer.allocate(65536)
            ch.socket().soTimeout = 1000
            val len = try { ch.read(buf) } catch (_: Exception) { -1 }
            val respHex = if (len > 0) {
                buf.flip()
                ByteArray(len).also { buf.get(it) }.toHexString()
            } else null

            ch.close()
            Log.i(TAG, "TCP sent ${data.size}B → $targetHost:$targetPort")
            SendResult(true, rawHex, respHex)
        } catch (e: Exception) {
            SendResult(false, rawHex, null, e.message)
        }
    }

    // ─────────────────────────────────────────────────────────
    // Build & send a mark_info packet (high-level helper)
    // ─────────────────────────────────────────────────────────
    suspend fun sendMarkInfo(
        ownerId: Int,
        marks: List<PacketBuilder.MarkInfo>,
        seq: Int,
        flags: Int,
        teaKey: ByteArray?,
        udpMask: Int,
        targetHost: String,
        targetPort: Int,
        vpnService: VpnService? = null
    ): SendResult {
        val payload = PacketBuilder.buildMarkInfo(ownerId, marks)
        val packet  = PacketBuilder.serializePacket(seq, 970, 0, flags, payload, teaKey, udpMask)
        return sendUdp(packet.toHexString(), targetHost, targetPort, vpnService)
    }

    // ─────────────────────────────────────────────────────────
    // Rebuild edited fields → encrypt if needed → send
    // ─────────────────────────────────────────────────────────
    suspend fun sendEditedPacket(
        fields: List<RawField>,
        originalHeader: ByteArray,         // first N bytes (tcp/udp header to keep)
        headerSize: Int,
        isUdp: Boolean,
        targetHost: String,
        targetPort: Int,
        encryptWithSession: Boolean = false,
        vpnService: VpnService? = null
    ): SendResult {
        val body = PacketBuilder.rebuildFromFields(fields)
        val finalBody = if (encryptWithSession) {
            val sk = PacketDecoder.sessionKey
            val sv = PacketDecoder.sessionIv
            if (sk != null && sv != null) {
                PacketBuilder.aesEncrypt(body, sk, sv) ?: body
            } else body
        } else body

        val full = originalHeader.copyOf(headerSize) + finalBody
        val hex  = full.toHexString()

        return if (isUdp) sendUdp(hex, targetHost, targetPort, vpnService)
        else              sendTcp(hex, targetHost, targetPort, vpnService)
    }
}
