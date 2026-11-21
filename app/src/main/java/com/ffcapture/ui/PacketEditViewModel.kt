package com.ffcapture.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.ffcapture.decoder.PacketBuilder
import com.ffcapture.decoder.PacketDecoder
import com.ffcapture.decoder.RawField
import com.ffcapture.decoder.fromHex
import com.ffcapture.decoder.toHexString
import com.ffcapture.model.CaptureRepository
import com.ffcapture.model.Constants
import com.ffcapture.model.Packet
import com.ffcapture.vpn.PacketSender
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class PacketEditViewModel(app: Application) : AndroidViewModel(app) {

    private val _packet = MutableLiveData<Packet?>()
    val packet: LiveData<Packet?> = _packet

    private val _rawFields = MutableLiveData<List<RawField>>(emptyList())
    val rawFields: LiveData<List<RawField>> = _rawFields

    private val _rebuiltHex = MutableLiveData<String>("")
    val rebuiltHex: LiveData<String> = _rebuiltHex

    private val _sendResult = MutableLiveData<String?>()
    val sendResult: LiveData<String?> = _sendResult

    private val _varintResult = MutableLiveData<String?>()
    val varintResult: LiveData<String?> = _varintResult

    // Send target (editable by user)
    var targetHost: String = Constants.HOST_CLIENT
    var targetPort: Int    = Constants.UDP_MATCH_PORT
    var encryptWithSession = false

    // ── Load a packet and parse its fields ──
    fun loadPacket(p: Packet) {
        _packet.value = p
        try {
            val bytes = p.rawHex.fromHex()
            val fields = PacketBuilder.parseRawFields(bytes)
            _rawFields.value = fields
            _rebuiltHex.value = p.rawHex
        } catch (e: Exception) {
            _rawFields.value = emptyList()
        }
    }

    // ── Update a single field's value and rebuild hex ──
    fun updateField(index: Int, newValue: String) {
        val list = _rawFields.value?.toMutableList() ?: return
        if (index >= list.size) return
        list[index] = list[index].copy(editedValue = newValue)
        _rawFields.value = list
        rebuildHex()
    }

    // ── Rebuild raw hex from current fields ──
    private fun rebuildHex() {
        val fields = _rawFields.value ?: return
        try {
            val bytes = PacketBuilder.rebuildFromFields(fields)
            _rebuiltHex.value = bytes.toHexString()
        } catch (e: Exception) {
            _rebuiltHex.value = "ERROR: ${e.message}"
        }
    }

    // ── Set raw hex directly (bypass field parser) ──
    fun setRawHex(hex: String) {
        _rebuiltHex.value = hex.replace(" ", "").replace("\n", "").lowercase()
        // Re-parse fields
        try {
            val bytes = hex.fromHex()
            _rawFields.value = PacketBuilder.parseRawFields(bytes)
        } catch (_: Exception) {}
    }

    // ── Send the edited packet ──
    fun sendPacket(isUdp: Boolean) {
        val hex = _rebuiltHex.value?.takeIf { it.isNotEmpty() } ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val result = if (isUdp) {
                PacketSender.sendUdp(hex, targetHost, targetPort)
            } else {
                PacketSender.sendTcp(hex, targetHost, targetPort)
            }
            val msg = if (result.ok) {
                "✅ Sent ${hex.length / 2}B\n" +
                "Response: ${result.responseHex?.take(128) ?: "(none)"}"
            } else {
                "❌ Failed: ${result.error}"
            }
            _sendResult.postValue(msg)

            // Log response back to capture
            if (result.ok && result.responseHex != null) {
                val dec = PacketDecoder.decode(result.responseHex.fromHex())
                val p = CaptureRepository.makePacket(
                    channel      = if (isUdp) Constants.CHANNEL_UDP else Constants.CHANNEL_TCP,
                    direction    = "RESEND-S2C",
                    type         = "????",
                    rawHex       = result.responseHex,
                    decryptedHex = dec.plainHex,
                    protobufFlat = dec.protobufFlat,
                    protobufTree = dec.protobufTree,
                    deepScan     = dec.deepScan.ifEmpty { null }
                )
                CaptureRepository.addPacket(p)
            }
        }
    }

    // ── Varint tools ──
    fun computeVarint(input: String) {
        try {
            val v = input.trim().toLongOrNull()
                ?: input.trim().removePrefix("0x").toLongOrNull(16)
                ?: run { _varintResult.value = "Invalid number"; return }

            val varBytes  = PacketBuilder.encodeVarint(v)
            val zigBytes  = PacketBuilder.encodeZigZag(v)
            val sb = StringBuilder()
            sb.appendLine("Value   : $v (0x${v.toString(16).uppercase()})")
            sb.appendLine("Varint  : ${varBytes.toHexString()}  (${varBytes.size}B)")
            sb.appendLine("ZigZag  : ${zigBytes.toHexString()}  (${zigBytes.size}B)")

            // Reverse: decode varint bytes
            val (decoded, n) = PacketBuilder.decodeVarint(varBytes)
            sb.appendLine("Decoded : $decoded  ($n bytes consumed)")
            _varintResult.value = sb.toString()
        } catch (e: Exception) {
            _varintResult.value = "Error: ${e.message}"
        }
    }

    fun clearSendResult() { _sendResult.value = null }
    fun clearVarintResult() { _varintResult.value = null }

    // ── Build mark_info and populate hex editor ──
    fun buildMarkInfoPacket(
        ownerId: Int,
        marks: List<PacketBuilder.MarkInfo>,
        seq: Int,
        flags: Int,
        teaKeyHex: String,
        udpMask: Int
    ) {
        try {
            val teaKey = if (teaKeyHex.length == 32) teaKeyHex.fromHex() else null
            val payload = PacketBuilder.buildMarkInfo(ownerId, marks)
            val packet  = PacketBuilder.serializePacket(seq, 970, 0, flags, payload, teaKey, udpMask)
            setRawHex(packet.toHexString())
            _sendResult.postValue("✅ mark_info built: ${packet.size}B")
        } catch (e: Exception) {
            _sendResult.postValue("❌ Build error: ${e.message}")
        }
    }
}
