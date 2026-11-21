package com.ffcapture.decoder

import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PKCS7Padding
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Port of the Python helper functions:
 *
 *   def var(v): encodeVarint
 *   def zz(v):  encodeZigZag (signed int → varint)
 *   def build_mark_info(owner_id, infos): builds RUDP_MAPMARK_CHANGED payload
 *   serialize_packet(seq, msg_id, sub, flags, payload, tea_key, udp_mask)
 */
object PacketBuilder {

    // ─────────────────────────────────────────────────────────
    // Varint encoding  (Python: def var(v))
    // ─────────────────────────────────────────────────────────
    fun encodeVarint(value: Long): ByteArray {
        var v = value
        val out = mutableListOf<Byte>()
        while (true) {
            val b = (v and 0x7F).toByte()
            v = v ushr 7
            out.add(if (v != 0L) (b.toInt() or 0x80).toByte() else b)
            if (v == 0L) break
        }
        return out.toByteArray()
    }

    fun encodeVarint(value: Int): ByteArray = encodeVarint(value.toLong())

    // ─────────────────────────────────────────────────────────
    // ZigZag + varint  (Python: def zz(v))
    // zz(v) = var((v << 1) ^ (v >> 63))
    // ─────────────────────────────────────────────────────────
    fun encodeZigZag(value: Long): ByteArray {
        val zz = (value shl 1) xor (value shr 63)
        return encodeVarint(zz)
    }

    fun encodeZigZag(value: Int): ByteArray = encodeZigZag(value.toLong())

    // ─────────────────────────────────────────────────────────
    // Decode varint from ByteArray at offset → Pair(value, bytesConsumed)
    // ─────────────────────────────────────────────────────────
    fun decodeVarint(data: ByteArray, offset: Int = 0): Pair<Long, Int> {
        var result = 0L
        var shift = 0
        var i = offset
        while (i < data.size) {
            val b = data[i++].toLong() and 0xFF
            result = result or ((b and 0x7F) shl shift)
            if ((b and 0x80) == 0L) break
            shift += 7
        }
        return Pair(result, i - offset)
    }

    fun decodeZigZag(data: ByteArray, offset: Int = 0): Pair<Long, Int> {
        val (zz, n) = decodeVarint(data, offset)
        return Pair((zz ushr 1) xor -(zz and 1L), n)
    }

    // ─────────────────────────────────────────────────────────
    // Protobuf field builders
    // ─────────────────────────────────────────────────────────
    fun protoFieldVarint(fieldNum: Int, value: Long): ByteArray {
        val tag = encodeVarint((fieldNum.toLong() shl 3) or 0L)
        return tag + encodeVarint(value)
    }

    fun protoFieldBytes(fieldNum: Int, data: ByteArray): ByteArray {
        val tag = encodeVarint((fieldNum.toLong() shl 3) or 2L)
        return tag + encodeVarint(data.size.toLong()) + data
    }

    fun protoFieldString(fieldNum: Int, s: String): ByteArray =
        protoFieldBytes(fieldNum, s.toByteArray(Charsets.UTF_8))

    // ─────────────────────────────────────────────────────────
    // build_mark_info(owner_id, infos)  — Python port
    //
    // infos: list of dicts with keys:
    //   TarPlayID, MarkerType, MarkFlag, ScannerMarkFlag
    // ─────────────────────────────────────────────────────────
    data class MarkInfo(
        val tarPlayId: Int,
        val markerType: Int,
        val markFlag: Int,
        val scannerMarkFlag: Int
    )

    fun buildMarkInfo(ownerId: Int, infos: List<MarkInfo>): ByteArray {
        val out = ByteArrayBuilder()
        out += encodeVarint(ownerId)             // owner_id
        out += encodeZigZag(infos.size)          // count (zigzag)
        for (m in infos) {
            out += encodeVarint(m.tarPlayId)
            out += byteArrayOf((m.markerType and 0xFF).toByte())
            out += encodeVarint(m.markFlag)
            out += encodeVarint(m.scannerMarkFlag)
        }
        return out.toByteArray()
    }

    // ─────────────────────────────────────────────────────────
    // serialize_packet(seq, msg_id, sub, flags, payload, tea_key, udp_mask)
    //
    // FF UDP packet header format (best-effort reconstruction):
    //   [0..1]  msg_id   LE uint16
    //   [2]     sub      uint8
    //   [3]     flags    uint8
    //   [4..7]  seq      LE uint32
    //   [8..]   payload  (AES encrypted if tea_key set)
    // ─────────────────────────────────────────────────────────
    fun serializePacket(
        seq: Int,
        msgId: Int,
        sub: Int,
        flags: Int,
        payload: ByteArray,
        teaKey: ByteArray? = null,
        udpMask: Int = 0
    ): ByteArray {
        val header = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(msgId.toShort())
            put(sub.toByte())
            put(flags.toByte())
            putInt(seq)
        }.array()

        val body = if (teaKey != null && teaKey.size == 16) {
            aesEncrypt(payload, teaKey, teaKey) ?: payload
        } else payload

        val raw = header + body

        // Apply udpMask XOR if set
        return if (udpMask != 0) {
            raw.map { (it.toInt() xor udpMask).toByte() }.toByteArray()
        } else raw
    }

    // ─────────────────────────────────────────────────────────
    // AES-CBC encrypt helper
    // ─────────────────────────────────────────────────────────
    fun aesEncrypt(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray? {
        return try {
            val cipher = PaddedBufferedBlockCipher(CBCBlockCipher(AESEngine()), PKCS7Padding())
            cipher.init(true, ParametersWithIV(KeyParameter(key), iv))
            val out = ByteArray(cipher.getOutputSize(data.size))
            val len = cipher.processBytes(data, 0, data.size, out, 0)
            val total = len + cipher.doFinal(out, len)
            out.copyOf(total)
        } catch (_: Exception) { null }
    }

    // ─────────────────────────────────────────────────────────
    // Parse raw hex edit back to structured fields
    // ─────────────────────────────────────────────────────────
    fun parseRawFields(data: ByteArray): List<RawField> {
        val fields = mutableListOf<RawField>()
        var i = 0
        while (i < data.size) {
            val start = i
            // Try varint
            var v = 0L; var shift = 0; var ok = false
            while (i < data.size) {
                val b = data[i++].toLong() and 0xFF
                v = v or ((b and 0x7F) shl shift)
                if ((b and 0x80) == 0L) { ok = true; break }
                shift += 7
                if (shift > 63) break
            }
            if (!ok) break
            val wireType = (v and 0x7).toInt()
            val fieldNum = (v ushr 3).toInt()
            when (wireType) {
                0 -> {
                    var fv = 0L; var fs = 0
                    while (i < data.size) {
                        val b = data[i++].toLong() and 0xFF
                        fv = fv or ((b and 0x7F) shl fs)
                        if ((b and 0x80) == 0L) break
                        fs += 7
                    }
                    fields.add(RawField(fieldNum, wireType, "varint", fv.toString(), null))
                }
                2 -> {
                    var len = 0L; var ls = 0
                    while (i < data.size) {
                        val b = data[i++].toLong() and 0xFF
                        len = len or ((b and 0x7F) shl ls)
                        if ((b and 0x80) == 0L) break
                        ls += 7
                    }
                    val end = minOf(i + len.toInt(), data.size)
                    val bytes = data.copyOfRange(i, end); i = end
                    val str = try {
                        val s = bytes.toString(Charsets.UTF_8)
                        if (s.all { it.code in 32..126 }) s else null
                    } catch (_: Exception) { null }
                    fields.add(RawField(fieldNum, wireType, if (str != null) "string" else "bytes",
                        str ?: bytes.toHexString(), bytes))
                }
                5 -> {
                    if (i + 4 <= data.size) {
                        val b = data.copyOfRange(i, i + 4); i += 4
                        fields.add(RawField(fieldNum, wireType, "fixed32", b.toHexString(), b))
                    }
                }
                1 -> {
                    if (i + 8 <= data.size) {
                        val b = data.copyOfRange(i, i + 8); i += 8
                        fields.add(RawField(fieldNum, wireType, "fixed64", b.toHexString(), b))
                    }
                }
                else -> break
            }
        }
        return fields
    }

    // ─────────────────────────────────────────────────────────
    // Rebuild packet from edited RawFields
    // ─────────────────────────────────────────────────────────
    fun rebuildFromFields(fields: List<RawField>): ByteArray {
        val out = ByteArrayBuilder()
        for (f in fields) {
            val tag = encodeVarint((f.fieldNum.toLong() shl 3) or f.wireType.toLong())
            out += tag
            when (f.wireType) {
                0 -> out += encodeVarint(f.editedValue.toLongOrNull() ?: 0L)
                2 -> {
                    val bytes = f.rawBytes
                        ?: f.editedValue.chunked(2).mapNotNull {
                            it.toIntOrNull(16)?.toByte()
                        }.toByteArray()
                    out += encodeVarint(bytes.size.toLong())
                    out += bytes
                }
                5 -> out += (f.rawBytes ?: ByteArray(4))
                1 -> out += (f.rawBytes ?: ByteArray(8))
            }
        }
        return out.toByteArray()
    }

    // Helper
    private class ByteArrayBuilder {
        private val list = mutableListOf<Byte>()
        operator fun plusAssign(b: ByteArray) { list.addAll(b.toList()) }
        operator fun plusAssign(b: Byte) { list.add(b) }
        fun toByteArray(): ByteArray = list.toByteArray()
    }
}

data class RawField(
    val fieldNum: Int,
    val wireType: Int,
    val type: String,         // "varint" / "bytes" / "string" / "fixed32" / "fixed64"
    var editedValue: String,  // editable
    val rawBytes: ByteArray?
)
