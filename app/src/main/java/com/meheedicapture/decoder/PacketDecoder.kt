package com.meheedicapture.decoder

import com.meheedicapture.model.Constants
import com.meheedicapture.model.ScanEntry
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PKCS7Padding
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

/**
 * Packet decoder: AES-CBC decrypt + simple protobuf wire-format parser.
 * Mirrors the Python capture.py logic.
 */
object PacketDecoder {

    // ── session key (set after MajorLogin) ──
    @Volatile var sessionKey: ByteArray? = null
    @Volatile var sessionIv:  ByteArray? = null

    data class DecodeResult(
        val aesUsed:      String?,
        val plainBytes:   ByteArray?,
        val plainHex:     String?,
        val protobufFlat: Map<String, Any>?,
        val protobufTree: Any?,
        val deepScan:     List<ScanEntry>
    )

    // ─────────────────────────────────────────────────────────
    // AES decrypt (CBC / PKCS7)
    // ─────────────────────────────────────────────────────────
    private fun aesDecrypt(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray? {
        return try {
            val cipher = PaddedBufferedBlockCipher(CBCBlockCipher(AESEngine()), PKCS7Padding())
            cipher.init(false, ParametersWithIV(KeyParameter(key), iv))
            val out = ByteArray(cipher.getOutputSize(data.size))
            val len = cipher.processBytes(data, 0, data.size, out, 0)
            val total = len + cipher.doFinal(out, len)
            out.copyOf(total)
        } catch (_: Exception) { null }
    }

    // ─────────────────────────────────────────────────────────
    // Try multiple offsets (like capture.py)
    // ─────────────────────────────────────────────────────────
    fun tryDecrypt(raw: ByteArray, isMajorLogin: Boolean = false): Triple<String?, ByteArray?, String?> {
        val offset = if (isMajorLogin) Constants.MAJOR_LOGIN_OFFSET else 0
        val candidates: MutableList<Pair<String, ByteArray>> = mutableListOf()

        // Static key
        for (off in Constants.AES_OFFSETS) {
            val start = offset + off
            if (start >= raw.size) continue
            val slice = raw.copyOfRange(start, raw.size)
            val dec = aesDecrypt(slice, Constants.AES_KEY, Constants.AES_IV)
            if (dec != null && dec.isNotEmpty())
                candidates.add(Pair("static@$start", dec))
        }

        // Session key
        val sk = sessionKey; val sv = sessionIv
        if (sk != null && sv != null) {
            for (off in Constants.AES_OFFSETS) {
                val start = offset + off
                if (start >= raw.size) continue
                val slice = raw.copyOfRange(start, raw.size)
                val dec = aesDecrypt(slice, sk, sv)
                if (dec != null && dec.isNotEmpty())
                    candidates.add(Pair("session@$start", dec))
            }
        }

        // Pick best candidate (longest valid result)
        val best = candidates.maxByOrNull { it.second.size } ?: return Triple(null, null, null)
        return Triple(best.first, best.second, best.second.toHexString())
    }

    // ─────────────────────────────────────────────────────────
    // Simple protobuf wire-format decoder (no .proto needed)
    // Returns flat map + nested tree
    // ─────────────────────────────────────────────────────────
    fun decodeProtobuf(data: ByteArray): Pair<Map<String, Any>, Any?> {
        val flat = mutableMapOf<String, Any>()
        val tree = mutableListOf<Map<String, Any>>()

        var idx = 0
        var fieldCount = 0

        fun readVarint(): Long {
            var result = 0L; var shift = 0
            while (idx < data.size) {
                val b = data[idx++].toLong() and 0xFF
                result = result or ((b and 0x7F) shl shift)
                if ((b and 0x80) == 0L) break
                shift += 7
            }
            return result
        }

        while (idx < data.size && fieldCount < 200) {
            val tag = try { readVarint() } catch (_: Exception) { break }
            if (tag == 0L) break
            val fieldNum = (tag ushr 3).toInt()
            val wireType = (tag and 0x7).toInt()

            val entry = mutableMapOf<String, Any>("field" to fieldNum, "wire" to wireType)

            when (wireType) {
                0 -> { // varint
                    val v = readVarint()
                    entry["type"] = "varint"
                    entry["value"] = v
                    flat["f${fieldNum}_int"] = v
                }
                1 -> { // 64-bit
                    if (idx + 8 > data.size) break
                    val bytes = data.copyOfRange(idx, idx + 8)
                    idx += 8
                    entry["type"] = "64bit"
                    entry["value"] = bytes.toHexString()
                    flat["f${fieldNum}_64b"] = bytes.toHexString()
                }
                2 -> { // length-delimited
                    val len = readVarint().toInt()
                    if (len < 0 || idx + len > data.size) break
                    val bytes = data.copyOfRange(idx, idx + len)
                    idx += len

                    // Try to interpret as UTF-8 string
                    val str = try {
                        val s = bytes.toString(Charsets.UTF_8)
                        if (s.all { it.code in 32..126 || it == '\n' || it == '\r' }) s else null
                    } catch (_: Exception) { null }

                    if (str != null && str.isNotBlank()) {
                        entry["type"] = "string"
                        entry["value"] = str
                        flat["f${fieldNum}_str"] = str
                    } else {
                        entry["type"] = "bytes"
                        entry["value"] = bytes.toHexString()
                        entry["len"] = len
                        flat["f${fieldNum}_bytes"] = bytes.toHexString()
                        // Try nested protobuf
                        if (len > 2) {
                            val nested = try { decodeProtobuf(bytes).first } catch (_: Exception) { null }
                            if (nested != null && nested.isNotEmpty()) {
                                entry["nested"] = nested
                            }
                        }
                    }
                }
                5 -> { // 32-bit
                    if (idx + 4 > data.size) break
                    val bytes = data.copyOfRange(idx, idx + 4)
                    idx += 4
                    entry["type"] = "32bit"
                    entry["value"] = bytes.toHexString()
                    flat["f${fieldNum}_32b"] = bytes.toHexString()
                }
                else -> break
            }
            tree.add(entry)
            fieldCount++
        }
        return Pair(flat, if (tree.isEmpty()) null else tree)
    }

    // ─────────────────────────────────────────────────────────
    // Deep scan: find UIDs, team codes, strings
    // ─────────────────────────────────────────────────────────
    fun deepScan(tree: Any?): List<ScanEntry> {
        val results = mutableListOf<ScanEntry>()
        fun scan(node: Any?, path: String) {
            when (node) {
                is Map<*, *> -> node.forEach { (k, v) -> scan(v, "$path.$k") }
                is List<*>   -> node.forEachIndexed { i, v -> scan(v, "$path[$i]") }
                is Long, is Int -> {
                    val lv = (node as Number).toLong()
                    val tag = when {
                        lv.toString().length in 8..12 -> "◀ uid?"
                        lv in 100000L..9999999L       -> "◀ team_code?"
                        else -> null
                    }
                    results.add(ScanEntry(path, "int", lv.toString(), tag))
                }
                is String -> {
                    if (node.length in 15..60 && !node.all { it.isDigit() })
                        results.add(ScanEntry(path, "str", node.take(80), "◀ gid?"))
                    else if (node.length in 1..200)
                        results.add(ScanEntry(path, "str", node.take(80)))
                }
            }
        }
        scan(tree, "root")
        return results
    }

    // ─────────────────────────────────────────────────────────
    // Full decode pipeline for a raw packet byte array
    // ─────────────────────────────────────────────────────────
    fun decode(raw: ByteArray, isMajorLogin: Boolean = false): DecodeResult {
        val (aesUsed, plain, plainHex) = tryDecrypt(raw, isMajorLogin)
        val (flat, tree) = if (plain != null && plain.size > 2)
            decodeProtobuf(plain)
        else
            Pair(emptyMap<String, Any>(), null)
        val scan = deepScan(tree)
        return DecodeResult(aesUsed, plain, plainHex, flat.ifEmpty { null }, tree, scan)
    }

    // ─────────────────────────────────────────────────────────
    // Parse packet type from TCP header (bytes 0-1, little-endian)
    // ─────────────────────────────────────────────────────────
    fun parseTcpType(data: ByteArray): String? {
        if (data.size < 2) return null
        val t = ((data[1].toInt() and 0xFF) shl 8) or (data[0].toInt() and 0xFF)
        return t.toString(16).padStart(4, '0')
    }

    // ─────────────────────────────────────────────────────────
    // Extract UDP message ID (little-endian short at some offset)
    // ─────────────────────────────────────────────────────────
    fun parseUdpMsgId(data: ByteArray, offset: Int = 0): Int? {
        if (data.size < offset + 2) return null
        return ((data[offset + 1].toInt() and 0xFF) shl 8) or (data[offset].toInt() and 0xFF)
    }
}

fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }
fun String.fromHex(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()
