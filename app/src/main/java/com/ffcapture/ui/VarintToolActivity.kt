package com.ffcapture.ui

import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.MenuItem
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import com.ffcapture.R
import com.ffcapture.databinding.ActivityVarintToolBinding
import com.ffcapture.decoder.PacketBuilder

/**
 * Standalone Varint / ZigZag calculator:
 *
 *  • Encode: decimal / hex → varint bytes, zigzag bytes
 *  • Decode: hex bytes → decoded varint value
 *  • Build mark_info packet interactively
 */
class VarintToolActivity : AppCompatActivity() {

    private lateinit var b: ActivityVarintToolBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityVarintToolBinding.inflate(layoutInflater)
        setContentView(b.root)
        setSupportActionBar(b.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        title = "Varint / ZigZag Tool"

        // ── Encode section ──
        b.etEncodeInput.addTextChangedListener(tw { compute() })
        b.btnEncodeVarint.setOnClickListener { compute() }

        // ── Decode section ──
        b.btnDecodeVarint.setOnClickListener {
            try {
                val hex = b.etDecodeHex.text.toString().replace(" ", "")
                val bytes = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                val (v, n) = PacketBuilder.decodeVarint(bytes)
                val (zz, _) = PacketBuilder.decodeZigZag(bytes)
                b.tvDecodeResult.text =
                    "Varint : $v  (0x${v.toString(16).uppercase()})\n" +
                    "ZigZag : $zz\n" +
                    "Bytes consumed: $n / ${bytes.size}"
            } catch (e: Exception) {
                b.tvDecodeResult.text = "Error: ${e.message}"
            }
        }

        // ── mark_info builder ──
        b.btnBuildMark.setOnClickListener { buildMarkInfo() }
    }

    private fun compute() {
        val input = b.etEncodeInput.text.toString().trim()
        try {
            val v = input.toLongOrNull()
                ?: input.removePrefix("0x").removePrefix("0X").toLongOrNull(16)
                ?: run { b.tvEncodeResult.text = "Invalid"; return }

            val varBytes = PacketBuilder.encodeVarint(v)
            val zigBytes = PacketBuilder.encodeZigZag(v)

            val sb = StringBuilder()
            sb.appendLine("Decimal : $v")
            sb.appendLine("Hex     : 0x${v.toString(16).uppercase()}")
            sb.appendLine("Binary  : ${v.toString(2)}")
            sb.appendLine()
            sb.appendLine("── var(v) ──")
            sb.appendLine("  Bytes : ${varBytes.joinToString(" ") { "%02x".format(it) }}")
            sb.appendLine("  Size  : ${varBytes.size} byte(s)")
            sb.appendLine()
            sb.appendLine("── zz(v) = var((v<<1)^(v>>63)) ──")
            val zzRaw = (v shl 1) xor (v shr 63)
            sb.appendLine("  ZZ raw: $zzRaw")
            sb.appendLine("  Bytes : ${zigBytes.joinToString(" ") { "%02x".format(it) }}")
            sb.appendLine("  Size  : ${zigBytes.size} byte(s)")
            b.tvEncodeResult.text = sb.toString()
        } catch (e: Exception) {
            b.tvEncodeResult.text = "Error: ${e.message}"
        }
    }

    private fun buildMarkInfo() {
        try {
            val ownerId   = b.etMarkOwnerId.text.toString().toLong()
            val tarPlay   = b.etMarkTarPlay.text.toString().toLong()
            val mType     = b.etMarkType.text.toString().toInt()
            val mFlag     = b.etMarkFlag.text.toString().toLong()
            val sFlag     = b.etMarkScanFlag.text.toString().toLong()

            val mark = PacketBuilder.MarkInfo(
                tarPlayId      = tarPlay.toInt(),
                markerType     = mType,
                markFlag       = mFlag.toInt(),
                scannerMarkFlag = sFlag.toInt()
            )
            val payload = PacketBuilder.buildMarkInfo(ownerId.toInt(), listOf(mark))

            // Optionally serialize with header
            val seq   = b.etMarkSeq.text.toString().toIntOrNull() ?: 0
            val flags = b.etMarkFlags.text.toString().toIntOrNull() ?: 0
            val full  = PacketBuilder.serializePacket(seq, 970, 0, flags, payload)

            val sb = StringBuilder()
            sb.appendLine("── build_mark_info() ──")
            sb.appendLine("Payload (${payload.size}B):")
            sb.appendLine(payload.joinToString(" ") { "%02x".format(it) })
            sb.appendLine()
            sb.appendLine("── serialize_packet(seq=$seq, msg_id=970, sub=0, flags=$flags) ──")
            sb.appendLine("Full packet (${full.size}B):")
            sb.appendLine(full.chunked(1).map { it[0] }
                .chunked(16).joinToString("\n") { row ->
                    row.joinToString(" ") { "%02x".format(it) }
                })
            b.tvMarkResult.text = sb.toString()
        } catch (e: Exception) {
            b.tvMarkResult.text = "Error: ${e.message}"
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) { finish(); return true }
        return super.onOptionsItemSelected(item)
    }

    private fun tw(action: (String) -> Unit) = object : TextWatcher {
        override fun afterTextChanged(s: Editable?) { action(s.toString()) }
        override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
        override fun onTextChanged(s: CharSequence?, st: Int, b: Int, c: Int) {}
    }
}
