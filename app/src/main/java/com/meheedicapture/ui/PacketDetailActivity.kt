package com.meheedicapture.ui

import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.Toast
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.meheedicapture.R
import com.meheedicapture.databinding.ActivityPacketDetailBinding
import com.meheedicapture.decoder.PacketBuilder
import com.meheedicapture.decoder.toHexString
import com.meheedicapture.model.CaptureRepository
import com.meheedicapture.model.Constants
import com.google.gson.GsonBuilder

class PacketDetailActivity : AppCompatActivity() {

    private lateinit var binding: ActivityPacketDetailBinding
    private val vm: PacketEditViewModel by viewModels()
    private lateinit var fieldsAdapter: RawFieldAdapter
    private val gson = GsonBuilder().setPrettyPrinting().create()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityPacketDetailBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        // Load packet from repository by seq
        val seq = intent.getIntExtra("packet_seq", -1)
        val pkt = CaptureRepository.getAll().find { it.seq == seq }
        if (pkt == null) { finish(); return }

        vm.loadPacket(pkt)
        supportActionBar?.title = "${pkt.channel} #${pkt.seq}"

        setupFieldsRecycler()
        observeViewModel()
        setupSendPanel()

        // Populate static views
        binding.tvChannel.text   = pkt.channel
        binding.tvDirection.text = pkt.direction
        binding.tvType.text      = pkt.type
        binding.tvMsgName.text   = pkt.msgName ?: pkt.url ?: "-"
        binding.tvTimestamp.text = pkt.timestamp
        binding.tvLength.text    = "${pkt.length} bytes"
        binding.tvAesUsed.text   = pkt.aesUsed ?: "none"

        // Raw hex (formatted 16 per line)
        binding.tvRawHex.text = formatHex(pkt.rawHex)

        // Decrypted hex
        if (pkt.decryptedHex != null) {
            binding.cardDecrypted.visibility = View.VISIBLE
            binding.tvDecryptedHex.text = formatHex(pkt.decryptedHex)
        }

        // Protobuf JSON
        if (pkt.protobufFlat != null) {
            binding.cardProtobuf.visibility = View.VISIBLE
            binding.tvProtobuf.text = gson.toJson(pkt.protobufFlat)
        }

        // Deep scan
        if (!pkt.deepScan.isNullOrEmpty()) {
            binding.cardDeepScan.visibility = View.VISIBLE
            val sb = StringBuilder()
            pkt.deepScan.forEach { e ->
                sb.append("  [${e.path}]  ${e.kind}  ${e.value}")
                if (e.tag != null) sb.append("  ${e.tag}")
                sb.append('\n')
            }
            binding.tvDeepScan.text = sb.toString()
        }
    }

    // ─────────────────────────────────────────────────────────
    private fun setupFieldsRecycler() {
        fieldsAdapter = RawFieldAdapter { index, newValue ->
            vm.updateField(index, newValue)
        }
        binding.rvFields.apply {
            layoutManager = LinearLayoutManager(this@PacketDetailActivity)
            adapter = fieldsAdapter
            setHasFixedSize(false)
        }
    }

    private fun observeViewModel() {
        vm.rawFields.observe(this) { fields ->
            fieldsAdapter.submitList(fields.toList())
        }
        vm.rebuiltHex.observe(this) { hex ->
            if (hex.isNotEmpty())
                binding.etRawEdit.setText(formatHex(hex))
        }
        vm.sendResult.observe(this) { msg ->
            msg?.let {
                AlertDialog.Builder(this)
                    .setTitle("Send Result")
                    .setMessage(it)
                    .setPositiveButton("OK", null)
                    .show()
                vm.clearSendResult()
            }
        }
    }

    private fun setupSendPanel() {
        // Target host / port pre-fill from packet channel
        val pkt = vm.packet.value
        vm.targetHost = when (pkt?.channel) {
            "HTTP" -> Constants.HOST_CLIENT
            "TCP"  -> Constants.HOST_CLIENT
            "UDP"  -> Constants.HOST_CLIENT
            else   -> Constants.HOST_CLIENT
        }
        vm.targetPort = when (pkt?.channel) {
            "UDP"  -> Constants.UDP_MATCH_PORT
            "TCP"  -> Constants.TCP_ONLINE_PORT
            else   -> Constants.HTTP_PORT
        }

        binding.etTargetHost.setText(vm.targetHost)
        binding.etTargetPort.setText(vm.targetPort.toString())
        binding.switchEncrypt.isChecked = false

        binding.etTargetHost.addTextChangedListener(tw { vm.targetHost = it })
        binding.etTargetPort.addTextChangedListener(tw { vm.targetPort = it.toIntOrNull() ?: vm.targetPort })
        binding.switchEncrypt.setOnCheckedChangeListener { _, c -> vm.encryptWithSession = c }

        // Sync raw edit box → vm
        binding.etRawEdit.addTextChangedListener(tw { hex ->
            vm.setRawHex(hex.replace(" ", "").replace("\n", ""))
        })

        binding.btnSendUdp.setOnClickListener { vm.sendPacket(isUdp = true) }
        binding.btnSendTcp.setOnClickListener { vm.sendPacket(isUdp = false) }
    }

    // ─────────────────────────────────────────────────────────
    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.detail_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> { finish(); true }
            R.id.menu_copy_json -> {
                val pkt = CaptureRepository.getAll()
                    .find { it.seq == (vm.packet.value?.seq ?: -1) }
                val json = gson.toJson(pkt)
                val cm = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
                cm.setPrimaryClip(android.content.ClipData.newPlainText("packet", json))
                Toast.makeText(this, "Copied JSON", Toast.LENGTH_SHORT).show()
                true
            }
            R.id.menu_reset_fields -> {
                vm.packet.value?.let { vm.loadPacket(it) }
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun formatHex(hex: String): String {
        val clean = hex.replace(" ", "").replace("\n", "")
        return clean.chunked(2).chunked(16).joinToString("\n") { row ->
            row.joinToString(" ") + "  |  " +
            row.map { h ->
                val c = h.toIntOrNull(16)?.toChar() ?: '.'
                if (c.code in 32..126) c else '.'
            }.joinToString("")
        }
    }

    private fun tw(action: (String) -> Unit) = object : TextWatcher {
        override fun afterTextChanged(s: Editable?) { action(s.toString()) }
        override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
        override fun onTextChanged(s: CharSequence?, st: Int, b: Int, c: Int) {}
    }
}
