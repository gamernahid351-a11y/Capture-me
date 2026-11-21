package com.meheedicapture.ui

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.Menu
import android.view.MenuItem
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.meheedicapture.R
import com.meheedicapture.databinding.ActivityMainBinding
import com.meheedicapture.model.Constants
import com.meheedicapture.vpn.CaptureVpnService
import com.google.android.material.chip.Chip

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val vm: MainViewModel by viewModels()
    private lateinit var adapter: PacketListAdapter

    private val vpnLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) startVpn()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)

        setupRecyclerView()
        setupChips()
        setupSearch()
        observeViewModel()
        setupFab()
    }

    // ─────────────────────────────────────────────────────────
    private fun setupRecyclerView() {
        adapter = PacketListAdapter { packet ->
            // Open detail / edit screen
            val intent = Intent(this, PacketDetailActivity::class.java)
            intent.putExtra("packet_seq", packet.seq)
            startActivity(intent)
        }
        binding.recyclerView.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = this@MainActivity.adapter
            setHasFixedSize(true)
        }
    }

    private fun setupChips() {
        val channels = listOf(null to "All", "HTTP" to "HTTP", "TCP" to "TCP", "UDP" to "UDP")
        channels.forEach { (chan, label) ->
            val chip = Chip(this).apply {
                text = label
                isCheckable = true
                isChecked = chan == null
                setOnCheckedChangeListener { _, checked ->
                    if (checked) vm.setFilter(chan)
                }
            }
            binding.chipGroupFilter.addView(chip)
        }
    }

    private fun setupSearch() {
        binding.searchInput.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) { vm.setSearch(s.toString()) }
            override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
            override fun onTextChanged(s: CharSequence?, st: Int, b: Int, c: Int) {}
        })
    }

    private fun setupFab() {
        binding.fabVpn.setOnClickListener {
            if (CaptureVpnService.isRunning) stopVpn() else requestVpnPermission()
        }
    }

    // ─────────────────────────────────────────────────────────
    private fun observeViewModel() {
        vm.filteredPackets.observe(this) { packets ->
            adapter.submitList(packets)
            binding.tvPacketCount.text = "${packets.size} packets"
        }
        vm.stats.observe(this) { s ->
            if (s == null) return@observe
            binding.tvStats.text =
                "HTTP:${s.httpCount}  TCP:${s.tcpCount}  UDP:${s.udpCount}  " +
                "Keys:${s.keyCount}  ${s.totalBytes / 1024}KB"
        }
        vm.isVpnRunning.observe(this) { running ->
            binding.fabVpn.setImageResource(
                if (running) R.drawable.ic_vpn_off else R.drawable.ic_vpn
            )
            binding.tvVpnStatus.text = if (running) "● Capturing" else "○ Stopped"
        }
        vm.exportResult.observe(this) { msg ->
            msg?.let {
                Toast.makeText(this, it, Toast.LENGTH_LONG).show()
                vm.clearExportResult()
            }
        }
    }

    // ─────────────────────────────────────────────────────────
    // VPN lifecycle
    // ─────────────────────────────────────────────────────────
    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) vpnLauncher.launch(intent)
        else startVpn()
    }

    private fun startVpn() {
        val i = Intent(this, CaptureVpnService::class.java)
            .setAction(CaptureVpnService.ACTION_START)
        startForegroundService(i)
        vm.refreshVpnState()
    }

    private fun stopVpn() {
        val i = Intent(this, CaptureVpnService::class.java)
            .setAction(CaptureVpnService.ACTION_STOP)
        startService(i)
        vm.refreshVpnState()
    }

    // ─────────────────────────────────────────────────────────
    // Menu
    // ─────────────────────────────────────────────────────────
    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.menu_export_all  -> { showExportDialog(); true }
            R.id.menu_clear       -> { confirmClear(); true }
            R.id.menu_varint_tool -> { startActivity(Intent(this, VarintToolActivity::class.java)); true }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun showExportDialog() {
        val options = arrayOf("All (combined)", "HTTP only", "TCP only", "UDP only")
        AlertDialog.Builder(this)
            .setTitle("Export JSON")
            .setItems(options) { _, which ->
                when (which) {
                    0 -> vm.exportJson(this, null)
                    1 -> vm.exportJson(this, "HTTP")
                    2 -> vm.exportJson(this, "TCP")
                    3 -> vm.exportJson(this, "UDP")
                }
            }.show()
    }

    private fun confirmClear() {
        AlertDialog.Builder(this)
            .setTitle("Clear capture?")
            .setMessage("All captured packets will be deleted from memory.")
            .setPositiveButton("Clear") { _, _ -> vm.clearCapture() }
            .setNegativeButton("Cancel", null)
            .show()
    }

    override fun onResume() {
        super.onResume()
        vm.refreshVpnState()
    }
}
