package com.ffcapture.ui

import android.app.Application
import android.content.Context
import android.content.Intent
import android.os.Environment
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.ffcapture.model.CaptureRepository
import com.ffcapture.model.Packet
import com.ffcapture.vpn.CaptureVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainViewModel(app: Application) : AndroidViewModel(app) {

    val packets: LiveData<List<Packet>> = CaptureRepository.liveAll
    val stats:   LiveData<CaptureRepository.Stats> = CaptureRepository.liveStats

    private val _filterChannel = MutableLiveData<String?>(null)
    val filterChannel: LiveData<String?> = _filterChannel

    private val _exportResult = MutableLiveData<String?>()
    val exportResult: LiveData<String?> = _exportResult

    private val _isVpnRunning = MutableLiveData(CaptureVpnService.isRunning)
    val isVpnRunning: LiveData<Boolean> = _isVpnRunning

    private val _searchQuery = MutableLiveData("")
    val searchQuery: LiveData<String> = _searchQuery

    // ── filtered list (channel + search) ──
    private val _filteredPackets = MutableLiveData<List<Packet>>(emptyList())
    val filteredPackets: LiveData<List<Packet>> = _filteredPackets

    init {
        packets.observeForever { rebuildFilter() }
        _filterChannel.observeForever { rebuildFilter() }
        _searchQuery.observeForever { rebuildFilter() }
    }

    fun setFilter(channel: String?) {
        _filterChannel.value = channel
    }

    fun setSearch(q: String) {
        _searchQuery.value = q.trim().lowercase()
    }

    fun refreshVpnState() {
        _isVpnRunning.postValue(CaptureVpnService.isRunning)
    }

    fun clearCapture() {
        CaptureRepository.clear()
    }

    private fun rebuildFilter() {
        val all   = packets.value ?: return
        val chan  = _filterChannel.value
        val query = _searchQuery.value?.lowercase() ?: ""

        var list = if (chan == null) all else all.filter { it.channel == chan }
        if (query.isNotEmpty()) {
            list = list.filter { p ->
                p.type.contains(query) ||
                p.msgName?.lowercase()?.contains(query) == true ||
                p.direction.lowercase().contains(query) ||
                p.url?.lowercase()?.contains(query) == true ||
                p.rawHex.contains(query) ||
                p.decryptedHex?.contains(query) == true
            }
        }
        _filteredPackets.postValue(list)
    }

    // ── Export ──
    fun exportJson(context: Context, channel: String? = null) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val json = when (channel) {
                    "HTTP" -> CaptureRepository.exportHttp()
                    "TCP"  -> CaptureRepository.exportTcp()
                    "UDP"  -> CaptureRepository.exportUdp()
                    else   -> CaptureRepository.exportAll()
                }
                val dir  = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
                    ?: context.filesDir
                val name = "ffcapture_${channel?.lowercase() ?: "all"}_${System.currentTimeMillis()}.json"
                val file = CaptureRepository.saveToFile(dir, name, json)
                _exportResult.postValue("Saved: ${file.absolutePath}")
            } catch (e: Exception) {
                _exportResult.postValue("Export error: ${e.message}")
            }
        }
    }

    fun clearExportResult() { _exportResult.value = null }
}
