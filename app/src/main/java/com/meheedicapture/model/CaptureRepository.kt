package com.meheedicapture.model

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import java.io.File
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.concurrent.atomic.AtomicInteger

/** Singleton in-memory store for all captured packets. Thread-safe. */
object CaptureRepository {

    private val gson: Gson = GsonBuilder().setPrettyPrinting().create()
    private val seq = AtomicInteger(0)
    private val ts  = DateTimeFormatter
        .ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS")
        .withZone(ZoneId.systemDefault())

    private val _httpPackets = mutableListOf<Packet>()
    private val _tcpPackets  = mutableListOf<Packet>()
    private val _udpPackets  = mutableListOf<Packet>()
    private val _sessionKeys = mutableListOf<SessionKey>()
    private val _allPackets  = mutableListOf<Packet>()
    private val lock = Any()

    private val _liveAll   = MutableLiveData<List<Packet>>(emptyList())
    private val _liveStats = MutableLiveData<Stats>()

    val liveAll:   LiveData<List<Packet>> get() = _liveAll
    val liveStats: LiveData<Stats>        get() = _liveStats

    data class Stats(
        val httpCount:  Int = 0,
        val tcpCount:   Int = 0,
        val udpCount:   Int = 0,
        val keyCount:   Int = 0,
        val totalBytes: Long = 0
    )

    private var totalBytes = 0L

    fun addPacket(p: Packet) {
        synchronized(lock) {
            when (p.channel) {
                Constants.CHANNEL_HTTP -> _httpPackets.add(p)
                Constants.CHANNEL_TCP  -> _tcpPackets.add(p)
                Constants.CHANNEL_UDP  -> _udpPackets.add(p)
            }
            _allPackets.add(0, p)          // newest first
            totalBytes += p.length
            _liveAll.postValue(_allPackets.toList())
            _liveStats.postValue(currentStats())
        }
    }

    fun addSessionKey(k: SessionKey) {
        synchronized(lock) {
            _sessionKeys.add(k)
            _liveStats.postValue(currentStats())
        }
    }

    fun makePacket(
        channel: String,
        direction: String,
        type: String,
        rawHex: String,
        msgName: String? = null,
        aesUsed: String? = null,
        decryptedHex: String? = null,
        protobufFlat: Map<String, Any>? = null,
        protobufTree: Any? = null,
        deepScan: List<ScanEntry>? = null,
        url: String? = null,
        method: String? = null,
        status: Int? = null,
        bodyHex: String? = null
    ): Packet = Packet(
        seq           = seq.getAndIncrement(),
        timestamp     = ts.format(Instant.now()),
        channel       = channel,
        direction     = direction,
        type          = type,
        msgName       = msgName,
        length        = rawHex.length / 2,
        rawHex        = rawHex,
        aesUsed       = aesUsed,
        decryptedHex  = decryptedHex,
        protobufFlat  = protobufFlat,
        protobufTree  = protobufTree,
        deepScan      = deepScan,
        url           = url,
        method        = method,
        status        = status,
        bodyHex       = bodyHex
    )

    private fun currentStats() = Stats(
        httpCount  = _httpPackets.size,
        tcpCount   = _tcpPackets.size,
        udpCount   = _udpPackets.size,
        keyCount   = _sessionKeys.size,
        totalBytes = totalBytes
    )

    // ── Clear all ──
    fun clear() {
        synchronized(lock) {
            _httpPackets.clear(); _tcpPackets.clear()
            _udpPackets.clear(); _allPackets.clear()
            _sessionKeys.clear(); totalBytes = 0L
            seq.set(0)
            _liveAll.postValue(emptyList())
            _liveStats.postValue(Stats())
        }
    }

    // ── Export helpers ──
    fun exportAll(): String {
        synchronized(lock) {
            val dump = CaptureDump(
                httpPackets = _httpPackets.toList(),
                tcpPackets  = _tcpPackets.toList(),
                udpPackets  = _udpPackets.toList(),
                sessionKeys = _sessionKeys.toList()
            )
            return gson.toJson(dump)
        }
    }

    fun exportHttp(): String = synchronized(lock) { gson.toJson(_httpPackets.toList()) }
    fun exportTcp():  String = synchronized(lock) { gson.toJson(_tcpPackets.toList()) }
    fun exportUdp():  String = synchronized(lock) { gson.toJson(_udpPackets.toList()) }
    fun exportKeys(): String = synchronized(lock) { gson.toJson(_sessionKeys.toList()) }

    fun saveToFile(dir: File, name: String, json: String): File {
        val f = File(dir, name)
        f.writeText(json, Charsets.UTF_8)
        return f
    }

    fun getAll(): List<Packet> = synchronized(lock) { _allPackets.toList() }
    fun getHttp(): List<Packet> = synchronized(lock) { _httpPackets.toList() }
    fun getTcp():  List<Packet> = synchronized(lock) { _tcpPackets.toList() }
    fun getUdp():  List<Packet> = synchronized(lock) { _udpPackets.toList() }
    fun getKeys(): List<SessionKey> = synchronized(lock) { _sessionKeys.toList() }
}
