package com.meheedicapture.model

import com.google.gson.annotations.SerializedName

data class Packet(
    @SerializedName("seq")           val seq: Int,
    @SerializedName("timestamp")     val timestamp: String,
    @SerializedName("channel")       val channel: String,       // HTTP / TCP-online / TCP-chat / UDP
    @SerializedName("direction")     val direction: String,     // C2S / S2C / REQ / RES
    @SerializedName("type")          val type: String,          // packet type hex or HTTP path
    @SerializedName("msg_name")      val msgName: String? = null,
    @SerializedName("length")        val length: Int,
    @SerializedName("raw_hex")       val rawHex: String,
    @SerializedName("aes_used")      val aesUsed: String? = null,
    @SerializedName("decrypted_hex") val decryptedHex: String? = null,
    @SerializedName("protobuf_flat") val protobufFlat: Map<String, Any>? = null,
    @SerializedName("protobuf_tree") val protobufTree: Any? = null,
    @SerializedName("deep_scan")     val deepScan: List<ScanEntry>? = null,
    // HTTP-specific
    @SerializedName("url")           val url: String? = null,
    @SerializedName("method")        val method: String? = null,
    @SerializedName("status")        val status: Int? = null,
    @SerializedName("body_hex")      val bodyHex: String? = null
)

data class ScanEntry(
    @SerializedName("path")  val path: String,
    @SerializedName("kind")  val kind: String,   // "int" / "str"
    @SerializedName("value") val value: String,
    @SerializedName("tag")   val tag: String? = null
)

data class SessionKey(
    val timestamp: String,
    val keyHex: String,
    val ivHex: String
)

/** Container for the full capture dump (all three channels) */
data class CaptureDump(
    val httpPackets: List<Packet>,
    val tcpPackets:  List<Packet>,
    val udpPackets:  List<Packet>,
    val sessionKeys: List<SessionKey>
)
