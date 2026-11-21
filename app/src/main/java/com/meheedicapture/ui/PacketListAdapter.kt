package com.meheedicapture.ui

import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.meheedicapture.R
import com.meheedicapture.model.Packet

class PacketListAdapter(
    private val onClick: (Packet) -> Unit
) : ListAdapter<Packet, PacketListAdapter.VH>(DIFF) {

    companion object {
        private val DIFF = object : DiffUtil.ItemCallback<Packet>() {
            override fun areItemsTheSame(a: Packet, b: Packet) = a.seq == b.seq
            override fun areContentsTheSame(a: Packet, b: Packet) = a == b
        }
    }

    inner class VH(view: View) : RecyclerView.ViewHolder(view) {
        val tvSeq:       TextView = view.findViewById(R.id.tvSeq)
        val tvChannel:   TextView = view.findViewById(R.id.tvChannel)
        val tvDirection: TextView = view.findViewById(R.id.tvDirection)
        val tvType:      TextView = view.findViewById(R.id.tvType)
        val tvMsgName:   TextView = view.findViewById(R.id.tvMsgName)
        val tvTime:      TextView = view.findViewById(R.id.tvTime)
        val tvLength:    TextView = view.findViewById(R.id.tvLength)
        val tvDecrypted: TextView = view.findViewById(R.id.tvDecrypted)
        val indicator:   View     = view.findViewById(R.id.channelIndicator)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH =
        VH(LayoutInflater.from(parent.context)
            .inflate(R.layout.item_packet, parent, false))

    override fun onBindViewHolder(h: VH, position: Int) {
        val p = getItem(position)

        h.tvSeq.text       = "#${p.seq}"
        h.tvChannel.text   = p.channel
        h.tvDirection.text = p.direction
        h.tvType.text      = p.type
        h.tvTime.text      = p.timestamp.substringAfterLast('T').take(12)
        h.tvLength.text    = "${p.length}B"
        h.tvMsgName.text   = p.msgName ?: p.url ?: ""
        h.tvDecrypted.visibility = if (p.decryptedHex != null) View.VISIBLE else View.GONE
        h.tvDecrypted.text = if (p.decryptedHex != null) "🔓 ${p.decryptedHex.take(32)}…" else ""

        // Color by channel
        h.indicator.setBackgroundColor(when (p.channel) {
            "HTTP" -> Color.parseColor("#4CAF50")
            "TCP"  -> Color.parseColor("#2196F3")
            "UDP"  -> Color.parseColor("#FF9800")
            else   -> Color.parseColor("#9E9E9E")
        })

        // Color direction
        h.tvDirection.setTextColor(when (p.direction) {
            "C2S"        -> Color.parseColor("#EF5350")
            "S2C"        -> Color.parseColor("#42A5F5")
            "RESEND-S2C" -> Color.parseColor("#AB47BC")
            else         -> Color.GRAY
        })

        h.itemView.setOnClickListener { onClick(p) }
    }
}
