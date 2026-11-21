package com.ffcapture.ui

import android.graphics.Color
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.ffcapture.R
import com.ffcapture.decoder.RawField

class RawFieldAdapter(
    private val onFieldEdited: (index: Int, newValue: String) -> Unit
) : ListAdapter<RawField, RawFieldAdapter.VH>(DIFF) {

    companion object {
        private val DIFF = object : DiffUtil.ItemCallback<RawField>() {
            override fun areItemsTheSame(a: RawField, b: RawField) =
                a.fieldNum == b.fieldNum && a.wireType == b.wireType
            override fun areContentsTheSame(a: RawField, b: RawField) =
                a.editedValue == b.editedValue
        }
    }

    inner class VH(view: View) : RecyclerView.ViewHolder(view) {
        val tvFieldNum: TextView = view.findViewById(R.id.tvFieldNum)
        val tvWireType: TextView = view.findViewById(R.id.tvWireType)
        val tvType:     TextView = view.findViewById(R.id.tvFieldType)
        val etValue:    EditText = view.findViewById(R.id.etFieldValue)
        var watcher: TextWatcher? = null
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH =
        VH(LayoutInflater.from(parent.context)
            .inflate(R.layout.item_raw_field, parent, false))

    override fun onBindViewHolder(h: VH, position: Int) {
        val field = getItem(position)

        h.tvFieldNum.text = "F${field.fieldNum}"
        h.tvWireType.text = "W${field.wireType}"
        h.tvType.text     = field.type

        // Color-code type
        h.tvType.setTextColor(when (field.type) {
            "varint"  -> Color.parseColor("#4CAF50")
            "string"  -> Color.parseColor("#2196F3")
            "bytes"   -> Color.parseColor("#FF9800")
            "fixed32" -> Color.parseColor("#9C27B0")
            "fixed64" -> Color.parseColor("#9C27B0")
            else      -> Color.GRAY
        })

        // Remove old watcher before updating text
        h.watcher?.let { h.etValue.removeTextChangedListener(it) }
        h.etValue.setText(field.editedValue)

        val watcher = object : TextWatcher {
            override fun afterTextChanged(s: Editable?) {
                val pos = h.bindingAdapterPosition
                if (pos != RecyclerView.NO_ID.toInt())
                    onFieldEdited(pos, s.toString())
            }
            override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
            override fun onTextChanged(s: CharSequence?, st: Int, b: Int, c: Int) {}
        }
        h.etValue.addTextChangedListener(watcher)
        h.watcher = watcher
    }
}
