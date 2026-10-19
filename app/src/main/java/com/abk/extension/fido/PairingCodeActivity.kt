package com.abk.extension.fido

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.dialog.MaterialAlertDialogBuilder

class PairingCodeActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val code = FidoStoragePaths.readPairingCode()
        val codeView = TextView(this).apply {
            text = code.ifBlank { getString(R.string.pairing_code_none) }
            textSize = 32f
            typeface = Typeface.MONOSPACE
            setTypeface(typeface, Typeface.BOLD)
            gravity = Gravity.CENTER
            letterSpacing = 0.16f
        }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 4, 24, 8)
            addView(TextView(this@PairingCodeActivity).apply {
                text = getString(R.string.pairing_dialog_message)
                textSize = 15f
                setPadding(0, 0, 0, 20)
            })
            addView(codeView)
        }

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.pairing_dialog_title)
            .setView(content)
            .setNegativeButton(R.string.action_close) { _, _ -> finish() }
            .setPositiveButton(R.string.action_copy) { _, _ ->
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(
                    ClipData.newPlainText(getString(R.string.pairing_code_title), code)
                )
                Toast.makeText(this, R.string.pairing_code_copied, Toast.LENGTH_SHORT).show()
            }
            .setOnDismissListener { finish() }
            .show()
    }
}
