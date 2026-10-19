package com.abk.extension.fido

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

class FidoAuthPromptActivity : FragmentActivity() {
    private var requestId: Int = -1
    private var isResultSent = false
    private var biometricPrompt: BiometricPrompt? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private val checkRequest = object : Runnable {
        override fun run() {
            if (isFinishing || isDestroyed) return
            if (!BiometricAuthBridge.isCurrent(requestId)) {
                sendResultAndFinish(requestId, false, null)
            } else {
                mainHandler.postDelayed(this, 300)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestId = intent.getIntExtra(EXTRA_REQUEST_ID, -1)
        Log.i(TAG, "onCreate requestId=$requestId expected=${BiometricAuthBridge.expectedRequestId}")
        if (requestId <= 0 || !BiometricAuthBridge.isCurrent(requestId)) {
            Log.w(TAG, "finish early due to invalid request id")
            finish()
            return
        }

        val rpId = intent.getStringExtra(EXTRA_RP_ID).orEmpty()
        val command = intent.getStringExtra(EXTRA_COMMAND).orEmpty()

        val biometricManager = BiometricManager.from(this)
        val authenticators =
            BiometricManager.Authenticators.BIOMETRIC_WEAK or
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        val canAuth = biometricManager.canAuthenticate(authenticators)
        Log.i(TAG, "canAuthenticate=$canAuth rp=${rpId.ifBlank { command }}")
        if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
            sendResultAndFinish(requestId, false, getString(R.string.auth_biometric_unavailable))
            return
        }

        // This Activity has standard launch mode: every callback keeps the id
        // of this prompt even if a later request opens another Activity.
        val callbackRequestId = requestId
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    Log.i(TAG, "authentication succeeded requestId=$requestId")
                    sendResultAndFinish(callbackRequestId, true, null)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    Log.w(TAG, "authentication error requestId=$requestId code=$errorCode msg=$errString")
                    sendResultAndFinish(
                        callbackRequestId,
                        false,
                        if (errString.isNotBlank()) errString.toString()
                        else getString(R.string.auth_biometric_denied)
                    )
                }
            }
        )
        biometricPrompt = prompt

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.auth_prompt_title))
            .setSubtitle(getString(R.string.auth_prompt_subtitle, rpId.ifBlank { command }))
            .setConfirmationRequired(false)
            .setAllowedAuthenticators(authenticators)
            .build()
        prompt.authenticate(promptInfo)
        mainHandler.postDelayed(checkRequest, 300)
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy requestId=$requestId isResultSent=$isResultSent")
        sendResult(requestId, false, null)
        mainHandler.removeCallbacks(checkRequest)
        biometricPrompt = null
        super.onDestroy()
    }

    private fun sendResultAndFinish(id: Int, success: Boolean, message: String?) {
        sendResult(id, success, message)
        finish()
    }

    private fun sendResult(id: Int, success: Boolean, message: String?) {
        if (id != requestId) return
        if (isResultSent) return
        isResultSent = true
        mainHandler.removeCallbacks(checkRequest)
        biometricPrompt?.cancelAuthentication()
        Log.i(TAG, "sendResultAndFinish requestId=$requestId success=$success message=${message.orEmpty()}")
        if (!message.isNullOrBlank()) {
            Handler(Looper.getMainLooper()).post {
                Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
            }
        }
        BiometricAuthBridge.finish(id, success)
    }

    companion object {
        private const val TAG = "AbkFidoAuth"
        const val EXTRA_REQUEST_ID = "request_id"
        const val EXTRA_COMMAND = "command"
        const val EXTRA_RP_ID = "rp_id"
    }
}
