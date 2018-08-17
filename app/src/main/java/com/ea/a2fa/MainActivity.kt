package com.ea.a2fa

import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.content.Intent
import android.util.Log
import com.google.zxing.integration.android.IntentIntegrator

class MainActivity : AppCompatActivity() {

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)

  }

  private fun addAccount() {
    val integrator = IntentIntegrator(this)
    integrator.setDesiredBarcodeFormats(IntentIntegrator.ALL_CODE_TYPES)
    integrator.setPrompt("Scan Code")
    integrator.setCameraId(0)
    integrator.setBeepEnabled(true)
    integrator.setBarcodeImageEnabled(false)
    integrator.setOrientationLocked(false)
    integrator.initiateScan()
  }

  override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    super.onActivityResult(requestCode, resultCode, data)
    val intentResult = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
    intentResult?.let {
      Log.e("QR Code Scan", "${intentResult.contents}")
    }

  }

}
