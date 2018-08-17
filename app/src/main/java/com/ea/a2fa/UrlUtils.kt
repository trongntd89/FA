package com.ea.a2fa

import android.net.Uri

class UrlUtils {
  companion object {
    fun parseUrl(url: String): Account {
      val uri = Uri.parse(url)
      return Account().apply {
        name = uri.path
        secret = uri.getQueryParameter("secret")
      }
    }
  }
}
