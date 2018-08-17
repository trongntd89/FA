package com.ea.a2fa

import com.ea.a2fa.TimeBasedOneTimePasswordUtil.decodeBase32
import java.util.Arrays
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and

class TwoFAUtils {
  companion object {
    // 30 seconds
    private const val EXPIRED_TIME = 30
    private const val blockOfZeros = "000000"
    private const val NUM_DIGITS_OUTPUT = 6

    fun gen2FAToken(secretKey: String): String {
      val currentTimeMilis = System.currentTimeMillis()

      val key = decodeBase32(secretKey)
      val data = ByteArray(8)
      var value = currentTimeMilis / 1000 / EXPIRED_TIME

      var i = 7
      while (value > 0) {
        data[i] = (value and 0xFF).toByte()
        value = value shr 8
        i--
      }

      // encrypt the data with the key and return the SHA1 of it in hex
      val signKey = SecretKeySpec(key, "HmacSHA1")
      // if this is expensive, could put in a thread-local
      val mac = Mac.getInstance("HmacSHA1")
      mac.init(signKey)
      val hash = mac.doFinal(data)

      // take the 4 least significant bits from the encrypted string as an offset
      val offset = hash[hash.size - 1] and 0xF

      // We're using a long because Java hasn't got unsigned int.
      var truncatedHash: Long = 0
      for (i in offset until offset + 4) {
        truncatedHash = truncatedHash shl 8
        // get the 4 bytes at the offset
        truncatedHash = truncatedHash or (hash[i].toInt() and 0xFF).toLong()
      }
      // cut off the top bit
      truncatedHash = truncatedHash and 0x7FFFFFFF

      // the token is then the last 6 digits in the number
      truncatedHash %= 1000000

      return zeroPrepend(truncatedHash, NUM_DIGITS_OUTPUT)
    }

    /**
     * Return the string prepended with 0s. Tested as 10x faster than String.format("%06d", ...); Exposed for testing.
     */
    private fun zeroPrepend(num: Long, digits: Int): String {
      val numStr = java.lang.Long.toString(num)
      if (numStr.length >= digits) {
        return numStr
      } else {
        val sb = StringBuilder(digits)
        val zeroCount = digits - numStr.length
        sb.append(blockOfZeros, 0, zeroCount)
        sb.append(numStr)
        return sb.toString()
      }
    }


    /**
     * Decode base-32 method. I didn't want to add a dependency to Apache Codec just for this decode method. Exposed for
     * testing.
     */
    private fun decodeBase32(str: String): ByteArray {
      // each base-32 character encodes 5 bits
      val numBytes = (str.length * 5 + 7) / 8
      var result = ByteArray(numBytes)
      var resultIndex = 0
      var which = 0
      var working = 0
      for (i in 0 until str.length) {
        val ch = str[i]
        val value: Int
        if (ch >= 'a' && ch <= 'z') {
          value = ch - 'a'
        } else if (ch >= 'A' && ch <= 'Z') {
          value = ch - 'A'
        } else if (ch >= '2' && ch <= '7') {
          value = 26 + (ch - '2')
        } else if (ch == '=') {
          // special case
          which = 0
          break
        } else {
          throw IllegalArgumentException("Invalid base-32 character: $ch")
        }
        /*
			 * There are probably better ways to do this but this seemed the most straightforward.
			 */
        when (which) {
          0 -> {
            // all 5 bits is top 5 bits
            working = value and 0x1F shl 3
            which = 1
          }
          1 -> {
            // top 3 bits is lower 3 bits
            working = working or (value and 0x1C shr 2)
            result[resultIndex++] = working.toByte()
            // lower 2 bits is upper 2 bits
            working = value and 0x03 shl 6
            which = 2
          }
          2 -> {
            // all 5 bits is mid 5 bits
            working = working or (value and 0x1F shl 1)
            which = 3
          }
          3 -> {
            // top 1 bit is lowest 1 bit
            working = working or (value and 0x10 shr 4)
            result[resultIndex++] = working.toByte()
            // lower 4 bits is top 4 bits
            working = value and 0x0F shl 4
            which = 4
          }
          4 -> {
            // top 4 bits is lowest 4 bits
            working = working or (value and 0x1E shr 1)
            result[resultIndex++] = working.toByte()
            // lower 1 bit is top 1 bit
            working = value and 0x01 shl 7
            which = 5
          }
          5 -> {
            // all 5 bits is mid 5 bits
            working = working or (value and 0x1F shl 2)
            which = 6
          }
          6 -> {
            // top 2 bits is lowest 2 bits
            working = working or (value and 0x18 shr 3)
            result[resultIndex++] = working.toByte()
            // lower 3 bits of byte 6 is top 3 bits
            working = value and 0x07 shl 5
            which = 7
          }
          7 -> {
            // all 5 bits is lower 5 bits
            working = working or (value and 0x1F)
            result[resultIndex++] = working.toByte()
            which = 0
          }
        }
      }
      if (which != 0) {
        result[resultIndex++] = working.toByte()
      }
      if (resultIndex != result.size) {
        result = Arrays.copyOf(result, resultIndex)
      }
      return result
    }
  }
}
