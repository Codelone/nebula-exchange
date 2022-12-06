package com.vesoft.exchange.common.utils

import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


object EncryptUtils {
  /**
   * 密钥, 256位32个字节
   */
  val DEFAULT_SECRET_KEY = "uBdUx82vPHkDKb284d7NkjFoNcKWBuka"

  private val AES = "AES"

  /**
   * 初始向量IV, 初始向量IV的长度规定为128位16个字节, 初始向量的来源为截取密钥.
   */

  /**
   * 加密解密算法/加密模式/填充方式
   */
  private val CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding"

  private val base64Encoder = java.util.Base64.getEncoder
  private val base64Decoder = java.util.Base64.getDecoder

  java.security.Security.setProperty("crypto.policy", "unlimited")

  /**
   * AES加密
   */
  def encode(key: String, content: String): String = {
    try {
      val newKey = this.checkSecretKey(key)
      val secretKey = new SecretKeySpec(newKey.getBytes, AES)
      val cipher = javax.crypto.Cipher.getInstance(CIPHER_ALGORITHM)
      val KEY_VI = newKey.substring(0, 16).getBytes
      cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(KEY_VI))
      // 获取加密内容的字节数组(这里要设置为utf-8)不然内容中如果有中文和英文混合中文就会解密为乱码
      val byteEncode = content.getBytes(java.nio.charset.StandardCharsets.UTF_8)
      // 根据密码器的初始化方式加密
      val byteAES = cipher.doFinal(byteEncode)
      // 将加密后的数据转换为字符串
      base64Encoder.encodeToString(byteAES)
    } catch {
      case e: Exception =>
        e.printStackTrace()
        ""
    }
  }

  /**
   * AES解密
   */
  def decode(key: String, content: String): String = {
    try {
      val newKey = this.checkSecretKey(key)
      val secretKey = new SecretKeySpec(newKey.getBytes, AES)
      val cipher = javax.crypto.Cipher.getInstance(CIPHER_ALGORITHM)
      val KEY_VI = newKey.substring(0, 16).getBytes
      cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(KEY_VI))
      // 将加密并编码后的内容解码成字节数组
      val byteContent = base64Decoder.decode(content)
      // 解密
      val byteDecode = cipher.doFinal(byteContent)
      new String(byteDecode, java.nio.charset.StandardCharsets.UTF_8)
    } catch {
      case e: Exception =>
        e.printStackTrace()
        ""
    }

  }

  def checkSecretKey(secretKey: String): String = {
    if (secretKey.length > 32) secretKey.substring(0, 32)
    else if (secretKey.length < 32) {
      val k = 32 / secretKey.length
      var newSecretKey = secretKey
      for (i <- 0 until k) {
        newSecretKey += secretKey
      }
      newSecretKey.substring(0, 32)
    }
    else secretKey
  }

  def main(args: Array[String]): Unit = {
    val secretKey = "YmFuZ3N1bg=saaa="
    /// 加密
    println(encode(secretKey,"nebula"))
    // 解密
    println(decode(secretKey,encode(secretKey,"nebula")))
  }
}
