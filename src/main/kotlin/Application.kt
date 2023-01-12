package teste

import java.io.FileOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.*
import java.security.spec.EncodedKeySpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator

fun main() {
    //generateRSAPair()

    val formattedInput = "5555555555554444_03_2030_737"
    val aesKey = generateAESKey()
    val encryptedData = performAESEncryption(formattedInput, aesKey)
    val encryptedAESKey = performRSAEncryption(aesKey);

    print("encryptedData: ")
    println(encryptedData)
    print("encryptedAESKey: ")
    println(encryptedAESKey)

}

fun performRSAEncryption(aesKey: Key): String {
    val publicKey = loadPublicKey(openPublicKey())
    val cipher = Cipher.getInstance("RSA")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    val bytes = cipher.doFinal(aesKey.encoded)
    return Base64.getEncoder().encode(bytes).decodeToString()
}

fun performAESEncryption(formattedInput: String, aesKey: Key): String? {
    val cipher: Cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, aesKey)
    val cipherText: ByteArray = cipher.doFinal(formattedInput.encodeToByteArray())
    return Base64.getEncoder().encodeToString(cipherText)
}


fun generateRSAPair(){
    val generator = KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048)
    val pair: KeyPair = generator.generateKeyPair()

    FileOutputStream("public.pem").use { fos -> fos.write(Base64.getEncoder().encode(pair.public.encoded)) }
    FileOutputStream("private.pem").use { fos -> fos.write(Base64.getEncoder().encode(pair.private.encoded)) }
}

fun generateAESKey(): Key {
    val rand = SecureRandom()
    val generator: KeyGenerator = KeyGenerator.getInstance("AES")
    generator.init(256, rand)
    return generator.generateKey()
}

private fun openPublicKey(): ByteArray {
    return ClassLoader.getSystemResource("public.pem").readBytes()
}

@Throws(IOException::class, NoSuchAlgorithmException::class, InvalidKeySpecException::class)
private fun loadPublicKey(encodeKey: ByteArray): PublicKey? {
    val publicKeyBytes: ByteArray = Base64.getDecoder().decode(encodeKey)
    val publicKeyFactory: KeyFactory = KeyFactory.getInstance("RSA")
    val publicKeySpec: EncodedKeySpec = X509EncodedKeySpec(publicKeyBytes)
    return publicKeyFactory.generatePublic(publicKeySpec)
}
