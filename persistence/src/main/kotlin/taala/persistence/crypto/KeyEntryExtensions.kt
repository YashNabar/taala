//package taala.keystore.crypto
//
//import taala.keystore.crypto.EncryptionOperations.unwrap
//import taala.persistence.entry.KeyStoreEntry
//import taala.persistence.entry.PrivateKeyEntry
//import taala.persistence.entry.SecretKeyEntry
//import java.security.Key
//import java.security.KeyFactory
//import java.security.spec.PKCS8EncodedKeySpec
//import javax.crypto.spec.SecretKeySpec
//
//fun KeyStoreEntry.retrieveKey(password: CharArray?): Key? {
//    return when (this) {
//        is SecretKeyEntry, PrivateKeyEntry -> this.retrieveKey(password)
//        else -> null
//    }
//}
//
//fun SecretKeyEntry.retrieveKey(password: CharArray?): Key {
//    val keyBytes = password?.let { unwrap(secretKey!!, salt!!, iv!!, password) } ?: secretKey
//    return SecretKeySpec(keyBytes, keyType)
//}
//
//fun PrivateKeyEntry.retrieveKey(password: CharArray?): Key {
//    val keyBytes = password?.let { unwrap(privateKey!!, salt!!, iv!!, password) } ?: privateKey
//    return KeyFactory.getInstance(keyType).generatePrivate(PKCS8EncodedKeySpec(keyBytes))
//}
