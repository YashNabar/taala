package taala.keystore

import java.io.InputStream
import java.io.OutputStream
import java.security.Key
import java.security.KeyStoreSpi
import java.security.cert.Certificate
import java.util.Date
import java.util.Enumeration

class KeyStoreImpl : KeyStoreSpi() {
    override fun engineGetKey(alias: String?, password: CharArray?): Key {
        throw UnsupportedOperationException()
    }

    override fun engineGetCertificateChain(alias: String?): Array<Certificate> {
        throw UnsupportedOperationException()
    }

    override fun engineGetCertificate(alias: String?): Certificate {
        throw UnsupportedOperationException()
    }

    override fun engineGetCreationDate(alias: String?): Date {
        throw UnsupportedOperationException()
    }

    override fun engineSetKeyEntry(alias: String?, key: Key?, password: CharArray?, chain: Array<out Certificate>?) {
        throw UnsupportedOperationException()
    }

    override fun engineSetKeyEntry(alias: String?, key: ByteArray?, chain: Array<out Certificate>?) {
        throw UnsupportedOperationException()
    }

    override fun engineSetCertificateEntry(alias: String?, cert: Certificate?) {
        throw UnsupportedOperationException()
    }

    override fun engineDeleteEntry(alias: String?) {
        throw UnsupportedOperationException()
    }

    override fun engineAliases(): Enumeration<String> {
        throw UnsupportedOperationException()
    }

    override fun engineContainsAlias(alias: String?): Boolean {
        throw UnsupportedOperationException()
    }

    override fun engineSize(): Int {
        throw UnsupportedOperationException()
    }

    override fun engineIsKeyEntry(alias: String?): Boolean {
        throw UnsupportedOperationException()
    }

    override fun engineIsCertificateEntry(alias: String?): Boolean {
        throw UnsupportedOperationException()
    }

    override fun engineGetCertificateAlias(cert: Certificate?): String {
        throw UnsupportedOperationException()
    }

    override fun engineStore(stream: OutputStream?, password: CharArray?) {
        throw UnsupportedOperationException()
    }

    override fun engineLoad(stream: InputStream?, password: CharArray?) {
        throw UnsupportedOperationException()
    }
}