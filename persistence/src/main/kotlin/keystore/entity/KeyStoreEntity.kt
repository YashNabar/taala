package keystore.entity

import java.io.Serializable
import java.security.PrivateKey
import java.security.cert.Certificate
import javax.crypto.SecretKey
import javax.persistence.Column
import javax.persistence.Id
import javax.persistence.Lob
import javax.persistence.MappedSuperclass

@MappedSuperclass
class KeyStoreEntity(
    @Id
    @Column(name = "alias")
    val alias: String,

    @Lob
    @Column(name = "private_key", nullable = true)
    val privateKey: PrivateKey?,

    @Lob
    @Column(name = "certificate_chain", nullable = true)
    var chain: List<Certificate>?,

    @Lob
    @Column(name = "secret_key", nullable = true)
    val secretKey: SecretKey?
) : Serializable
