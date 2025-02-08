package keystore.entry

import java.io.Serializable
import java.security.PrivateKey
import java.security.cert.Certificate
import javax.crypto.SecretKey
import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.Id
import javax.persistence.Lob
import javax.persistence.Table

@Entity
@Table(name = "keystore_entry")
class KeyStoreEntry(
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
    val secretKey: SecretKey?,

    @Column(name = "type")
    val type: String,
) : Serializable
