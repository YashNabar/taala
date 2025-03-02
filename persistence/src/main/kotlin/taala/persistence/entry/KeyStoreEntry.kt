package taala.persistence.entry

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Lob
import jakarta.persistence.Table

@Entity
@Table(name = "keystore_entry")
@Suppress("LongParameterList")
class KeyStoreEntry(
    @Id
    @Column(name = "alias")
    val alias: String,

    @Lob
    @Column(name = "private_key", nullable = true)
    val privateKey: ByteArray?,

    @Lob
    @Column(name = "certificate_chain", nullable = true)
    val chain: ByteArray?,

    @Lob
    @Column(name = "secret_key", nullable = true)
    val secretKey: ByteArray?,

    @Column(name = "certificate_type", nullable = true)
    val certificateType: String?,

    @Column(name = "key_type", nullable = true)
    val keyType: String?,
)
