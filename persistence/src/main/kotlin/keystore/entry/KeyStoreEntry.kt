package keystore.entry

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Lob
import jakarta.persistence.Table

@Entity
@Table(name = "keystore_entry")
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

    @Column(name = "type")
    val type: String,
)
