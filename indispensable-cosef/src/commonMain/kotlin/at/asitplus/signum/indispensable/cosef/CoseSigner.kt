package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.equalsCryptographically
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.sign.sign
import at.asitplus.signum.indispensable.sign.signature
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.cbor.CborElement
import kotlinx.serialization.serializer

/**
 * Signs `COSE_Sign1` messages with Signum [Signer]s and returns typed views that retain the supplied payload and
 * header
 *
 * Validates before signing: the signer matches `alg`
 * A supplied `kid` matches the public key's [coseKid] when that is set; the leaf of a
 * supplied `x5chain` carries the signer's public key.
 * Header parameters and placement are preserved; optional parameters are not filled in.
 * Mismatches fail with [IllegalArgumentException] before the signer is invoked; signer failures propagate.
 */
@OptIn(ExperimentalSerializationApi::class)
class CoseSigner(signers: Map<CoseAlgorithm.Signature, Signer>) {
    private val signers = signers.toMap()

    init {
        require(this.signers.isNotEmpty()) { "At least one signer is required" }
        this.signers.forEach { (algorithm, signer) ->
            require(algorithm.isCompatibleWith(signer)) { "Registered COSE algorithm $algorithm does not match the signer" }
        }
    }

    /** Signs [payload] with [header]; labels in [unprotectedLabels] go into the unprotected bucket. */
    suspend fun <P : Any, H : CoseHeaderBase> sign1(
        header: H,
        payload: P,
        payloadSerializer: KSerializer<P>,
        headerSerializer: KSerializer<H>,
        unprotectedLabels: Set<CborElement> = emptySet(),
        detached: Boolean = false,
        externalAad: ByteArray = byteArrayOf(),
    ): CoseSign1Typed<P, H> = sign1(
        CoseHeaderWrapped(header, headerSerializer, unprotectedLabels),
        payload, payloadSerializer, detached, externalAad,
    )

    suspend inline fun <reified P : Any, reified H : CoseHeaderBase> sign1(
        header: H,
        payload: P,
        unprotectedLabels: Set<CborElement> = emptySet(),
        detached: Boolean = false,
        externalAad: ByteArray = byteArrayOf(),
    ): CoseSign1Typed<P, H> = sign1(
        header, payload,
        coseCompliantSerializer.serializersModule.serializer<P>(),
        coseCompliantSerializer.serializersModule.serializer<H>(),
        unprotectedLabels, detached, externalAad,
    )

    /** Signs [payload] with an already wrapped header, keeping its bucket placement. */
    suspend fun <P : Any, H : CoseHeaderBase> sign1(
        header: CoseHeaderWrapped<H>,
        payload: P,
        payloadSerializer: KSerializer<P>,
        detached: Boolean = false,
        externalAad: ByteArray = byteArrayOf(),
    ): CoseSign1Typed<P, H> {
        val signer = selectSigner(header.header)
        val plainPayload = encodePayload(payload, payloadSerializer)
        val plainProtectedHeader = header.plainProtectedHeader
        val signature = signer.sign(COSE.sign1StructureInput(plainProtectedHeader, externalAad, plainPayload)).signature
        return CoseTyped(
            cose = CoseSign1(
                plainProtectedHeader = plainProtectedHeader,
                unprotectedHeader = header.unprotectedHeader,
                plainPayload = if (detached) null else plainPayload,
                plainSignature = signature.coseBytes.copyOf(),
            ),
            payload = payload,
            wrappedHeader = header,
        )
    }

    suspend inline fun <reified P : Any, H : CoseHeaderBase> sign1(
        header: CoseHeaderWrapped<H>,
        payload: P,
        detached: Boolean = false,
        externalAad: ByteArray = byteArrayOf(),
    ): CoseSign1Typed<P, H> = sign1(
        header, payload,
        coseCompliantSerializer.serializersModule.serializer<P>(),
        detached, externalAad,
    )

    private fun selectSigner(header: CoseHeaderBase): Signer {
        val algorithm = requireNotNull(header.algorithm) { "COSE signing requires alg (label 1) in the header" }
        require(algorithm is CoseAlgorithm.Signature) { "$algorithm is not a COSE signature algorithm" }
        val signer = requireNotNull(signers[algorithm]) { "No signer registered for COSE algorithm $algorithm" }
        require(algorithm.isCompatibleWith(signer)) { "Signer does not match the COSE header algorithm $algorithm" }
        val publicKey = signer.publicKey
        header.kid?.let { kid ->
            val signerKid = publicKey.coseKid
            require(signerKid == null || kid.contentEquals(signerKid)) {
                "Signer key ID does not match the COSE header kid"
            }
        }
        header.certificateChain?.firstOrNull()?.let { leaf ->
            val certificate = requireNotNull(runCatching { Certificate.decodeFromByteArray(leaf) }.getOrNull()) {
                "x5chain leaf is not a certificate"
            }
            require(certificate.publicKey.equalsCryptographically(publicKey)) {
                "Signer public key does not match the x5chain leaf certificate"
            }
        }
        return signer
    }
}

/**
 * RSA must map to exactly this algorithm. ECDSA must match the digest, and the curve only where the COSE algorithm
 * fixes one (`ESP256`/`ESP384`/`ESP512`)
 */
private fun CoseAlgorithm.Signature.isCompatibleWith(signer: Signer): Boolean = when (val expected = algorithm) {
    is EcdsaAlgorithm -> {
        val actual = signer.signatureAlgorithm as? EcdsaAlgorithm
        val curve = (signer.publicKey as? EcdsaPublicKey)?.curve
        actual != null && curve != null && actual.digest == expected.digest &&
                (expected.requiredCurve == null || expected.requiredCurve == curve)
    }
    else -> signer.signatureAlgorithm.toCoseAlgorithm().getOrNull() == this
}