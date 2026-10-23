package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.contentHashCodeIfArray
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.cbor.CborElement

typealias CoseSign1Typed<P, H> = CoseTyped<CoseSign1, P, H>
typealias CoseMac0Typed<P, H> = CoseTyped<CoseMac0, P, H>

/**
 * Typed payload and effective header over an unchanged [cose] wire object.
 *
 * Create values through [CoseSigner] / [CoseMacer] and decode views through `typed()`; construction and copying are
 * internal. COSE_Sign1 and COSE_Mac0 share one structure, so they share this view; the signature of a
 * [CoseSign1Typed] is derived on access, see [signature].
 * Forward [cose] or serialize through [CoseTypedSerializerTemplate] to preserve the original bytes.
 * Typed decoding does not verify signatures or MACs, nor establish key trust.
 */
@OptIn(ExperimentalSerializationApi::class)
@ConsistentCopyVisibility
data class CoseTyped<out C : COSE, out P, H : CoseHeaderBase> internal constructor(
    val cose: C,
    val payload: P,
    internal val wrappedHeader: CoseHeaderWrapped<H>,
) {
    override fun toString(): String = cose.toString()

    /** The effective header: protected and unprotected bucket combined and decoded. */
    val header: H get() = wrappedHeader.header

    /** Labels of [header] carried in the unprotected bucket. */
    val unprotectedLabels: Set<CborElement> get() = wrappedHeader.unprotectedLabels

    /** Labels listed in `crit`, which the application must understand. */
    val criticalLabels: List<CborElement> get() = wrappedHeader.criticalLabels

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseTyped<*, *, *>

        if (cose != other.cose) return false
        if (payload != null) {
            if (other.payload == null) return false
            if (!payload.contentEqualsIfArray(other.payload)) return false
        } else if (other.payload != null) return false
        if (wrappedHeader != other.wrappedHeader) return false

        return true
    }

    override fun hashCode(): Int {
        var result = cose.hashCode()
        result = 31 * result + (payload?.contentHashCodeIfArray() ?: 0)
        result = 31 * result + wrappedHeader.hashCode()
        return result
    }

    /** Builders from raw signature / MAC functions, for tests and internal use. Public: [CoseSigner], [CoseMacer]. */
    internal companion object {

        suspend fun <P : Any, H : CoseHeaderBase> sign1(
            header: CoseHeaderWrapped<H>,
            payload: P,
            payloadSerializer: KSerializer<P>,
            detached: Boolean = false,
            externalAad: ByteArray = byteArrayOf(),
            signer: suspend (ByteArray) -> ByteArray,
        ): CoseSign1Typed<P, H> = CoseTyped(
            CoseSign1(
                header = header,
                plainPayload = encodePayload(payload, payloadSerializer),
                detached = detached,
                externalAad = externalAad,
                signer = signer,
            ),
            payload,
            header,
        )

        suspend fun <P : Any> sign1(
            protectedHeader: CoseHeader,
            unprotectedHeader: CoseHeader? = null,
            payload: P,
            payloadSerializer: KSerializer<P>,
            detached: Boolean = false,
            externalAad: ByteArray = byteArrayOf(),
            signer: suspend (ByteArray) -> ByteArray,
        ): CoseSign1Typed<P, CoseHeader> = sign1(
            wrapCoseHeaders(protectedHeader, unprotectedHeader),
            payload, payloadSerializer, detached, externalAad, signer,
        )

        suspend fun <P : Any, H : CoseHeaderBase> mac0(
            header: CoseHeaderWrapped<H>,
            payload: P,
            payloadSerializer: KSerializer<P>,
            detached: Boolean = false,
            externalAad: ByteArray = byteArrayOf(),
            mac: suspend (ByteArray) -> ByteArray,
        ): CoseMac0Typed<P, H> = CoseTyped(
            CoseMac0(
                header = header,
                plainPayload = encodePayload(payload, payloadSerializer),
                detached = detached,
                externalAad = externalAad,
                mac = mac,
            ),
            payload,
            header,
        )

        suspend fun <P : Any> mac0(
            protectedHeader: CoseHeader,
            unprotectedHeader: CoseHeader? = null,
            payload: P,
            payloadSerializer: KSerializer<P>,
            detached: Boolean = false,
            externalAad: ByteArray = byteArrayOf(),
            mac: suspend (ByteArray) -> ByteArray,
        ): CoseMac0Typed<P, CoseHeader> = mac0(
            wrapCoseHeaders(protectedHeader, unprotectedHeader),
            payload, payloadSerializer, detached, externalAad, mac,
        )
    }
}

/** The signature of a [CoseSign1], interpreted according to `alg` (or the `x5chain` leaf) of the effective header. */
val CoseSign1Typed<*, *>.signature: CryptoSignature
    get() = COSE.getSignature(cose.plainSignature, header)

/**
 * Encodes [payload] the way the previous `CoseSigned.create` did: a [ByteArray] is used as-is, anything else is
 * serialized and wrapped in CBOR tag 24
 */
internal fun <P : Any> encodePayload(payload: P, payloadSerializer: KSerializer<P>): ByteArray = when (payload) {
    is ByteArray -> payload
    is ByteStringWrapper<*> -> throw IllegalArgumentException("Payload must not be a ByteStringWrapper")
    else -> coseCompliantSerializer.encodeToByteArray(
        ByteStringWrapperSerializer(payloadSerializer), ByteStringWrapper(payload)
    ).wrapInCborTag(24)
}