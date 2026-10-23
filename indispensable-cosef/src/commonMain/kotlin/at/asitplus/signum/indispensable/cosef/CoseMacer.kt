package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.mac.mac
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.cbor.CborElement
import kotlinx.serialization.serializer

/**
 * Creates `COSE_Mac0` messages and returns typed views that retain the supplied payload and header.
 *
 * Signum has no key holder for MAC keys comparable to `Signer`, so keys are registered as raw bytes per
 * algorithm
 *
 * Copies [keys]. The header's `alg` selects the key; a missing or unregistered `alg` fails with
 * [IllegalArgumentException] before any MAC is computed. A `kid` in the header cannot be checked against a raw key
 * and is taken as supplied.
 */
@OptIn(ExperimentalSerializationApi::class)
class CoseMacer(keys: Map<CoseAlgorithm.MAC, ByteArray>) {
    private val keys = keys.mapValues { (_, key) -> key.copyOf() }

    init {
        require(this.keys.isNotEmpty()) { "At least one key is required" }
        this.keys.forEach { (algorithm, key) -> require(key.isNotEmpty()) { "Empty key registered for $algorithm" } }
    }

    /** MACs [payload] with [header]; labels in [unprotectedLabels] go into the unprotected bucket. */
    suspend fun <P : Any, H : CoseHeaderBase> mac0(
        header: H,
        payload: P,
        payloadSerializer: KSerializer<P>,
        headerSerializer: KSerializer<H>,
        unprotectedLabels: Set<CborElement> = emptySet(),
        detached: Boolean = false,
        externalAad: ByteArray = byteArrayOf(),
    ): CoseMac0Typed<P, H> = mac0(
        CoseHeaderWrapped(header, headerSerializer, unprotectedLabels),
        payload, payloadSerializer, detached, externalAad,
    )

    suspend inline fun <reified P : Any, reified H : CoseHeaderBase> mac0(
        header: H,
        payload: P,
        unprotectedLabels: Set<CborElement> = emptySet(),
        detached: Boolean = false,
        externalAad: ByteArray = byteArrayOf(),
    ): CoseMac0Typed<P, H> = mac0(
        header, payload,
        coseCompliantSerializer.serializersModule.serializer<P>(),
        coseCompliantSerializer.serializersModule.serializer<H>(),
        unprotectedLabels, detached, externalAad,
    )

    /** MACs [payload] with an already wrapped header, keeping its bucket placement. */
    suspend fun <P : Any, H : CoseHeaderBase> mac0(
        header: CoseHeaderWrapped<H>,
        payload: P,
        payloadSerializer: KSerializer<P>,
        detached: Boolean = false,
        externalAad: ByteArray = byteArrayOf(),
    ): CoseMac0Typed<P, H> {
        val (algorithm, key) = selectKey(header.header)
        val plainPayload = encodePayload(payload, payloadSerializer)
        val plainProtectedHeader = header.plainProtectedHeader
        val tag = algorithm.mac(key, COSE.mac0StructureInput(plainProtectedHeader, externalAad, plainPayload))
        return CoseTyped(
            cose = CoseMac0(
                plainProtectedHeader = plainProtectedHeader,
                unprotectedHeader = header.unprotectedHeader,
                plainPayload = if (detached) null else plainPayload,
                tag = tag,
            ),
            payload = payload,
            wrappedHeader = header,
        )
    }

    suspend inline fun <reified P : Any, H : CoseHeaderBase> mac0(
        header: CoseHeaderWrapped<H>,
        payload: P,
        detached: Boolean = false,
        externalAad: ByteArray = byteArrayOf(),
    ): CoseMac0Typed<P, H> = mac0(
        header, payload,
        coseCompliantSerializer.serializersModule.serializer<P>(),
        detached, externalAad,
    )

    private fun selectKey(header: CoseHeaderBase): Pair<CoseAlgorithm.MAC, ByteArray> {
        val algorithm = requireNotNull(header.algorithm) { "COSE MAC requires alg (label 1) in the header" }
        require(algorithm is CoseAlgorithm.MAC) { "$algorithm is not a COSE MAC algorithm" }
        val key = requireNotNull(keys[algorithm]) { "No key registered for COSE algorithm $algorithm" }
        return algorithm to key
    }
}