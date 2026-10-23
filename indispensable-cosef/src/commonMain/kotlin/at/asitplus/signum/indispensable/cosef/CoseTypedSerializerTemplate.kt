package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.cbor.Cbor

/**
 * Serializes a [CoseTyped] through its wire object only, decoding the payload and header on the way back.
 *
 * Mirrors josef's `JwsTypedSerializerTemplate`.
 */
class CoseTypedSerializerTemplate<C : CosePlaintextMessage, P, H : CoseHeaderBase>(
    coseSerializer: KSerializer<C>,
    payloadSerializer: KSerializer<P>,
    headerSerializer: KSerializer<H>,
    serialFormat: Cbor = coseCompliantSerializer,
) : TransformingSerializerTemplate<CoseTyped<C, P, H>, C>(
    parent = coseSerializer,
    serialName = "CoseTyped",
    encodeAs = { it.cose },
    decodeAs = { cose ->
        CoseTyped(
            cose,
            cose.getPayload(payloadSerializer, serialFormat).getOrThrow(),
            cose.wrappedHeader(headerSerializer, serialFormat),
        )
    }
)