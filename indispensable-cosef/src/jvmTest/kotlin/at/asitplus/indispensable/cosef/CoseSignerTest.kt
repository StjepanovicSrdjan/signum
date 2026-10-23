package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureInput
import at.asitplus.signum.indispensable.sign.SignatureResult
import at.asitplus.signum.indispensable.sign.SignatureVerifier
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.sign.UserInitiatedCancellation
import at.asitplus.signum.indispensable.sign.makeVerifier
import at.asitplus.signum.indispensable.sign.verify
import at.asitplus.signum.supreme.Supreme
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborElement
import kotlinx.serialization.cbor.CborInteger
import kotlinx.serialization.cbor.CborString

@Serializable
internal data class SignedClaims(val sub: String)

private suspend fun newEcSigner(): Signer.WithExportableKey = Signer.Ephemeral { ec {} }

private suspend fun newRsaSigner(): Signer.WithExportableKey = Signer.Ephemeral {
    rsa {
        bits = 2048
        digest = Digest.SHA256
        padding = RsaAlgorithm.Padding.PSS
    }
}

private class CountingSigner(private val delegate: Signer) : Signer by delegate {
    var calls = 0
        private set

    override suspend fun sign(data: SignatureInput): SignatureResult<*> {
        calls++
        return delegate.sign(data)
    }
}

@OptIn(ExperimentalSerializationApi::class)
val CoseSignerTest by matrixSuite {
    Supreme.init()

    val claims = SignedClaims("alice")

    "sign1 produces a verifiable COSE_Sign1 and retains payload and header" {
        val signer = newEcSigner()
        val header = CoseHeader(algorithm = CoseAlgorithm.Signature.ES256)
        val typed = CoseSigner(mapOf(CoseAlgorithm.Signature.ES256 to signer)).sign1(header, claims)

        typed.payload shouldBe claims
        typed.header shouldBe header
        typed.cose.plainSignature shouldBe typed.signature.coseBytes

        val parsed = CoseSign1(coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), typed.cose))
        parsed.typed<SignedClaims, CoseHeader>() shouldBe typed
        signer.makeVerifier().verify(parsed.signatureInput(), typed.signature) shouldBe SignatureVerifier.Success
    }

    "the header algorithm selects the registered signer" {
        val ec = newEcSigner()
        val rsa = newRsaSigner()
        // registration order differs from signing order, so positional selection would fail
        val coseSigner = CoseSigner(mapOf(
            CoseAlgorithm.Signature.PS256 to rsa,
            CoseAlgorithm.Signature.ES256 to ec,
        ))
        for ((algorithm, signer) in listOf(CoseAlgorithm.Signature.ES256 to ec, CoseAlgorithm.Signature.PS256 to rsa)) {
            val typed = coseSigner.sign1(CoseHeader(algorithm = algorithm), claims)
            signer.makeVerifier().verify(typed.cose.signatureInput(), typed.signature) shouldBe SignatureVerifier.Success
        }
    }

    "unprotected labels are placed in the unprotected bucket" {
        val typed = CoseSigner(mapOf(CoseAlgorithm.Signature.ES256 to newEcSigner())).sign1(
            CoseHeader(algorithm = CoseAlgorithm.Signature.ES256, kid = "kid".encodeToByteArray()),
            claims,
            unprotectedLabels = setOf(CborInteger(4)),
        )

        typed.cose.protectedHeader.keys shouldBe setOf<CborElement>(CborInteger(1))
        typed.cose.unprotectedHeader.keys shouldBe setOf<CborElement>(CborInteger(4))
        typed.unprotectedLabels shouldBe setOf<CborElement>(CborInteger(4))
    }

    "an already wrapped header keeps its bucket placement" {
        val signer = newEcSigner()
        val wrapped = CoseHeaderWrapped(
            CoseHeader(algorithm = CoseAlgorithm.Signature.ES256, kid = "kid".encodeToByteArray()),
            unprotectedLabels = setOf(CborInteger(4)),
        )
        val typed = CoseSigner(mapOf(CoseAlgorithm.Signature.ES256 to signer)).sign1(wrapped, claims)

        typed.cose.wrappedHeader<CoseHeader>() shouldBe wrapped
        typed.unprotectedLabels shouldBe setOf<CborElement>(CborInteger(4))
        signer.makeVerifier().verify(typed.cose.signatureInput(), typed.signature) shouldBe SignatureVerifier.Success
    }

    "a custom header model is signed with its own parameters" {
        val signer = newEcSigner()
        val header = AppHeader(algorithm = CoseAlgorithm.Signature.ES256, app = "x")
        val typed = CoseSigner(mapOf(CoseAlgorithm.Signature.ES256 to signer)).sign1(header, claims)

        typed.header shouldBe header
        typed.cose.protectedHeader[CborInteger(-65537)] shouldBe CborString("x")

        val parsed = CoseSign1(coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), typed.cose))
        parsed.typed<SignedClaims, AppHeader>() shouldBe typed
        signer.makeVerifier().verify(parsed.signatureInput(), typed.signature) shouldBe SignatureVerifier.Success
    }

    "detached signing with external AAD verifies over the supplied payload" {
        val signer = newEcSigner()
        val aad = "aad".encodeToByteArray()
        val typed = CoseSigner(mapOf(CoseAlgorithm.Signature.ES256 to signer)).sign1(
            CoseHeader(algorithm = CoseAlgorithm.Signature.ES256), claims, detached = true, externalAad = aad,
        )

        typed.cose.plainPayload.shouldBeNull()
        typed.payload shouldBe claims
        val input = typed.cose.signatureInput(aad, detachedPayload = encodePayload(claims, SignedClaims.serializer()))
        signer.makeVerifier().verify(input, typed.signature) shouldBe SignatureVerifier.Success
    }

    "ES256 does not bind a curve, ESP256 does" {
        val p256 = newEcSigner()
        CoseSigner(mapOf(CoseAlgorithm.Signature.ES256 to p256))
        val typed = CoseSigner(mapOf(CoseAlgorithm.Signature.ESP256 to p256))
            .sign1(CoseHeader(algorithm = CoseAlgorithm.Signature.ESP256), claims)
        p256.makeVerifier().verify(typed.cose.signatureInput(), typed.signature) shouldBe SignatureVerifier.Success

        val otherCurveKey = Signer.Ephemeral { ec { curve = ECCurve.SECP_384_R_1 } }.publicKey
        val wrongCurve = object : Signer by p256 {
            override val publicKey = otherCurveKey
        }
        shouldThrow<IllegalArgumentException> { CoseSigner(mapOf(CoseAlgorithm.Signature.ESP256 to wrongCurve)) }
    }

    "invalid headers are rejected before invoking the signer" {
        val signer = CountingSigner(newEcSigner())
        signer.publicKey.coseKid = "actual-key".encodeToByteArray()
        val coseSigner = CoseSigner(mapOf(CoseAlgorithm.Signature.ES256 to signer))
        for (header in listOf(
            CoseHeader(),
            CoseHeader(algorithm = CoseAlgorithm.Signature.PS256),
            CoseHeader(algorithm = CoseAlgorithm.MAC.HS256),
            CoseHeader(algorithm = CoseAlgorithm.Signature.ES256, kid = "old-key".encodeToByteArray()),
        )) {
            shouldThrow<IllegalArgumentException> { coseSigner.sign1(header, claims) }
        }
        signer.calls shouldBe 0

        coseSigner.sign1(CoseHeader(algorithm = CoseAlgorithm.Signature.ES256, kid = "actual-key".encodeToByteArray()), claims)
        signer.calls shouldBe 1
    }

    "invalid signer configurations are rejected" {
        shouldThrow<IllegalArgumentException> { CoseSigner(emptyMap()) }
        shouldThrow<IllegalArgumentException> { CoseSigner(mapOf(CoseAlgorithm.Signature.RS256 to newEcSigner())) }
        shouldThrow<IllegalArgumentException> { CoseSigner(mapOf(CoseAlgorithm.Signature.ES384 to newEcSigner())) }
    }

    "registered signers survive later changes to the supplied map" {
        val original = newEcSigner()
        val signers = mutableMapOf<CoseAlgorithm.Signature, Signer>(CoseAlgorithm.Signature.ES256 to original)
        val coseSigner = CoseSigner(signers)
        signers.clear()

        val typed = coseSigner.sign1(CoseHeader(algorithm = CoseAlgorithm.Signature.ES256), claims)
        original.makeVerifier().verify(typed.cose.signatureInput(), typed.signature) shouldBe SignatureVerifier.Success
    }

    "signer cancellation propagates unchanged" {
        val delegate = newEcSigner()
        val problem = UserInitiatedCancellation("cancelled", null)
        val signer = object : Signer by delegate {
            override suspend fun sign(data: SignatureInput): SignatureResult<*> = SignatureResult.Failure(problem)
        }
        shouldThrow<UserInitiatedCancellation> {
            CoseSigner(mapOf(CoseAlgorithm.Signature.ES256 to signer))
                .sign1(CoseHeader(algorithm = CoseAlgorithm.Signature.ES256), claims)
        } shouldBe problem
    }
}