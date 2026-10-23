package at.asitplus.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.AppHeader
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseHeaderWrapped
import at.asitplus.signum.indispensable.cosef.CoseMac0
import at.asitplus.signum.indispensable.cosef.CoseMacer
import at.asitplus.signum.indispensable.cosef.encodePayload
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.typed
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.mac
import at.asitplus.signum.supreme.Supreme
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.cbor.CborElement
import kotlinx.serialization.cbor.CborInteger
import kotlinx.serialization.cbor.CborString

@OptIn(ExperimentalSerializationApi::class)
val CoseMacerTest by matrixSuite {
    Supreme.init()

    val key = ByteArray(32) { it.toByte() }
    val claims = SignedClaims("alice")

    "mac0 produces the HMAC over the MAC_structure and retains payload and header" {
        val header = CoseHeader(algorithm = CoseAlgorithm.MAC.HS256)
        val typed = CoseMacer(mapOf(CoseAlgorithm.MAC.HS256 to key)).mac0(header, claims)

        typed.payload shouldBe claims
        typed.header shouldBe header
        typed.cose.tag shouldBe HMAC.SHA256.mac(key, typed.cose.macInput())

        val parsed = CoseMac0.Companion(
            coseCompliantSerializer.encodeToByteArray(
                CoseMac0.Companion.serializer(),
                typed.cose
            )
        )
        parsed.typed<SignedClaims, CoseHeader>() shouldBe typed
    }

    "the header algorithm selects the registered key" {
        val otherKey = ByteArray(48) { (it + 100).toByte() }
        val macer = CoseMacer(
            mapOf(
                CoseAlgorithm.MAC.HS384 to otherKey,
                CoseAlgorithm.MAC.HS256 to key,
            )
        )

        val hs256 = macer.mac0(CoseHeader(algorithm = CoseAlgorithm.MAC.HS256), claims)
        hs256.cose.tag shouldBe HMAC.SHA256.mac(key, hs256.cose.macInput())

        val hs384 = macer.mac0(CoseHeader(algorithm = CoseAlgorithm.MAC.HS384), claims)
        hs384.cose.tag shouldBe HMAC.SHA384.mac(otherKey, hs384.cose.macInput())
    }

    "HS256/64 yields a truncated 8-byte tag" {
        val typed = CoseMacer(mapOf(CoseAlgorithm.MAC.HS256_64 to key))
            .mac0(CoseHeader(algorithm = CoseAlgorithm.MAC.HS256_64), claims)

        typed.cose.tag.size shouldBe 8
        typed.cose.tag shouldBe HMAC.SHA256.mac(key, typed.cose.macInput()).copyOf(8)
    }

    "unprotected labels are placed in the unprotected bucket" {
        val typed = CoseMacer(mapOf(CoseAlgorithm.MAC.HS256 to key)).mac0(
            CoseHeader(algorithm = CoseAlgorithm.MAC.HS256, kid = "kid".encodeToByteArray()),
            claims,
            unprotectedLabels = setOf(CborInteger(4)),
        )

        typed.cose.protectedHeader.keys shouldBe setOf<CborElement>(CborInteger(1))
        typed.cose.unprotectedHeader.keys shouldBe setOf<CborElement>(CborInteger(4))
        typed.unprotectedLabels shouldBe setOf<CborElement>(CborInteger(4))
    }

    "an already wrapped header keeps its bucket placement" {
        val wrapped = CoseHeaderWrapped.Companion(
            CoseHeader(algorithm = CoseAlgorithm.MAC.HS256, kid = "kid".encodeToByteArray()),
            unprotectedLabels = setOf(CborInteger(4)),
        )
        val typed = CoseMacer(mapOf(CoseAlgorithm.MAC.HS256 to key)).mac0(wrapped, claims)

        typed.cose.wrappedHeader<CoseHeader>() shouldBe wrapped
        typed.cose.tag shouldBe HMAC.SHA256.mac(key, typed.cose.macInput())
    }

    "a custom header model is MACed with its own parameters" {
        val header = AppHeader(algorithm = CoseAlgorithm.MAC.HS256, app = "x")
        val typed = CoseMacer(mapOf(CoseAlgorithm.MAC.HS256 to key)).mac0(header, claims)

        typed.header shouldBe header
        typed.cose.protectedHeader[CborInteger(-65537)] shouldBe CborString("x")
        typed.cose.tag shouldBe HMAC.SHA256.mac(key, typed.cose.macInput())

        val parsed = CoseMac0.Companion(
            coseCompliantSerializer.encodeToByteArray(
                CoseMac0.Companion.serializer(),
                typed.cose
            )
        )
        parsed.typed<SignedClaims, AppHeader>() shouldBe typed
    }

    "detached MAC with external AAD covers the supplied payload" {
        val aad = "aad".encodeToByteArray()
        val typed = CoseMacer(mapOf(CoseAlgorithm.MAC.HS256 to key)).mac0(
            CoseHeader(algorithm = CoseAlgorithm.MAC.HS256), claims, detached = true, externalAad = aad,
        )

        typed.cose.plainPayload.shouldBeNull()
        typed.payload shouldBe claims
        val input = typed.cose.macInput(aad, detachedPayload = encodePayload(
            claims,
            SignedClaims.serializer()
        )
        )
        typed.cose.tag shouldBe HMAC.SHA256.mac(key, input)
    }

    "invalid headers and configurations are rejected" {
        val macer = CoseMacer(mapOf(CoseAlgorithm.MAC.HS256 to key))
        for (header in listOf(
            CoseHeader(),
            CoseHeader(algorithm = CoseAlgorithm.MAC.HS384),
            CoseHeader(algorithm = CoseAlgorithm.Signature.ES256),
        )) {
            shouldThrow<IllegalArgumentException> { macer.mac0(header, claims) }
        }
        shouldThrow<IllegalArgumentException> { CoseMacer(emptyMap()) }
        shouldThrow<IllegalArgumentException> { CoseMacer(mapOf(CoseAlgorithm.MAC.HS256 to byteArrayOf())) }
    }

    "the registered key is copied" {
        val mutableKey = key.copyOf()
        val macer = CoseMacer(mapOf(CoseAlgorithm.MAC.HS256 to mutableKey))
        mutableKey.fill(0)

        val typed = macer.mac0(CoseHeader(algorithm = CoseAlgorithm.MAC.HS256), claims)
        typed.cose.tag shouldBe HMAC.SHA256.mac(key, typed.cose.macInput())
    }
}