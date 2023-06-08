// import { JwtCredentialPayload, createVerifiableCredentialJwt } from 'did-jwt-vc'
import { ES256KSigner, hexToBytes, decodeJWT } from 'did-jwt';
import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyCredential, verifyPresentation } from 'did-jwt-vc'
import { Resolver } from 'did-resolver'
import { getResolver } from 'web-did-resolver'


// Create a singer by using a private key (hex).
const key = '79fe6ebcdc25e141b17078454f5dedaee1859d3d8b6d0530067d697b5819c810';
const signer = ES256KSigner(hexToBytes(key))

// Prepare an issuer
const issuer = {
    did: 'did:web:pfoytik.github.io',
    signer: signer
}

// Prepare the Verifiable Credential Payload
const vcPayload = {
  sub: 'did:web:pfoytik.github.io',
  nbf: 1562950282,
  vc: {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    credentialSubject: {
      ue: { "_id" : "642c5e0474064ce427ff0a96", "schema_version" : 1, "imsi" : "999700000000001", "msisdn" : [ ], "imeisv" : "4370816125816151", "mme_host" : [ ], "mme_realm" : [ ], "purge_flag" : [ ], "security" : { "k" : "465B5CE8 B199B49F AA5F0A2E E238A6BC", "op" : null, "opc" : "E8ED289D EBA952E4 283B54E8 8E6183CA", "amf" : "8000", "sqn" : 1281 }, "ambr" : { "downlink" : { "value" : 1, "unit" : 3 }, "uplink" : { "value" : 1, "unit" : 3 } }, "slice" : [ { "sst" : 1, "default_indicator" : true, "session" : [ { "name" : "internet", "type" : 3, "qos" : { "index" : 9, "arp" : { "priority_level" : 8, "pre_emption_capability" : 1, "pre_emption_vulnerability" : 1 } }, "ambr" : { "downlink" : { "value" : 1, "unit" : 3 }, "uplink" : { "value" : 1, "unit" : 3 } }, "_id" : "642c5e0474064ce427ff0a98", "pcc_rule" : [ ] } ], "_id" : "642c5e0474064ce427ff0a97" } ], "access_restriction_data" : 32, "subscriber_status" : 0, "network_access_mode" : 0, "subscribed_rau_tau_timer" : 12, "__v" : 0 }
    }
  }
}

// Create the Verifiable Credential (JWT)
const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer)
console.log('//// Verifiable Credential:\n', vcJwt)

// Prepare the Verifiable Presentation Payload
const vpPayload = {
  vp: {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiablePresentation'],
    verifiableCredential: [vcJwt],
    ue: { "_id" : "642c5e0474064ce427ff0a96", "schema_version" : 1, "imsi" : "999700000000001", "msisdn" : [ ], "imeisv" : "4370816125816151", "mme_host" : [ ], "mme_realm" : [ ], "purge_flag" : [ ], "security" : { "k" : "465B5CE8 B199B49F AA5F0A2E E238A6BC", "op" : null, "opc" : "E8ED289D EBA952E4 283B54E8 8E6183CA", "amf" : "8000", "sqn" : 1281 }, "ambr" : { "downlink" : { "value" : 1, "unit" : 3 }, "uplink" : { "value" : 1, "unit" : 3 } }, "slice" : [ { "sst" : 1, "default_indicator" : true, "session" : [ { "name" : "internet", "type" : 3, "qos" : { "index" : 9, "arp" : { "priority_level" : 8, "pre_emption_capability" : 1, "pre_emption_vulnerability" : 1 } }, "ambr" : { "downlink" : { "value" : 1, "unit" : 3 }, "uplink" : { "value" : 1, "unit" : 3 } }, "_id" : "642c5e0474064ce427ff0a98", "pcc_rule" : [ ] } ], "_id" : "642c5e0474064ce427ff0a97" } ], "access_restriction_data" : 32, "subscriber_status" : 0, "network_access_mode" : 0, "subscribed_rau_tau_timer" : 12, "__v" : 0 }
}
}

// Create the Verifiable Presentation (JWT)
const vpJwt = await createVerifiablePresentationJwt(vpPayload, issuer)
console.log('\n//// Verifiable Presentation:\n', vpJwt)

// Resolve and Verify  

// Prepare the did:web resolver
const resolver = new Resolver(getResolver())

// Verify the Credentantial and the Presentation
const decodedCred = decodeJWT(vcJwt)
console.log('///// ue imsi:\n', decodedCred['payload']['vc']['credentialSubject']['ue']['imsi'])
const verifiedVC = await verifyCredential(vcJwt, resolver)
console.log('//// Verified Credentials:\n', verifiedVC)

const verifiedVP = await verifyPresentation(vpJwt, resolver)
console.log('\n//// Verified Presentation:\n', verifiedVP)

