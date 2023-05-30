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
      degree: {
        type: 'MastersDegree',
        name: 'Masters in Modeling and Simulation'
      }
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
    degree: {
	    type: 'MastersDegree',
	    name: 'Masters in Modeling and Simulation'
    }
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
console.log('///// Degree Type:\n', decodedCred['payload']['vc']['credentialSubject']['degree'])
const verifiedVC = await verifyCredential(vcJwt, resolver)
console.log('//// Verified Credentials:\n', verifiedVC)

const verifiedVP = await verifyPresentation(vpJwt, resolver)
console.log('\n//// Verified Presentation:\n', verifiedVP)

