import { createJWT, verifyJWT, ES256KSigner, hexToBytes, decodeJWT } from 'did-jwt';
import { Resolver } from 'did-resolver'
import { getResolver } from 'web-did-resolver'

// Create a singer by using a private key (hex).
const key = '79fe6ebcdc25e141b17078454f5dedaee1859d3d8b6d0530067d697b5819c810';
const signer = ES256KSigner(hexToBytes(key))

// Create a signed JWT
const jwt = await createJWT(
  { aud: 'did:web:pfoytik.github.io', name: 'Peter Foytik' },
  { issuer: 'did:web:pfoytik.github.io', signer },
  { alg: 'ES256K' }
)

console.log(`//// JWT:\n${jwt}`)

// Decode the JWT
const decoded = decodeJWT(jwt)
console.log('\n//// JWT Decoded:\n',decoded)

// Verify the JWT by resolving its DID:WEB
const webResolver = getResolver()
//console.log(webResolver)
const resolver = new Resolver({
  ...webResolver
})

//resolver.resolve("did:web:pfoytik.github.io").then(doc =>console.log(doc))

verifyJWT(jwt, {
  resolver,
  audience: "did:web:pfoytik.github.io"
}).then(({ payload, doc, did, signer, jwt }) => {
  console.log('\n//// Verified:\n', payload)
})
