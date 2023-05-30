// import { JwtCredentialPayload, createVerifiableCredentialJwt } from 'did-jwt-vc'
import { ES256KSigner, hexToBytes, decodeJWT } from 'did-jwt';
import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyCredential, verifyPresentation } from 'did-jwt-vc'
import { Resolver } from 'did-resolver'
import { getResolver } from 'web-did-resolver'

const vcJwt = 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRlZ3JlZSI6eyJ0eXBlIjoiTWFzdGVyc0RlZ3JlZSIsIm5hbWUiOiJNYXN0ZXJzIGluIE1vZGVsaW5nIGFuZCBTaW11bGF0aW9uIn19fSwic3ViIjoiZGlkOndlYjpwZm95dGlrLmdpdGh1Yi5pbyIsIm5iZiI6MTU2Mjk1MDI4MiwiaXNzIjoiZGlkOndlYjpwZm95dGlrLmdpdGh1Yi5pbyJ9.18OvXDen8osYaEittQRLFhAtj0O7IAQvU9BO7N-trkR4XnaMRyYYpWQ2jaerNIOANmo5qlZCOk_RJ_2X5u0l3g'

const vpJwt = 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0owZVhBaU9pSktWMVFpZlEuZXlKMll5STZleUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdk1qQXhPQzlqY21Wa1pXNTBhV0ZzY3k5Mk1TSmRMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWwwc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJbVJsWjNKbFpTSTZleUowZVhCbElqb2lUV0Z6ZEdWeWMwUmxaM0psWlNJc0ltNWhiV1VpT2lKTllYTjBaWEp6SUdsdUlFMXZaR1ZzYVc1bklHRnVaQ0JUYVcxMWJHRjBhVzl1SW4xOWZTd2ljM1ZpSWpvaVpHbGtPbmRsWWpwd1ptOTVkR2xyTG1kcGRHaDFZaTVwYnlJc0ltNWlaaUk2TVRVMk1qazFNREk0TWl3aWFYTnpJam9pWkdsa09uZGxZanB3Wm05NWRHbHJMbWRwZEdoMVlpNXBieUo5LjE4T3ZYRGVuOG9zWWFFaXR0UVJMRmhBdGowTzdJQVF2VTlCTzdOLXRya1I0WG5hTVJ5WVlwV1EyamFlck5JT0FObW81cWxaQ09rX1JKXzJYNXUwbDNnIl0sImRlZ3JlZSI6eyJ0eXBlIjoiTWFzdGVyc0RlZ3JlZSIsIm5hbWUiOiJNYXN0ZXJzIGluIE1vZGVsaW5nIGFuZCBTaW11bGF0aW9uIn19LCJpc3MiOiJkaWQ6d2ViOnBmb3l0aWsuZ2l0aHViLmlvIn0.zk8ozx6swRcD9Ho4WbgwiPuTj5TaWlOFvJmwZDcsL1guDcpsXNIR6R2xnA4h1bouYOKkmi4Ir7MUtWR-1SRUHQ'

// Prepare the did:web resolver
const resolver = new Resolver(getResolver())

// Verify the Credentantial and the Presentation
const decodedCred = decodeJWT(vcJwt)
console.log('Degree Type: ', decodedCred['payload']['vc']['credentialSubject']['degree'])
const verifiedVC = await verifyCredential(vcJwt, resolver)
console.log('VerifiedCredentials: ', verifiedVC['verified'])

const verifiedVP = await verifyPresentation(vpJwt, resolver)
console.log('VerifiedPresentation: ', verifiedVP['verified'])

