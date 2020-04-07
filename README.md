# Overview

Example project to encrypt and decrypt a gpg file (or pgp) without the gpg executable bundles together. This code resurfaces in AWS Lambda functions nicely.


Expects access to a public key in s3, a private key in s3, and a private key passphrase in secrets manager.

## Debugging

See the launch.json for debugging, also review the top of the file `gpg-service.ts` file to ensure you are getting the correct aws resources.