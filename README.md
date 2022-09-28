![GitHub banner](https://user-images.githubusercontent.com/527411/192760138-a1f61694-f705-4358-b419-e5eeb78c2ea0.png)

# DCC Boxed (Local) Key Store

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Tests](https://github.com/SmartDCCInnovation/dccboxed-keystore/actions/workflows/node.yml/badge.svg?branch=main&event=push)](https://github.com/SmartDCCInnovation/dccboxed-keystore/actions/workflows/node.yml)
[![codecov](https://codecov.io/gh/SmartDCCInnovation/dccboxed-keystore/branch/main/graph/badge.svg?token=PUCAOO95CY)](https://codecov.io/gh/SmartDCCInnovation/dccboxed-keystore)
[![GitHub version](https://badge.fury.io/gh/SmartDCCInnovation%2Fdccboxed-keystore.svg)](https://badge.fury.io/gh/SmartDCCInnovation%2Fdccboxed-keystore)


This repo holds (1) a JSON [database of certificates and private keys][keystore]
for use with [DCC Boxed][boxed] and (2) a TypeScript library for
accessing/updating the database from a DCC Boxed instance.

The provided [database][keystore] is preloaded with the `ZAZ1` remote party
credentials to enable a user to sign/validate DUIS XML signatures. However,
specific device certificates need to be fetched from the SMKI service on the DCC
Boxed instance. Thus, part of the TypeScript library includes code that can
query the SMKI service for a device certificate.

**Note:** `ZAZ1` is a self contained PKI for UK smart meter devices used for
testing and validation purposes. The ZAZ1 PKI is used by DCC&nbsp;Boxed and any
smart energy devices attached to it. 

## Usage

### Requirements

Developed and tested against `node 16`. Install from `npm`:

```
npm i @smartdcc/dccboxed-keystore
```

### Standalone JSON Database

If your use case is to access the key material for a DCC Boxed in a non
JavaScript application then a it is possible to generate an JSON file with the
certificates and keys in. For example, the [`keystore.json`][keystore] file
included in this project can be used freely in other projects.

Alternatively, if you have access to a DCC Boxed instance then this file can be
generated using the following command (along with and additional certificates
that can be included):

```
npm run build:db <boxed ip address> <outputfile.json> [<additional serials in hex>...]
```

The above command runs a [script][script] which:

  1. downloads the `org-certs.zip` file from DCC Boxed and converts the
     contained key material into a format needed by the database.
  2. The `additional serials in hex` allows for certificates that are stored in
     the SMKI service but not in `org-certs.zip` file to be fetched and added to
     the database, e.g. the ACB digital signature is one such certificate that
     is useful to have.

The format of the JSON database file is defined in
[`schema.json`](./schema.json).

### Typical Use Case

The typical use case of this library is to provide a complete wraparound all
needed key material for using DCC Boxed. Thus, it exposes the `BoxedKeyStore`
class. This class provides:

  1. Local cache (stored in a json db file of the same format described above)
  2. Backed by readonly access to the [`keystore.json`][keystore]
  3. Will search DCC Boxed SMKI for devices certificates if not found in either 1. or 2. and add them to its local cache.

Currently in step 3 it will only search for device certificates as it is assumes
that organisation certificates will not change in normal use so will be provided
in [`keystore.json`][keystore].

An example of its usage would be as follows:

```typescript
import { BoxedKeyStore, KeyUsage } from '@smartdcc/dccboxed-keystore'

const boxedIpAddress: string = '1.2.3.4'
const keyStore = await BoxedKeyStore.new(boxedIpAddress)

console.log(
  await keyStore.query({
    eui: '90B3D51F30010000',
    keyUsage: KeyUsage.digitalSignature,
    lookup: 'certificate',
    role: 2
  })
)

/* delete any temporary cache files, keyStore should not be used again after this. */
await keyStore.cleanup()
```

This could output the following (where `X509Certificate` is a class provided by
NodeJS's `crypto` library):

```js
[
  {
    eui: EUI { eui: '90b3d51f30010000' },
    keyUsage: [ 0 ],
    serial: 98403031005530424935033843217390525231n,
    role: 2,
    certificate: X509Certificate {
      subject: 'CN=GITTESTSUPPLIER\nOU=02\nx500UniqueIdentifier=\x90³Õ\\1F0\\01\\00\\00',
      subjectAltName: undefined,
      issuer: 'OU=07\nCN=Z1',
...snip...
      serialNumber: '4A07BC01D9253B51FAF01F7EC7DA5B2F'
    },
    name: 'Z1b-supplier-ds'
  },
  {
    eui: EUI { eui: '90b3d51f30010000' },
    keyUsage: [ 0 ],
    serial: 105986833131214866166891566273223584671n,
    role: 2,
    certificate: X509Certificate {
      subject: 'CN=GITTESTSUPPLIER\nOU=02\nx500UniqueIdentifier=\x90³Õ\\1F0\\01\\00\\00',
      subjectAltName: undefined,
      issuer: 'OU=07\nCN=Z1',
...snip...
      serialNumber: '4FBC525201A1D7586C1BC1C4734DEB9F'
    },
    name: 'Z1-supplier-ds'
  }
]
```

Alternatively, looking up the corresponding private keys would be as follows:

```typescript
console.log(
  await keyStore.query({
    eui: '90B3D51F30010000',
    keyUsage: KeyUsage.digitalSignature,
    lookup: 'privateKey',
    role: 2
  })
)
```

This could output the following (where `PrivateKeyObject` is a class provided by
NodeJS's `crypto` library):

```js
[
  {
    eui: EUI { eui: '90b3d51f30010000' },
    keyUsage: [ 0 ],
    serial: 98403031005530424935033843217390525231n,
    role: 2,
    privateKey: PrivateKeyObject { [Symbol(kKeyType)]: 'private' },
    name: 'Z1b-supplier-ds'
  },
  {
    eui: EUI { eui: '90b3d51f30010000' },
    keyUsage: [ 0 ],
    serial: 105986833131214866166891566273223584671n,
    role: 2,
    privateKey: PrivateKeyObject { [Symbol(kKeyType)]: 'private' },
    name: 'Z1-supplier-ds'
  }
]
```

Its just as easy to lookup a device certificate (which are not stored in
[`keystore.json`][keystore] so is queried from DCC Boxed SMKI web service, if it
exists):

```typescript
console.log(
  await keyStore.query({
    eui: '00-db-12-34-56-78-90-a4',
    keyUsage: KeyUsage.keyAgreement,
    lookup: 'certificate',
  })
)
```

Alternatively, it is possible to also query by serial number:

```typescript
console.log(
  await keyStore.query({
    serial: BigInt('105986833131214866166891566273223584671'),
    lookup: 'certificate',
  })
)
```

If persistence of the local cache is required between program runs then the
class should be instantiated as follows:

```typescript
const keyStore = BoxedKeyStore.new(boxedIpAddress, localCacheFile)
```

If the `localCacheFile` is omitted, a temporary file is crated in the system temp
folder.

### Advanced Usage

#### Certificate Metadata

In addition to the key store features described above, two utility functions are
provided to parse and extract meta data from smart metering certificates. See
`buildOrgCertificateMetadata` and `buildDeviceCertificateMetadata` functions in
[`certificateMetadata.ts`](./src/certificateMetadata.ts).

To better understand the difference between Organisation and Device certificates
please consult the [Smart Energy Code][duis] and see *Appendix A* and *Appendix
B*.

#### Query Certificates

Client side code to query the DCC Boxed SMKI service is located in
  [`certificateSearch.ts`](./src/certificateSearch.ts). It provides the ability
  to use both the certificate search and certificate retrieve API (as supported
  by DCC&nbsp;Boxed). For information about these API's, please consult the
  [Smart Energy Code][duis] and see *Appendix M*.

#### Store Internals

The underlying datastore class is provided as `KeyStoreDB`, which is a wrapper
around the [`node-json-db`][node-json-db] package. This defines both the `query`
and `push` operations used by `BoxedKeyStore`.

## Contributing

Contributions are welcome!

When submitting a pull request, please ensure:

  1. Each PR is concise and provides only one feature/bug fix.
  2. Unit test are provided to cover feature. The project uses `jest`. To test,
     run `npm run test:cov` to view code coverage metrics.
  3. Bugfixes are reference the GitHub issue.
  4. If appropriate, update documentation.
  5. Before committing, run `npm run lint` and `npm run prettier-check`.

If you are planning a new non-trivial feature, please first raise a GitHub issue
to discuss it to before investing your time to avoid disappointment.

Any contributions will be expected to be licensable under GPLv3.

## Other Info

Copyright 2022, Smart DCC Limited, All rights reserved. Project is licensed under GPLv3.

[duis]: https://smartenergycodecompany.co.uk/the-smart-energy-code-2/ 'Smart Energy Code'
[boxed]: https://www.smartdcc.co.uk/our-smart-network/network-products-services/dcc-boxed/ 'DCC Boxed'
[keystore]: keystore.json 'JSON Key Store'
[node-json-db]: https://github.com/Belphemur/node-json-db 'GitHub: Belphemur/node-json-db'
[script]: scripts/index.ts 'DB Generation Script'
