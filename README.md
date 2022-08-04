# DCC Boxed (Local) Key Store

This repo holds (1) a JSON [database of certificates and private keys][keystore]
for use with [DCC Boxed][boxed] and (2) a TypeScript library for
accessing/updating the database from a DCC Boxed instance.

The provided [database][keystore] is preloaded with the ZAZ1 remote party
credentials to enable a user to sign/validate DUIS XML signatures. However,
specific device certificates need to be fetched from the SMKI service on the DCC
Boxed instance. Thus, part of the TypeScript library includes code that can
query the SMKI service for a device certificate.

## Usage

### Standalone JSON Database

It is possible to directly use the [`keystore.json`][keystore] file included in
this project in your own projects. If you have access to a DCC Boxed instance
then this file can be rebuilt using the following:

```
npm run build:db <boxed ip address> <outputfile.json> [<additional serials in hex>...]
```

This script works by downloading the `org-certs.zip` file from DCC Boxed and
converting the key material into the database. The `additional serials in hex`
allows for certificates that are stored in SMKI but not in `org-certs.zip` file
to be fetched and added to the database, e.g. the ACB digital signature is one
such certificate that is useful to have.

The format of the JSON file is defined in [`schema.json`](./schema.json).

### Typical Use Case

The typical use case of this library is to provide a complete wraparound all
needed key material for using DCC Boxed. Thus, it exposes the `BoxedKeyStore`
class. This class provides:

  1. Local cache (stored in a json db file of the same format described above)
  2. Backed by readonly access to the [`keystore.json`][keystore]
  3. Will search DCC Boxed SMKI for devices certificates if not found in either 1. or 2. and add them to its local cache.

Currently in step 3 it will only search for device certificates as it is assume
that organisation certificates will not change in normal use so will be provided
in [`keystore.json`][keystore].

An example of its usage would be as follows:

```typescript
import { BoxedKeyStore } from '@smartdcc/dccboxed-keystore'

const boxedIpAddress: string = '1.2.3.4'
const keyStore = new BoxedKeyStore(boxedIpAddress)

console.log(
  await keyStore.query({
    eui: '90B3D51F30010000',
    keyUsage: KeyUsage.digitalSignature,
    lookup: 'certificate',
    role: 2
  })
)

console.log(
  await keyStore.query({
    eui: '90B3D51F30010000',
    keyUsage: KeyUsage.digitalSignature,
    lookup: 'privateKey',
    role: 2
  })
)
```

Its just as easy to lookup a device certificate (which is not stored in
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
const keyStore = new BoxedKeyStore(boxedIpAddress, localCacheFile)
```

If the `localCacheFile` is omitted, a temporary file is crated in the system temp
folder.

### Advanced Usage

The underlying datastore class is provided as `KeyStoreDB`, which is a wrapper
around the [`node-json-db`][node-json-db] package. This defines both the `query`
and `push` operations used by `BoxedKeyStore`.

Tools to extract the meta data from organisation and devices SMKI
certificates are provided in
[`certificateMetadata.ts`](./src/certificateMetadata.ts).

Client side code to query the DCC Boxed SMKI service is located in
[`certificateSearch.ts`](./src/certificateSearch.ts).

## Other Info

Copyright 2022, Smart DCC Limited, All rights reserved. Project is licensed under GLPv3.

[duis]: https://smartenergycodecompany.co.uk/the-smart-energy-code-2/ 'Smart Energy Code'
[boxed]: https://www.smartdcc.co.uk/our-smart-network/network-products-services/dcc-boxed/ 'DCC Boxed'
[keystore]: ./keystore.json 'JSON Key Store'
[node-json-db]: https://github.com/Belphemur/node-json-db 'GitHub: Belphemur/node-json-db'