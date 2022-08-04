/*
 * Created on Thu Aug 04 2022
 *
 * Copyright (c) 2022 Smart DCC Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import { JsonDB } from 'node-json-db'
import { createPrivateKey, KeyObject, X509Certificate } from 'node:crypto'
import {
  buildDeviceCertificateMetadata,
  buildOrgCertificateMetadata,
  CertificateMetadata,
  EUI,
  KeyUsage,
  normaliseEUI,
} from './certificateMetadata'

/**
 * Specific entry in the JSON db. Indexed by the device EUI and the certificate
 * serial number. The difference between a remote party certificate and device
 * certificate is represented by the presence of the role.
 */
export interface Entry {
  /**
   * Remote party role as defined in the SEC
   */
  role?: number

  /**
   * PEM encoded X509 certificate
   */
  certificate?: string

  /**
   * PEM encoded PKCS8 private key
   */
  privateKey?: string

  /**
   * Optional free form string that can be set. E.g. could be used to store the
   * file name of the certificate (Z1-supplier) or human readable name.
   */
  name?: string
}

export type PushOptions = { name?: string } & (
  | { certificate: X509Certificate; private?: KeyObject }
  | {
      meta: Omit<CertificateMetadata, 'eui'> & {
        eui: string | Uint8Array | EUI
      }
      private: KeyObject
    }
)

function pushOptionsHasCertificate(
  p: PushOptions
): p is { name?: string; certificate: X509Certificate; private?: KeyObject } {
  return 'certificate' in p
}

// commented as not currently required
/*
function pushOptionsHasMeta(
  p: PushOptions
): p is { name?: string; certificate: X509Certificate; private?: KeyObject } {
  return 'meta' in p
}
*/

export type QueryOptions = { lookup: 'certificate' | 'privateKey' } & (
  | { serial: bigint }
  | {
      eui: string | Uint8Array | EUI
      keyUsage: KeyUsage
      role?: number
    }
)

export function queryOptionsHasEUI(q: QueryOptions): q is {
  eui: string | Uint8Array | EUI
  keyUsage: KeyUsage
  role?: number
  lookup: 'certificate' | 'privateKey'
} {
  return 'eui' in q
}

type _EUI64 = string
type _SERIAL = string
type _USAGE = 'digitalSignature' | 'keyAgreement'

export type MaybeList<T> = T | T[]

export class KeyStoreDB {
  private readonly db: JsonDB

  constructor(filename: string) {
    this.db = new JsonDB(filename, true, true)
    this.db.load()
  }

  /**
   * Search for private key
   *
   * @param options
   */
  public query(options: {
    eui: string | Uint8Array | EUI
    keyUsage: KeyUsage
    role?: number
    lookup: 'privateKey'
  }): Promise<
    null | (CertificateMetadata & { name?: string; privateKey: KeyObject })[]
  >

  /**
   * Search for certificate
   *
   * @param options
   */
  public query(options: {
    eui: string | Uint8Array | EUI
    keyUsage: KeyUsage
    role?: number
    lookup: 'certificate'
  }): Promise<
    | null
    | (CertificateMetadata & { name?: string; certificate: X509Certificate })[]
  >

  /**
   * Lookup private key by certificate serial
   *
   * @param options
   */
  public query(options: {
    serial: bigint
    lookup: 'privateKey'
  }): Promise<
    null | (CertificateMetadata & { name?: string; privateKey: KeyObject })
  >

  /**
   * Lookup certificate by serial
   *
   * @param options
   */
  public query(options: {
    serial: bigint
    lookup: 'certificate'
  }): Promise<
    | null
    | (CertificateMetadata & { name?: string; certificate: X509Certificate })
  >

  /**
   * Main interface into key store database
   *
   * @param options
   * @returns
   */
  public query(
    options: QueryOptions
  ): Promise<null | MaybeList<
    CertificateMetadata & { name?: string } & (
        | { certificate: X509Certificate }
        | { privateKey: KeyObject }
      )
  >>

  public async query(
    options: QueryOptions
  ): Promise<null | MaybeList<
    CertificateMetadata & { name?: string } & (
        | { certificate: X509Certificate }
        | { privateKey: KeyObject }
      )
  >> {
    if (queryOptionsHasEUI(options)) {
      let tree: Record<_SERIAL, Entry>
      try {
        tree = this.db.getData(
          `/${normaliseEUI(options.eui)}/${KeyUsage[options.keyUsage]}`
        ) as Record<_SERIAL, Entry>
      } catch {
        return null
      }

      /* accumulate matches */
      const results: (CertificateMetadata &
        ({ certificate: X509Certificate } | { privateKey: KeyObject }))[] = []

      for (const serial in tree) {
        const e: Entry = tree[serial]
        /* skip any entries without the correct role */
        if (typeof options.role === 'number' && e.role !== options.role) {
          continue
        }

        /* skip any entries without the request cert/key */
        if (!(options.lookup in e) || typeof e[options.lookup] !== 'string') {
          continue
        }
        let material:
          | { certificate: X509Certificate }
          | { privateKey: KeyObject }
        if (options.lookup === 'certificate') {
          material = {
            certificate: new X509Certificate(e.certificate as string),
          }
        } else {
          material = {
            privateKey: createPrivateKey({
              key: e.privateKey as string,
              type: 'pkcs8',
              format: 'pem',
            }),
          }
        }
        const role: { role?: number } = {}
        if (typeof e.role === 'number') {
          role.role = e.role
        }
        const name: { name?: string } = {}
        if (typeof e.name === 'string') {
          name.name = e.name
        }
        results.push({
          eui: options.eui instanceof EUI ? options.eui : new EUI(options.eui),
          keyUsage: [options.keyUsage],
          serial: BigInt(serial),
          ...role,
          ...material,
          ...name,
        })
      }
      if (results.length >= 1) {
        return results
      }
    } else {
      /* search by serial */
      const tree = this.db.getData('/') as Record<
        _EUI64,
        Record<_USAGE, Record<_SERIAL, Entry>>
      >
      for (const id in tree) {
        for (const usage in tree[id]) {
          for (const serial in tree[id][usage as _USAGE]) {
            if (serial === options.serial.toString()) {
              const e: Entry = tree[id][usage as _USAGE][serial]
              if (
                options.lookup in e &&
                typeof e[options.lookup] === 'string'
              ) {
                let material:
                  | { certificate: X509Certificate }
                  | { privateKey: KeyObject }
                if (options.lookup === 'certificate') {
                  material = {
                    certificate: new X509Certificate(e.certificate as string),
                  }
                } else {
                  material = {
                    privateKey: createPrivateKey({
                      key: e.privateKey as string,
                      type: 'pkcs8',
                      format: 'pem',
                    }),
                  }
                }
                const role: { role?: number } = {}
                if (typeof e.role === 'number') {
                  role.role = e.role
                }
                const name: { name?: string } = {}
                if (typeof e.name === 'string') {
                  name.name = e.name
                }
                return {
                  eui: new EUI(id),
                  keyUsage: [KeyUsage[usage as _USAGE]],
                  serial: options.serial,
                  ...role,
                  ...material,
                  ...name,
                }
              }
            }
          }
        }
      }
    }
    return null
  }

  public push(options: PushOptions): CertificateMetadata {
    let meta: CertificateMetadata
    const certificate: { certificate?: string } = {}
    const privateKey: { privateKey?: string } = {}
    const name: { name?: string } = {}
    if (typeof options.name === 'string') {
      name.name = options.name
    }
    if (pushOptionsHasCertificate(options)) {
      certificate.certificate = options.certificate.toJSON()
      try {
        meta = buildOrgCertificateMetadata(options.certificate)
      } catch {
        try {
          meta = buildDeviceCertificateMetadata(options.certificate)
        } catch {
          throw new Error('unable to extract metadata from certificate')
        }
      }
      if (options.private) {
        privateKey.privateKey = options.private?.export({
          format: 'pem',
          type: 'pkcs8',
        }) as string
        if (!options.certificate.checkPrivateKey(options.private)) {
          throw new Error('invalid key pair')
        }
      }
    } else {
      meta = { ...options.meta, eui: new EUI(normaliseEUI(options.meta.eui)) }
      privateKey.privateKey = options.private?.export({
        format: 'pem',
        type: 'pkcs8',
      }) as string
    }
    const entry: Entry = {
      ...certificate,
      ...privateKey,
      ...name,
    }
    if (typeof meta.role === 'number') {
      entry.role = meta.role
    }
    if (
      meta.keyUsage.length !== 1 &&
      meta.keyUsage[0] !== KeyUsage.digitalSignature &&
      meta.keyUsage[0] !== KeyUsage.keyAgreement
    ) {
      throw new Error('unsupported keyUsage')
    }
    this.db.push(
      `/${normaliseEUI(meta.eui)}/${KeyUsage[meta.keyUsage[0]]}/${meta.serial}`,
      entry,
      false
    )
    return meta
  }
}
