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

import { KeyObject, X509Certificate } from 'node:crypto'
import { rm } from 'node:fs/promises'
import { resolve } from 'node:path'
import { tmpNameSync } from 'tmp'
import {
  EUI,
  KeyUsage,
  CertificateMetadata,
  normaliseEUI,
} from './certificateMetadata'
import {
  CertificateStatus,
  CertificateUsage,
  query,
  search,
} from './certificateSearch'
import { KeyStoreDB, MaybeList, QueryOptions, queryOptionsHasEUI } from './db'

export const defaultBackingFile = resolve(__dirname, '..', 'keystore.json')

export class BoxedKeyStore extends KeyStoreDB {
  public get temporyFile(): string | undefined {
    return this._temporyFile
  }

  /**
   * Creates a new caching key store
   *
   * @param boxedAddress ip address of a DCC Boxed instance
   * @param backingDB backing readonly database
   * @param localFile local file to cache updates to, if undefined a temporary file is created
   * @param _temporyFile
   */
  protected constructor(
    private boxedAddress: string,
    private backingDB: KeyStoreDB,
    localFile: string,
    private _temporyFile?: string,
  ) {
    super(localFile)
  }

  /**
   * Wrap constructor for async operations.
   *
   * @param boxedAddress ip address of a DCC Boxed instance
   * @param localFile local file to cache updates to, if undefined a temporary file is created
   * @param backingFile backing readonly database file, if undefined a default backing file is used
   * @returns
   */
  public static async new(
    boxedAddress: string,
    localFile?: string,
    backingFile?: string,
  ): Promise<BoxedKeyStore> {
    let tmp_flag = false
    if (typeof localFile !== 'string') {
      localFile = tmpNameSync({ postfix: '.json' })
      tmp_flag = true
    }
    const instance = new BoxedKeyStore(
      boxedAddress,
      await KeyStoreDB.new(backingFile ?? defaultBackingFile),
      localFile,
      tmp_flag ? localFile : undefined,
    )
    await instance.db.load()
    return instance
  }

  public override query(options: {
    eui: string | Uint8Array | EUI
    keyUsage: KeyUsage
    role?: number | undefined
    lookup: 'privateKey'
  }): Promise<
    (CertificateMetadata & { name?: string; privateKey: KeyObject })[] | null
  >
  public override query(options: {
    eui: string | Uint8Array | EUI
    keyUsage: KeyUsage
    role?: number | undefined
    lookup: 'certificate'
  }): Promise<
    | (CertificateMetadata & { name?: string; certificate: X509Certificate })[]
    | null
  >
  public override query(options: {
    serial: bigint
    lookup: 'privateKey'
  }): Promise<
    (CertificateMetadata & { name?: string; privateKey: KeyObject }) | null
  >
  public override query(options: {
    serial: bigint
    lookup: 'certificate'
  }): Promise<
    | (CertificateMetadata & { name?: string; certificate: X509Certificate })
    | null
  >
  public override query(
    options: QueryOptions,
  ): Promise<MaybeList<
    CertificateMetadata & { name?: string } & (
        | { certificate: X509Certificate }
        | { privateKey: KeyObject }
      )
  > | null>

  public override async query(
    options: QueryOptions,
  ): Promise<MaybeList<
    CertificateMetadata & { name?: string } & (
        | { certificate: X509Certificate }
        | { privateKey: KeyObject }
      )
  > | null> {
    let x = await super.query(options)
    if (x) {
      return x
    }
    x = await this.backingDB.query(options)
    if (x) {
      return x
    }

    if (options.lookup === 'certificate') {
      if (queryOptionsHasEUI(options)) {
        let keyUsage: CertificateUsage
        switch (options.keyUsage) {
          case KeyUsage.digitalSignature:
            keyUsage = CertificateUsage['Digital Signing']
            break
          case KeyUsage.keyAgreement:
            keyUsage = CertificateUsage['Key Agreement']
            break
          default:
            return null
        }
        /* role is only valid for org certs which are not currently supported to
        be queried  */
        //const role: { CertificateRole?: number } = {}
        if (typeof options.role === 'number') {
          return null
          //  role.CertificateRole = options.role
        }
        const sr = {
          CertificateUsage: keyUsage,
          CertificateStatus: CertificateStatus['In use'],
          //    ...role,
          q: {
            CertificateSubjectAltName: normaliseEUI(options.eui)
              .toString()
              .replace(/(.{2})(?!$)/g, '$1-'),
          },
        }
        const qrs = await search(sr, this.boxedAddress)
        if (qrs.length >= 1) {
          for (const qr of qrs) {
            await super.push({ certificate: qr.x509 })
          }
          return qrs.map(({ meta, x509 }) => ({ ...meta, certificate: x509 }))
        }
      } else {
        const r = await query(options.serial.toString(16), this.boxedAddress)
        if (r) {
          await super.push({ certificate: r.x509 })
          return { ...r.meta, certificate: r.x509 }
        }
      }
    }
    return null
  }

  /**
   * deletes any temporary files created
   */
  public async cleanup(): Promise<void> {
    if (typeof this.temporyFile === 'string') {
      await rm(this.temporyFile)
    }
  }
}
