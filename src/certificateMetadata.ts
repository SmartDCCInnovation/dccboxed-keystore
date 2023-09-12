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

import { X509Certificate } from 'node:crypto'
import {
  ASN1Construction,
  ASN1Element,
  ASN1TagClass,
  BERElement,
  packBits,
  SEQUENCE,
} from 'asn1-ts'
import { isUint8Array } from 'node:util/types'

export function normaliseEUI(eui: string | Uint8Array | EUI): string {
  let result: string
  if (typeof eui === 'string') {
    result = eui.toLowerCase().replace(/\s/g, '').replace(/-/g, '')
  } else if (isUint8Array(eui)) {
    result = Buffer.from(eui).toString('hex')
  } else if (eui instanceof EUI) {
    result = eui.valueOf()
  } else {
    throw new TypeError('eui should be a string or Uint8Array')
  }

  if (result.match(/^[0-9a-f]{16}$/) === null) {
    throw new Error(`not a valid eui: ${result}`)
  }
  return result
}

export class EUI {
  public readonly eui: string
  constructor(eui: string | Uint8Array) {
    this.eui = normaliseEUI(eui)
  }

  public toString(): string {
    return this.eui
  }

  public valueOf(): string {
    return this.eui
  }

  public equals(otherEui: string | Uint8Array | EUI): boolean {
    if (typeof otherEui === 'string' || isUint8Array(otherEui)) {
      try {
        return this.eui === normaliseEUI(otherEui)
      } catch {
        return false
      }
    } else {
      return this.eui === otherEui.eui
    }
  }
}

export enum KeyUsage {
  digitalSignature = 0,
  nonRepudiation = 1,
  keyEncipherment = 2,
  dataEncipherment = 3,
  keyAgreement = 4,
  keyCertSign = 5,
  cRLSign = 6,
  encipherOnly = 7,
  decipherOnly = 8,
}

export interface CertificateMetadata {
  eui: EUI
  serial: number | bigint
  role?: number
  keyUsage: KeyUsage[]
}

export function parseOrganisationSubject(
  subjectRDNs: SEQUENCE<ASN1Element>,
): Pick<CertificateMetadata, 'eui' | 'role'> {
  let role: number | undefined = undefined
  let eui: string | undefined = undefined

  for (const rdn of subjectRDNs) {
    const attribs = rdn.set
    for (const att of attribs) {
      const type = att.sequence[0].objectIdentifier
      /* organizationUnitName */
      if (type.dotDelimitedNotation === '2.5.4.11') {
        const hexRole = att.sequence[1].utf8String /* should be a choice */
        if (hexRole.match(/^[0-9a-fA-F]{2}$/) !== null) {
          role = parseInt(hexRole, 16)
        }
      }
      /* uniqueIdentifier */
      if (type.dotDelimitedNotation === '2.5.4.45') {
        const id = att.sequence[1].bitString
        if (id.length === 64) {
          eui = Buffer.from(packBits(id)).toString('hex')
        }
      }
    }
  }
  if (role === undefined || eui === undefined) {
    throw new Error('invalid subject')
  }
  return {
    role,
    eui: new EUI(eui),
  }
}

export function extractExtension(
  tbsCertificate: SEQUENCE<ASN1Element>,
  oid: string,
): Uint8Array | null {
  /* find and then iterate through extensions */
  for (const el of tbsCertificate) {
    if (
      el.tagNumber === 3 &&
      el.tagClass === ASN1TagClass.context &&
      el.construction === ASN1Construction.constructed
    ) {
      const extensions = el.sequence[0].sequence
      for (const ext of extensions) {
        const extension = ext.sequence
        /* filter non-keyUsage */
        if (extension[0].objectIdentifier.dotDelimitedNotation === oid) {
          return extension[extension.length - 1].octetString
        }
      }
    }
  }
  return null
}

/**
 * Search for the keyUsage extension and extract its values. More info:
 * https://datatracker.ietf.org/doc/html/rfc2459#section-4.1
 *
 * @param tbsCertificate
 * @returns
 */
export function parseKeyUsageFromExtensions(
  tbsCertificate: SEQUENCE<ASN1Element>,
): KeyUsage[] {
  const keyUsage: KeyUsage[] = []
  const e = extractExtension(tbsCertificate, '2.5.29.15')
  if (e === null) {
    throw new Error('keyUsage extension not found')
  }
  const usage = new BERElement()
  usage.fromBytes(e)
  const usageString = usage.bitString
  for (let j = 0; j < usageString.length; j++) {
    if (usageString[j]) {
      keyUsage.push(j)
    }
  }
  return keyUsage
}

/**
 * Given an algorithm identifier (as defined by RFC2459), throw an exception if
 * its not ecdsa with sha256.
 *
 * @param algId
 */
export function assertKeyType(algId: SEQUENCE<ASN1Element>): void {
  if (
    algId[0].objectIdentifier.dotDelimitedNotation !== '1.2.840.10045.4.3.2'
  ) {
    throw new Error('expected ECDSA with SHA256')
  }
}

/**
 * parse metadata from a organisation certificate, throws exception if not
 * correct format.
 * @param cert
 * @returns
 */
export function buildOrgCertificateMetadata(
  cert: X509Certificate,
): CertificateMetadata {
  const root = new BERElement()
  root.fromBytes(cert.raw)
  /* below assumes standard certificate structure, see RFC2459 section 4 */
  const tbsCertificate = root.sequence[0].sequence
  const serial = tbsCertificate[1].integer
  assertKeyType(tbsCertificate[2].sequence)
  const subjectRDNs = tbsCertificate[5].sequence
  const subject = parseOrganisationSubject(subjectRDNs)
  const keyUsage = parseKeyUsageFromExtensions(tbsCertificate.slice(7))

  return {
    ...subject,
    serial,
    keyUsage,
  }
}

export function parseSubjectAltNameFromExtensions(
  tbsCertificate: SEQUENCE<ASN1Element>,
): EUI {
  const e = extractExtension(tbsCertificate, '2.5.29.17')
  if (e === null) {
    throw new Error('subjectAltName extension not found')
  }
  const altName = new BERElement()
  altName.fromBytes(e)
  const subjectAltNames = altName.sequence
  for (const generalName of subjectAltNames) {
    /* search for an otherName which is a id-on-hardwareModuleName */
    if (
      generalName.tagNumber === 0 &&
      generalName.tagClass === ASN1TagClass.context &&
      generalName.construction === ASN1Construction.constructed &&
      generalName.sequence[0].objectIdentifier.dotDelimitedNotation ===
        '1.3.6.1.5.5.7.8.4'
    ) {
      const hardwareModuleName = generalName.sequence[1].sequence[0].sequence
      // below would be a manufacturer unique id
      // hardwareModuleName[0].objectIdentifier.dotDelimitedNotation
      return new EUI(hardwareModuleName[1].octetString)
    }
  }
  throw new Error('hwSerialNum not found')
}

/**
 * parse metadata from a device certificate, throws exception if not correct
 * format.
 * @param cert
 * @returns
 */
export function buildDeviceCertificateMetadata(
  cert: X509Certificate,
): CertificateMetadata {
  const root = new BERElement()
  root.fromBytes(cert.raw)
  /* below assumes standard certificate structure, see RFC2459 section 4 */
  const tbsCertificate = root.sequence[0].sequence
  const serial = tbsCertificate[1].integer
  assertKeyType(tbsCertificate[2].sequence)
  const eui = parseSubjectAltNameFromExtensions(tbsCertificate)
  const keyUsage = parseKeyUsageFromExtensions(tbsCertificate)

  return {
    eui,
    serial,
    keyUsage,
  }
}
