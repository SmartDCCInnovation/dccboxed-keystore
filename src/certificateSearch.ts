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

import { XMLParser, XMLBuilder } from 'fast-xml-parser'
import got from 'got'
import { parse as contentType } from 'content-type'
import { X509Certificate } from 'crypto'
import {
  buildDeviceCertificateMetadata,
  buildOrgCertificateMetadata,
  CertificateMetadata,
} from './certificateMetadata'

export const enum CertificateStatus {
  Pending = 'P',
  'In use' = 'I',
  'Not In use' = 'N',
  Expired = 'E',
  Revoked = 'R',
}

export const enum CertificateUsage {
  'Digital Signing' = 'DS',
  'Key Agreement' = 'KA',
}

export const enum CertificateRole {
  Root = '0',
  Recovery = '1',
  Supplier = '2',
  'Network Operator' = '3',
  'Access Control Broker' = '4',
  'Transitional CoS' = '5',
  'WAN Provider' = '6',
  'Issuing Authority' = '7',
  'Load Controller' = '8',
  Other = '127',
  XmlSign = '135',
  DspXmlSign = '137',
}

/**
 * Type that is serialised into xml to retrieve a certificate.
 */
export interface CertificateDataRequest {
  CertificateSerial: string
}

/**
 * General tree structure of strings to hold parsed DUIS.
 */
export interface XMLData {
  [key: string]: string | string[] | XMLData | XMLData[]
}

export function prepareRequest(name: string, body: XMLData): string {
  const builder = new XMLBuilder({ ignoreAttributes: false })
  return builder.build({
    '?xml': {
      '@_version': '1.0',
      '@_encoding': 'utf-8',
      [name]: body,
    },
  })
}

export type QueryResult = {
  meta: CertificateMetadata
  x509: X509Certificate
}

/**
 * Parses a URL-like string and returns a properly formatted URL string
 *
 * @param url_like - String that may be a partial or complete URL
 * @returns Properly formatted URL string with protocol and port if needed
 *
 * If the input string:
 * - Does not contain a colon: Prepends 'http://' and appends port 8083
 * - Does not contain protocol: Prepends 'http://'
 * - Is already a complete URL: Returns as-is after URL validation
 */
export function parseUrl(url_like: string): string {
  if (!url_like.includes(':')) {
    return `http://${url_like}:8083/`
  }
  const fullUrl = url_like.includes('://') ? url_like : `http://${url_like}`
  return new URL(fullUrl).toString()
}

/**
 * queries the SMKI certificatesearch service. when entering the
 * CertificateSubjectName or CertificateSubjectAltName parameters, ensure they
 * follow the <code>a1-a2-a3-a4-a5-a6-a7-a8</code> format.
 *
 * @param sr
 * @param boxedAddress
 * @returns
 */
export async function search(
  sr: (
    | {
        q: { CertificateSubjectName: string }
        CertificateRole: CertificateRole
      }
    | { q: { CertificateSubjectAltName: string } }
  ) & {
    CertificateUsage: CertificateUsage
    CertificateStatus: CertificateStatus
  },
  boxedAddress: string,
): Promise<QueryResult[]> {
  const result = await got(
    `${parseUrl(boxedAddress)}services/certificatesearch`,
    {
      method: 'post',
      headers: { 'content-type': 'application/xml' },
      searchParams: { apikey: 'u3bg9gt38htd0j2' },
      body: prepareRequest('CertificateSearchRequest', sr.q),
      timeout: {
        lookup: 100,
        connect: 500,
        request: 4000,
      },
      throwHttpErrors: false,
    },
  )
  const ct = result.headers['content-type']
  if (result.statusCode === 402) {
    return []
  } else if (result.statusCode === 401) {
    throw new Error('invalid search parameters')
  } else if (
    result.statusCode !== 200 ||
    !ct ||
    contentType(ct).type !== 'application/xml'
  ) {
    throw new Error(`unknown error ${result.statusCode}: ${ct}`)
  }

  const parser = new XMLParser({
    ignoreAttributes: false,
    parseAttributeValue: false,
    parseTagValue: false,
  })
  const searchResult = parser.parse(result.body)
  const resultListMaybe = searchResult?.CertificateSearchResponse?.Result
  if (!resultListMaybe) {
    return []
  }
  const serials: string[] = []

  let resultList
  if (!Array.isArray(resultListMaybe)) {
    resultList = [resultListMaybe]
  } else {
    resultList = resultListMaybe
  }

  for (const e of resultList) {
    if (
      e?.CertificateUsage === sr.CertificateUsage &&
      typeof e?.CertificateSerial === 'string' &&
      e?.CertificateStatus === sr.CertificateStatus
    ) {
      const srRole = sr as { CertificateRole?: CertificateRole }
      if (
        typeof srRole.CertificateRole !== 'string' ||
        srRole.CertificateRole === e?.CertificateRole
      ) {
        serials.push(e?.CertificateSerial)
      }
    }
  }

  const queryResults = await Promise.all(
    serials.map((serial) => query(serial, boxedAddress)),
  )
  return queryResults.filter((qr) => qr !== null) as QueryResult[]
}

export async function query(
  serial: string,
  boxedAddress: string,
): Promise<QueryResult | null> {
  const result = await got(
    `${parseUrl(boxedAddress)}services/retrievecertificate`,
    {
      method: 'post',
      headers: { 'content-type': 'application/xml' },
      searchParams: { apikey: 'u3bg9gt38htd0j2' },
      body: prepareRequest('CertificateDataRequest', {
        CertificateSerial: serial,
      }),
      timeout: {
        lookup: 100,
        connect: 500,
        request: 4000,
      },
      throwHttpErrors: false,
    },
  )
  const ct = result.headers['content-type']
  if (result.statusCode === 402) {
    return null
  } else if (result.statusCode === 401) {
    throw new Error('invalid search parameters')
  } else if (
    result.statusCode !== 200 ||
    !ct ||
    contentType(ct).type !== 'application/xml'
  ) {
    throw new Error(`unknown error ${result.statusCode}: ${ct}`)
  }

  const parser = new XMLParser({
    ignoreAttributes: false,
    parseAttributeValue: false,
    parseTagValue: false,
  })
  const certificateResult = parser.parse(result.body)
  const certificateResponse =
    certificateResult?.CertificateDataResponse?.CertificateResponse

  if (typeof certificateResponse?.CertificateBody === 'string') {
    const x509 = new X509Certificate(
      `-----BEGIN CERTIFICATE-----\n${certificateResponse?.CertificateBody}\n-----END CERTIFICATE-----`,
    )
    if (typeof certificateResponse?.CertificateSubjectName === 'string') {
      /* org cert */
      return {
        meta: buildOrgCertificateMetadata(x509),
        x509,
      }
    } else if (
      typeof certificateResponse?.CertificateSubjectAltName === 'string'
    ) {
      /* device cert */
      return {
        meta: buildDeviceCertificateMetadata(x509),
        x509,
      }
    }
  }
  return null
}
