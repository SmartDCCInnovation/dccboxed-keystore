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

const gotMock = jest.fn()
jest.mock('got', () => ({ default: gotMock, __esModule: true }))
import { X509Certificate } from 'crypto'
import type { Response, OptionsOfTextResponseBody } from 'got'
import {
  buildDeviceCertificateMetadata,
  buildOrgCertificateMetadata,
} from '../src/certificateMetadata'
import * as cs from '../src/certificateSearch'

describe('prepareRequest', () => {
  test('defined', () => {
    expect(cs.prepareRequest).toBeDefined()
  })

  test('basic', () => {
    expect(cs.prepareRequest('hello', { a: 'b' })).toBe(
      `<?xml version="1.0" encoding="utf-8"?><hello><a>b</a></hello>`,
    )
  })

  test('nested', () => {
    expect(cs.prepareRequest('hello', { a: 'b', c: { e: 'd' } })).toBe(
      `<?xml version="1.0" encoding="utf-8"?><hello><a>b</a><c><e>d</e></c></hello>`,
    )
  })

  test('array', () => {
    expect(cs.prepareRequest('hello', { a: ['1', '2', '3'] })).toBe(
      `<?xml version="1.0" encoding="utf-8"?><hello><a>1</a><a>2</a><a>3</a></hello>`,
    )
  })

  test('nominal', () => {
    const q = {
      op: 'search',
      q: {
        CertificateSubjectName: '90-B3-D5-1F-30-01-00-00',
      },
      CertificateRole: cs.CertificateRole.Supplier,
      CertificateStatus: cs.CertificateStatus['In use'],
      CertificateUsage: cs.CertificateUsage['Digital Signing'],
    }
    expect(cs.prepareRequest('CertificateSearchRequest', q.q)).toBe(
      '<?xml version="1.0" encoding="utf-8"?>' +
        '<CertificateSearchRequest>' +
        '<CertificateSubjectName>90-B3-D5-1F-30-01-00-00</CertificateSubjectName>' +
        '</CertificateSearchRequest>',
    )
  })
})

const deviceCert_88738457002f966c_ds = `
  MIIBnDCCAUGgAwIBAgIQE+bjQJyID9vnGkKazzdXRjAKBggqhkjOPQQDAjAhMQsw
  CQYDVQQLDAIwNDESMBAGA1UELQMJAJCz1R8wAAACMCAXDTIyMDYyMzEzNDE1M1oY
  Dzk5OTkxMjMxMjM1OTU5WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9poP
  zZqPf3B+zGH6+iom4+33eYBg3kAOqJu1iZVcQv51kkWxELt+kODSTwzIunNji833
  8r2rLo0hX7NtFwBbMKN6MHgwDgYDVR0PAQH/BAQDAgMIMDIGA1UdEQEB/wQoMCag
  JAYIKwYBBQUHCASgGDAWBgoqhjoAilwBAQIBBAiIc4RXAC+WbDAdBgNVHSABAf8E
  EzARMA8GDSqGOgABhI+5DwECAQQwEwYDVR0jBAwwCoAIQmk1NdPd4QEwCgYIKoZI
  zj0EAwIDSQAwRgIhAMU7lkl7VPekQ6aWz3wBdlr8hnEhuyryXucUXNGPGazYAiEA
  paMZlFoNDO59rJgZ9ZAjskjenTF0G7CMu+jjaw87nBw=`

const deviceCert_88738457002f966c_ka = `
  MIIBmzCCAUGgAwIBAgIQTfVuktUo+DVE66BUcGjPjDAKBggqhkjOPQQDAjAhMQsw
  CQYDVQQLDAIwNDESMBAGA1UELQMJAJCz1R8wAAACMCAXDTIyMDYyMzEzNDEzNloY
  Dzk5OTkxMjMxMjM1OTU5WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6+EM
  hCIy3HztgN9HAd81OcFtCkEShRS/YbMFxln1tyGzEAGMZR8RQeYsmr+jiZAgmmXA
  X/qYa3hBhfaOYa9Uk6N6MHgwDgYDVR0PAQH/BAQDAgeAMDIGA1UdEQEB/wQoMCag
  JAYIKwYBBQUHCASgGDAWBgoqhjoAilwBAQIBBAiIc4RXAC+WbDAdBgNVHSABAf8E
  EzARMA8GDSqGOgABhI+5DwECAQQwEwYDVR0jBAwwCoAIQmk1NdPd4QEwCgYIKoZI
  zj0EAwIDSAAwRQIgZqf2nVEAZbMN4QMxl8wegvijwrfDgzF/EkQybixcdngCIQDS
  TAXdhesiClG5XBv2t3WgVAlHc8bew0LB/bEfUxNMsw==`

const deviceCert_00db1234567890a4_ka = `
  MIIBoDCCAUagAwIBAgIQSiNt7Xc0UzIiYPfefETBZjAKBggqhkjOPQQDAjAPMQ0w
  CwYDVQQDEwRFMzU3MCAXDTE2MDQwNjAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjAA
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4WwfjNZwHoDL4DG1QJVIbyWwWn6B
  Kt8SJ2ujFyakONVNyEfnK2E3UgibkuL4hT0+Q84PoO9SDlnsMbcsoUkI06OBkDCB
  jTAOBgNVHQ8BAf8EBAMCAwgwEQYDVR0OBAoECEcMHpw5Eh7IMDUGA1UdEQEB/wQr
  MCmgJwYIKwYBBQUHCASgGzAZBg0qhjoAAYSPuQ8BAgIBBAgA2xI0VniQpDAcBgNV
  HSABAf8EEjAQMA4GDCqGOgAB7e5AAQIBBDATBgNVHSMEDDAKgAhH1ArzQSkEoDAK
  BggqhkjOPQQDAgNIADBFAiBtih3M74gET/t+qE6aRYvvCQfYGqUK26lzVBFwhaxF
  ywIhAMWtZ3u/bQs4oFbKuXDQreKUFw2W7kRVbOa8NbYFXR92`

const orgCert_90b3d51f30000001_ds = `
  MIIBkjCCATigAwIBAgIQRpr+wufAyq7IpAB2m3AryDAKBggqhkjOPQQDAjAaMQsw
  CQYDVQQLEwIwNzELMAkGA1UEAxMCWjEwHhcNMTUxMDMwMDAwMDAwWhcNMjUxMDI5
  MjM1OTU5WjAhMQswCQYDVQQLDAIwMTESMBAGA1UELQMJAJCz1R8wAAABMFkwEwYH
  KoZIzj0CAQYIKoZIzj0DAQcDQgAEX9CL9uFDiw2je8JkE1vpZfLVIrsqJmM1OgI5
  7QIKhacanY2F2HzDikhNorxT729KFo0M6IYcQKVDxM0VsnZm+aNZMFcwDgYDVR0P
  AQH/BAQDAgeAMBEGA1UdDgQKBAhB+supVvg9hzAdBgNVHSABAf8EEzARMA8GDSqG
  OgABhI+5DwECAQQwEwYDVR0jBAwwCoAIT1aI1+yTO+IwCgYIKoZIzj0EAwIDSAAw
  RQIgFUzuFGjfksF5+XNiopwuwpQJobd1GmBl9SKG+6d7y9oCIQCLDPSUJlfX4clm
  ZOLPpTSroslJqBT+gh8fKXK0Rhbbtw==`

const orgCert_90b3d51f30010000_ds = `
  MIIBrDCCAVKgAwIBAgIQT7xSUgGh11hsG8HEc03rnzAKBggqhkjOPQQDAjAaMQsw
  CQYDVQQLEwIwNzELMAkGA1UEAxMCWjEwHhcNMTUxMDMwMDAwMDAwWhcNMjUxMDI5
  MjM1OTU5WjA7MRgwFgYDVQQDDA9HSVRURVNUU1VQUExJRVIxCzAJBgNVBAsMAjAy
  MRIwEAYDVQQtAwkAkLPVHzABAAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQw
  wqtaDRMXJv+9qA55KUzDdTRDKj5CRAW5ejq6D/x53OcpslF1Y8t9lYJ+TFC0jLo9
  h9WJPFG5bYfDReNxf4weo1kwVzAOBgNVHQ8BAf8EBAMCB4AwEQYDVR0OBAoECESJ
  l5LRlvS4MB0GA1UdIAEB/wQTMBEwDwYNKoY6AAGEj7kPAQIBBDATBgNVHSMEDDAK
  gAhPVojX7JM74jAKBggqhkjOPQQDAgNIADBFAiEA39CQ51c+r1+oLhqn242f7VEY
  ObV1LVXRAJHyUP3xiiICIF637Dax9BM+UVV9M7WcSe9rvRDpqksdzZKOZbPprdHF`

const orgCert_90b3d51f30010000_ds_b = `
  MIIBrDCCAVKgAwIBAgIQSge8AdklO1H68B9+x9pbLzAKBggqhkjOPQQDAjAaMQsw
  CQYDVQQLEwIwNzELMAkGA1UEAxMCWjEwHhcNMTYwMTEwMDAwMDAwWhcNMjYwMTA5
  MjM1OTU5WjA7MRgwFgYDVQQDDA9HSVRURVNUU1VQUExJRVIxCzAJBgNVBAsMAjAy
  MRIwEAYDVQQtAwkAkLPVHzABAAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT6
  b7/6HJpOQvSjzWWfO+uQoxtWWu17p5F3SLpoT+TGACE8vp0lgh+ngNlHuXXJMPN3
  q6EhApAEQmR6maNlIIiwo1kwVzAOBgNVHQ8BAf8EBAMCB4AwEQYDVR0OBAoECEME
  a0+3xPEbMB0GA1UdIAEB/wQTMBEwDwYNKoY6AAGEj7kPAQIBBDATBgNVHSMEDDAK
  gAhPVojX7JM74jAKBggqhkjOPQQDAgNIADBFAiEAvXvJRsABv/3nyEO/DVW5np3W
  TPuHhsJQfc4fIpxRBmUCIH+0LzbjIIn8tTVK5fnRmV/wHfG0cjU7E6excCnrDULy`

const orgCert_90b3d51f30010000_ds_xmlSign = `
  MIIBfzCCASWgAwIBAgIQFL5K0uodDk7H9xVr0kYkpzAKBggqhkjOPQQDAjAaMQsw
  CQYDVQQLDAIwNzELMAkGA1UEAwwCWjEwIBcNMTgwMTAxMDAwMDAwWhgPMjExODAx
  MDEwMDAwMDBaMCExCzAJBgNVBAsMAjg3MRIwEAYDVQQtAwkAkLPVHzABAAAwWTAT
  BgcqhkjOPQIBBggqhkjOPQMBBwNCAASfiKvSIFxEFeHhGzLWEiBlfi045xQ/m4hL
  +s1+SKlje0Vb//LRzGVaUobobAJaVN5cRd43ZiioDY+0cTTwvUcuo0QwQjAdBgNV
  HSABAf8EEzARMA8GDSqGOgABhI+5DwECAQQwEQYDVR0OBAoECEusYLdMsaDbMA4G
  A1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA4LXpqbs5lRubjOM4FtEy
  7rowBKUyf62/hreDAIn3fEoCIDVnSEzk+wBn2NJ392d+S9sd03Wca5m4YVgyb2GT
  eX8c`

describe('query', () => {
  beforeEach(() => {
    gotMock.mockReset()
  })

  test('certificate-not-found', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 402,
          headers: {},
        } as Response<string>)
      }),
    )
    await expect(cs.query('1234', '1.2.3.4')).resolves.toBeNull()
    expect(gotMock).toHaveBeenCalledTimes(1)
    expect(gotMock).toHaveBeenCalledWith(
      'http://1.2.3.4:8083/services/retrievecertificate',
      expect.objectContaining<OptionsOfTextResponseBody>({
        body: cs.prepareRequest('CertificateDataRequest', {
          CertificateSerial: '1234',
        }),
        method: 'post',
        headers: expect.objectContaining({ 'content-type': 'application/xml' }),
      }),
    )
  })

  test('certificate-not-found-with-header', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 402,
          headers: {},
        } as Response<string>)
      }),
    )
    await expect(
      cs.query('1234', '1.2.3.4', { 'X-Authentication': 'Secret' }),
    ).resolves.toBeNull()
    expect(gotMock).toHaveBeenCalledTimes(1)
    expect(gotMock).toHaveBeenCalledWith(
      'http://1.2.3.4:8083/services/retrievecertificate',
      expect.objectContaining<OptionsOfTextResponseBody>({
        body: cs.prepareRequest('CertificateDataRequest', {
          CertificateSerial: '1234',
        }),
        method: 'post',
        headers: expect.objectContaining({
          'content-type': 'application/xml',
          'X-Authentication': 'Secret',
        }),
      }),
    )
  })

  test('invalid-query', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 401,
          headers: {},
        } as Response<string>)
      }),
    )
    await expect(cs.query('1234', '1.2.3.4')).rejects.toThrow(
      'invalid search parameters',
    )
    expect(gotMock).toHaveBeenCalledTimes(1)
  })

  test('unknown-response', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 404,
          headers: {},
        } as Response<string>)
      }),
    )
    await expect(cs.query('1234', '1.2.3.4')).rejects.toThrow('unknown error')
    expect(gotMock).toHaveBeenCalledTimes(1)
  })

  test('unknown-response-2', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 200,
          headers: { 'content-type': 'text/plain' },
          body: '<html></html>',
        } as Response<string>)
      }),
    )
    await expect(cs.query('1234', '1.2.3.4')).rejects.toThrow('unknown error')
    expect(gotMock).toHaveBeenCalledTimes(1)
  })

  test('nominal-organisation', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 200,
          headers: { 'content-type': 'application/xml; charset=utf-8' },
          body: `
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <CertificateDataResponse>
              <ResponseCode>200</ResponseCode>
              <ResponseMessage>Success</ResponseMessage>
              <AuditReference>1234567890-abc123456</AuditReference>
              <CertificateResponse>
                <CertificateSubjectName>90-B3-D5-1F-30-00-00-01</CertificateSubjectName>
                <CertificateSerial>469AFEC2E7C0CAAEC8A400769B702BC8</CertificateSerial>
                <CertificateStatus>I</CertificateStatus>
                <CertificateBody>${orgCert_90b3d51f30000001_ds}</CertificateBody>
                <CertificateRole>1</CertificateRole>
                <CertificateUsage>DS</CertificateUsage>
                <ManufacturingFlag>false</ManufacturingFlag>
              </CertificateResponse>
            </CertificateDataResponse>`,
        } as Response<string>)
      }),
    )
    const x509 = new X509Certificate(
      Buffer.from(orgCert_90b3d51f30000001_ds, 'base64'),
    )
    await expect(
      cs.query('469AFEC2E7C0CAAEC8A400769B702BC8', '1.2.3.4'),
    ).resolves.toMatchObject({
      meta: buildOrgCertificateMetadata(x509),
      x509,
    })
    expect(gotMock).toHaveBeenCalledTimes(1)
    expect(gotMock).toHaveBeenNthCalledWith(
      1,
      'http://1.2.3.4:8083/services/retrievecertificate',
      expect.objectContaining({
        body: cs.prepareRequest('CertificateDataRequest', {
          CertificateSerial: '469AFEC2E7C0CAAEC8A400769B702BC8',
        }),
        method: 'post',
        headers: { 'content-type': 'application/xml' },
      }),
    )
  })

  test('nominal-device', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 200,
          headers: { 'content-type': 'application/xml; charset=utf-8' },
          body: `
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <CertificateDataResponse>
              <ResponseCode>200</ResponseCode>
              <ResponseMessage>Success</ResponseMessage>
              <AuditReference>1234567890-abc123456</AuditReference>
              <CertificateResponse>
                <CertificateSubjectAltName>88-73-84-57-00-2F-96-6C</CertificateSubjectAltName>
                <CertificateSerial>4DF56E92D528F83544EBA0547068CF8C</CertificateSerial>
                <CertificateStatus>I</CertificateStatus>
                <CertificateBody>${deviceCert_88738457002f966c_ds}</CertificateBody>
                <CertificateUsage>DS</CertificateUsage>
                <ManufacturingFlag>false</ManufacturingFlag>
              </CertificateResponse>
            </CertificateDataResponse>`,
        } as Response<string>)
      }),
    )
    const x509 = new X509Certificate(
      Buffer.from(deviceCert_88738457002f966c_ds, 'base64'),
    )
    await expect(
      cs.query('4DF56E92D528F83544EBA0547068CF8C', '1.2.3.4'),
    ).resolves.toMatchObject({
      meta: buildDeviceCertificateMetadata(x509),
      x509,
    })
    expect(gotMock).toHaveBeenCalledTimes(1)
    expect(gotMock).toHaveBeenNthCalledWith(
      1,
      'http://1.2.3.4:8083/services/retrievecertificate',
      expect.objectContaining({
        body: cs.prepareRequest('CertificateDataRequest', {
          CertificateSerial: '4DF56E92D528F83544EBA0547068CF8C',
        }),
        method: 'post',
        headers: { 'content-type': 'application/xml' },
      }),
    )
  })

  test('result-missing-certificate', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 200,
          headers: { 'content-type': 'application/xml; charset=utf-8' },
          body: `
            <?xml version="1.0" encoding="utf-8"?>
            <CertificateDataResponse>
              <ResponseCode>200</ResponseCode>
              <ResponseMessage>Success</ResponseMessage>
              <AuditReference>1234567890-abc123456</AuditReference>
              <CertificateResponse>
              <CertificateSubjectName>90-B3-D5-1F-30-00-00-01</CertificateSubjectName>
              <CertificateSerial>54321</CertificateSerial>
              <CertificateStatus>I</CertificateStatus>
              <CertificateRole>2</CertificateRole>
              <CertificateUsage>KA</CertificateUsage>
              <ManufacturingFlag>false</ManufacturingFlag>
              </CertificateResponse>
            </CertificateDataResponse>`,
        } as Response<string>)
      }),
    )
    await expect(cs.query('54321', '1.2.3.4')).resolves.toBeNull()
    expect(gotMock).toHaveBeenCalledTimes(1)
  })
})

describe('search', () => {
  beforeEach(() => {
    gotMock.mockReset()
  })

  test('certificate-not-found', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 402,
          headers: {},
        } as Response<string>)
      }),
    )
    const q = {
      q: { CertificateSubjectAltName: '11-22-33-44-55-66-77-88' },
      CertificateStatus: cs.CertificateStatus['In use'],
      CertificateUsage: cs.CertificateUsage['Digital Signing'],
    }
    await expect(cs.search(q, '1.2.3.4')).resolves.toStrictEqual([])
    expect(gotMock).toHaveBeenCalledTimes(1)
    expect(gotMock).toHaveBeenCalledWith(
      'http://1.2.3.4:8083/services/certificatesearch',
      expect.objectContaining<OptionsOfTextResponseBody>({
        body: cs.prepareRequest('CertificateSearchRequest', q.q),
        method: 'post',
        headers: expect.objectContaining({ 'content-type': 'application/xml' }),
      }),
    )
  })

  test('certificate-not-found-with-headers', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 402,
          headers: {},
        } as Response<string>)
      }),
    )
    const q = {
      q: { CertificateSubjectAltName: '11-22-33-44-55-66-77-88' },
      CertificateStatus: cs.CertificateStatus['In use'],
      CertificateUsage: cs.CertificateUsage['Digital Signing'],
    }
    await expect(
      cs.search(q, '1.2.3.4', { 'X-Authentication': 'Secret' }),
    ).resolves.toStrictEqual([])
    expect(gotMock).toHaveBeenCalledTimes(1)
    expect(gotMock).toHaveBeenCalledWith(
      'http://1.2.3.4:8083/services/certificatesearch',
      expect.objectContaining<OptionsOfTextResponseBody>({
        body: cs.prepareRequest('CertificateSearchRequest', q.q),
        method: 'post',
        headers: expect.objectContaining({
          'content-type': 'application/xml',
          'X-Authentication': 'Secret',
        }),
      }),
    )
  })

  test('invalid-query', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 401,
          headers: {},
        } as Response<string>)
      }),
    )
    const q = {
      q: { CertificateSubjectAltName: '11-22-33-44-55-66-77-88' },
      CertificateStatus: cs.CertificateStatus['In use'],
      CertificateUsage: cs.CertificateUsage['Digital Signing'],
    }
    await expect(cs.search(q, '1.2.3.4')).rejects.toThrow(
      'invalid search parameters',
    )
    expect(gotMock).toHaveBeenCalledTimes(1)
  })

  test('unknown-response', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 404,
          headers: {},
        } as Response<string>)
      }),
    )
    const q = {
      q: { CertificateSubjectAltName: '11-22-33-44-55-66-77-88' },
      CertificateStatus: cs.CertificateStatus['In use'],
      CertificateUsage: cs.CertificateUsage['Digital Signing'],
    }
    await expect(cs.search(q, '1.2.3.4')).rejects.toThrow('unknown error')
    expect(gotMock).toHaveBeenCalledTimes(1)
  })

  test('unknown-response-2', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 200,
          headers: { 'content-type': 'text/plain' },
          body: '<html></html>',
        } as Response<string>)
      }),
    )
    const q = {
      q: { CertificateSubjectAltName: '11-22-33-44-55-66-77-88' },
      CertificateStatus: cs.CertificateStatus['In use'],
      CertificateUsage: cs.CertificateUsage['Digital Signing'],
    }
    await expect(cs.search(q, '1.2.3.4')).rejects.toThrow('unknown error')
    expect(gotMock).toHaveBeenCalledTimes(1)
  })

  test('no-results-without-402', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 200,
          headers: { 'content-type': 'application/xml; charset=utf-8' },
          body: `
          <?xml version="1.0" encoding="utf-8"?>
          <CertificateSearchResponse>
            <ResponseCode>200</ResponseCode>
            <ResponseMessage>Success</ResponseMessage>
            <AuditReference>1234567890-abc123456</AuditReference>
          </CertificateSearchResponse>`,
        } as Response<string>)
      }),
    )
    const q = {
      q: {
        CertificateSubjectAltName: '00-DB-12-34-56-78-90-A4',
      },
      CertificateUsage: cs.CertificateUsage['Key Agreement'],
      CertificateStatus: cs.CertificateStatus['In use'],
    }
    await expect(cs.search(q, '1.2.3.4')).resolves.toStrictEqual([])
    expect(gotMock).toHaveBeenCalledTimes(1)
  })

  test('miss-keyusage', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 200,
          headers: { 'content-type': 'application/xml; charset=utf-8' },
          body: `
          <?xml version="1.0" encoding="utf-8"?>
          <CertificateSearchResponse>
            <ResponseCode>200</ResponseCode>
            <ResponseMessage>Success</ResponseMessage>
            <AuditReference>1234567890-abc123456</AuditReference>
            <Result>
              <CertificateSerial>12345</CertificateSerial>
              <CertificateSubjectAltName>00-DB-12-34-56-78-90-A4</CertificateSubjectAltName>
              <CertificateStatus>I</CertificateStatus>
              <CertificateUsage>DS</CertificateUsage>
              <ManufacturingFlag>false</ManufacturingFlag>
            </Result>
          </CertificateSearchResponse>`,
        } as Response<string>)
      }),
    )
    const q = {
      q: {
        CertificateSubjectAltName: '00-DB-12-34-56-78-90-A4',
      },
      CertificateStatus: cs.CertificateStatus['In use'],
      CertificateUsage: cs.CertificateUsage['Key Agreement'],
    }
    await expect(cs.search(q, '1.2.3.4')).resolves.toStrictEqual([])
    expect(gotMock).toHaveBeenCalledTimes(1)
    expect(gotMock).toHaveBeenLastCalledWith(
      expect.any(String),
      expect.objectContaining({
        body: cs.prepareRequest('CertificateSearchRequest', q.q),
      }),
    )
  })

  test('miss-status', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 200,
          headers: { 'content-type': 'application/xml; charset=utf-8' },
          body: `
          <?xml version="1.0" encoding="utf-8"?>
          <CertificateSearchResponse>
            <ResponseCode>200</ResponseCode>
            <ResponseMessage>Success</ResponseMessage>
            <AuditReference>1234567890-abc123456</AuditReference>
            <Result>
              <CertificateSerial>12345</CertificateSerial>
              <CertificateSubjectAltName>00-DB-12-34-56-78-90-A4</CertificateSubjectAltName>
              <CertificateStatus>I</CertificateStatus>
              <CertificateUsage>KA</CertificateUsage>
              <ManufacturingFlag>false</ManufacturingFlag>
            </Result>
          </CertificateSearchResponse>`,
        } as Response<string>)
      }),
    )
    const q = {
      q: {
        CertificateSubjectAltName: '00-DB-12-34-56-78-90-A4',
      },
      CertificateStatus: cs.CertificateStatus.Expired,
      CertificateUsage: cs.CertificateUsage['Key Agreement'],
    }
    await expect(cs.search(q, '1.2.3.4')).resolves.toStrictEqual([])
    expect(gotMock).toHaveBeenCalledTimes(1)
    expect(gotMock).toHaveBeenLastCalledWith(
      expect.any(String),
      expect.objectContaining({
        body: cs.prepareRequest('CertificateSearchRequest', q.q),
      }),
    )
  })

  test('miss-role', async () => {
    gotMock.mockReturnValue(
      new Promise<Response<string>>((resolve) => {
        resolve({
          statusCode: 200,
          headers: { 'content-type': 'application/xml; charset=utf-8' },
          body: `
          <?xml version="1.0" encoding="utf-8"?>
          <CertificateSearchResponse>
            <ResponseCode>200</ResponseCode>
            <ResponseMessage>Success</ResponseMessage>
            <AuditReference>1234567890-abc123456</AuditReference>
            <Result>
              <CertificateSerial>37CDF206B07DDEF852FBC62950F22ED0</CertificateSerial>
              <CertificateSubjectName>90-B3-D5-1F-30-00-00-02</CertificateSubjectName>
              <CertificateStatus>I</CertificateStatus>
              <CertificateRole>4</CertificateRole>
              <CertificateUsage>KA</CertificateUsage>
              <ManufacturingFlag>false</ManufacturingFlag>
            </Result>
            <Result>
              <CertificateSerial>587FE59553E2675B0C0E2A5C402A9F61</CertificateSerial>
              <CertificateSubjectName>90-B3-D5-1F-30-00-00-02</CertificateSubjectName>
              <CertificateStatus>I</CertificateStatus>
              <CertificateRole>4</CertificateRole>
              <CertificateUsage>DS</CertificateUsage>
              <ManufacturingFlag>false</ManufacturingFlag>
            </Result>
          </CertificateSearchResponse>`,
        } as Response<string>)
      }),
    )
    const q = {
      q: {
        CertificateSubjectName: '90-B3-D5-1F-30-00-00-02',
      },
      CertificateStatus: cs.CertificateStatus['In use'],
      CertificateUsage: cs.CertificateUsage['Key Agreement'],
      CertificateRole: cs.CertificateRole.XmlSign,
    }
    await expect(cs.search(q, '1.2.3.4')).resolves.toStrictEqual([])
    expect(gotMock).toHaveBeenCalledTimes(1)
    expect(gotMock).toHaveBeenLastCalledWith(
      expect.any(String),
      expect.objectContaining({
        body: cs.prepareRequest('CertificateSearchRequest', q.q),
      }),
    )
  })

  test('nominal-device-keyagreement', async () => {
    gotMock.mockImplementation((x) => {
      if (x.endsWith('certificatesearch')) {
        return new Promise<Response<string>>((resolve) => {
          resolve({
            statusCode: 200,
            headers: { 'content-type': 'application/xml; charset=utf-8' },
            body: `
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <CertificateSearchResponse>
              <ResponseCode>200</ResponseCode>
              <ResponseMessage>Success</ResponseMessage>
              <AuditReference>1234567890-abc123456</AuditReference>
              <Result>
                <CertificateSerial>4DF56E92D528F83544EBA0547068CF8C</CertificateSerial>
                <CertificateSubjectAltName>88-73-84-57-00-2F-96-6C</CertificateSubjectAltName>
                <CertificateStatus>I</CertificateStatus>
                <CertificateUsage>DS</CertificateUsage>
                <ManufacturingFlag>false</ManufacturingFlag>
              </Result>
              <Result>
                <CertificateSerial>13E6E3409C880FDBE71A429ACF375746</CertificateSerial>
                <CertificateSubjectAltName>88-73-84-57-00-2F-96-6C</CertificateSubjectAltName>
                <CertificateStatus>I</CertificateStatus>
                <CertificateUsage>KA</CertificateUsage>
                <ManufacturingFlag>false</ManufacturingFlag>
              </Result>
            </CertificateSearchResponse>`,
          } as Response<string>)
        })
      } else {
        return new Promise<Response<string>>((resolve) => {
          resolve({
            statusCode: 200,
            headers: { 'content-type': 'application/xml; charset=utf-8' },
            body: `
            <?xml version="1.0" encoding="utf-8"?>
            <CertificateDataResponse>
              <ResponseCode>200</ResponseCode>
              <ResponseMessage>Success</ResponseMessage>
              <AuditReference>1234567890-abc123456</AuditReference>
              <CertificateResponse>
              <CertificateSubjectAltName>88-73-84-57-00-2F-96-6C</CertificateAltName>
              <CertificateSerial>13E6E3409C880FDBE71A429ACF375746</CertificateSerial>
              <CertificateStatus>I</CertificateStatus>
              <CertificateBody>
                ${deviceCert_88738457002f966c_ka}
              </CertificateBody>
              <CertificateUsage>KA</CertificateUsage>
              <ManufacturingFlag>false</ManufacturingFlag>
              </CertificateResponse>
            </CertificateDataResponse>`,
          } as Response<string>)
        })
      }
    })
    const q = {
      q: {
        CertificateSubjectAltName: '88-73-84-57-00-2F-96-6C',
      },
      CertificateStatus: cs.CertificateStatus['In use'],
      CertificateUsage: cs.CertificateUsage['Key Agreement'],
    }
    const x509 = new X509Certificate(
      Buffer.from(deviceCert_88738457002f966c_ka, 'base64'),
    )
    await expect(cs.search(q, '1.2.3.4')).resolves.toMatchObject([
      {
        meta: buildDeviceCertificateMetadata(x509),
        x509,
      },
    ])
    expect(gotMock).toHaveBeenCalledTimes(2)
    expect(gotMock).toHaveBeenNthCalledWith(
      1,
      'http://1.2.3.4:8083/services/certificatesearch',
      expect.objectContaining({
        body: cs.prepareRequest('CertificateSearchRequest', {
          CertificateSubjectAltName: '88-73-84-57-00-2F-96-6C',
        }),
        method: 'post',
        headers: { 'content-type': 'application/xml' },
      }),
    )
    expect(gotMock).toHaveBeenNthCalledWith(
      2,
      'http://1.2.3.4:8083/services/retrievecertificate',
      expect.objectContaining({
        body: cs.prepareRequest('CertificateDataRequest', {
          CertificateSerial: '13E6E3409C880FDBE71A429ACF375746',
        }),
        method: 'post',
        headers: { 'content-type': 'application/xml' },
      }),
    )
  })

  test('nominal-device-digitalsignature', async () => {
    gotMock.mockImplementation((x) => {
      if (x.endsWith('certificatesearch')) {
        return new Promise<Response<string>>((resolve) => {
          resolve({
            statusCode: 200,
            headers: { 'content-type': 'application/xml; charset=utf-8' },
            body: `
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <CertificateSearchResponse>
              <ResponseCode>200</ResponseCode>
              <ResponseMessage>Success</ResponseMessage>
              <AuditReference>1234567890-abc123456</AuditReference>
              <Result>
                <CertificateSerial>4DF56E92D528F83544EBA0547068CF8C</CertificateSerial>
                <CertificateSubjectAltName>88-73-84-57-00-2F-96-6C</CertificateSubjectAltName>
                <CertificateStatus>I</CertificateStatus>
                <CertificateUsage>DS</CertificateUsage>
                <ManufacturingFlag>false</ManufacturingFlag>
              </Result>
              <Result>
                <CertificateSerial>13E6E3409C880FDBE71A429ACF375746</CertificateSerial>
                <CertificateSubjectAltName>88-73-84-57-00-2F-96-6C</CertificateSubjectAltName>
                <CertificateStatus>I</CertificateStatus>
                <CertificateUsage>KA</CertificateUsage>
                <ManufacturingFlag>false</ManufacturingFlag>
              </Result>
            </CertificateSearchResponse>`,
          } as Response<string>)
        })
      } else {
        return new Promise<Response<string>>((resolve) => {
          resolve({
            statusCode: 200,
            headers: { 'content-type': 'application/xml; charset=utf-8' },
            body: `
            <?xml version="1.0" encoding="utf-8"?>
            <CertificateDataResponse>
              <ResponseCode>200</ResponseCode>
              <ResponseMessage>Success</ResponseMessage>
              <AuditReference>1234567890-abc123456</AuditReference>
              <CertificateResponse>
              <CertificateSubjectAltName>88-73-84-57-00-2F-96-6C</CertificateAltName>
              <CertificateSerial>4DF56E92D528F83544EBA0547068CF8C</CertificateSerial>
              <CertificateStatus>I</CertificateStatus>
              <CertificateBody>
                ${deviceCert_88738457002f966c_ds}
              </CertificateBody>
              <CertificateUsage>DS</CertificateUsage>
              <ManufacturingFlag>false</ManufacturingFlag>
              </CertificateResponse>
            </CertificateDataResponse>`,
          } as Response<string>)
        })
      }
    })
    const q = {
      q: {
        CertificateSubjectAltName: '88-73-84-57-00-2F-96-6C',
      },
      CertificateStatus: cs.CertificateStatus['In use'],
      CertificateUsage: cs.CertificateUsage['Digital Signing'],
    }
    const x509 = new X509Certificate(
      Buffer.from(deviceCert_88738457002f966c_ds, 'base64'),
    )
    await expect(cs.search(q, '1.2.3.4')).resolves.toMatchObject([
      {
        meta: buildDeviceCertificateMetadata(x509),
        x509,
      },
    ])
    expect(gotMock).toHaveBeenCalledTimes(2)
    expect(gotMock).toHaveBeenNthCalledWith(
      1,
      'http://1.2.3.4:8083/services/certificatesearch',
      expect.objectContaining({
        body: cs.prepareRequest('CertificateSearchRequest', {
          CertificateSubjectAltName: '88-73-84-57-00-2F-96-6C',
        }),
        method: 'post',
        headers: { 'content-type': 'application/xml' },
      }),
    )
    expect(gotMock).toHaveBeenNthCalledWith(
      2,
      'http://1.2.3.4:8083/services/retrievecertificate',
      expect.objectContaining({
        body: cs.prepareRequest('CertificateDataRequest', {
          CertificateSerial: '4DF56E92D528F83544EBA0547068CF8C',
        }),
        method: 'post',
        headers: { 'content-type': 'application/xml' },
      }),
    )
  })

  test('nominal-organisation-supplier1', async () => {
    gotMock.mockImplementation((x, { body }) => {
      if (x.endsWith('certificatesearch')) {
        return new Promise<Response<string>>((resolve) => {
          resolve({
            statusCode: 200,
            headers: { 'content-type': 'application/xml; charset=utf-8' },
            body: `
              <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
              <CertificateSearchResponse>
                <ResponseCode>200</ResponseCode>
                <ResponseMessage>Success</ResponseMessage>
                <AuditReference>1234567890-abc123456</AuditReference>
                <Result>
                  <CertificateSerial>3B362657731E6B2BBE078650CFA14F15</CertificateSerial>
                  <CertificateSubjectName>90-B3-D5-1F-30-01-00-00</CertificateSubjectName>
                  <CertificateStatus>I</CertificateStatus>
                  <CertificateRole>2</CertificateRole>
                  <CertificateUsage>KA</CertificateUsage>
                  <ManufacturingFlag>false</ManufacturingFlag>
                </Result>
                <Result>
                  <CertificateSerial>52D7B8A109F26D898CE821C32878F618</CertificateSerial>
                  <CertificateSubjectName>90-B3-D5-1F-30-01-00-00</CertificateSubjectName>
                  <CertificateStatus>I</CertificateStatus>
                  <CertificateRole>2</CertificateRole>
                  <CertificateUsage>KA</CertificateUsage>
                  <ManufacturingFlag>false</ManufacturingFlag>
                </Result>
                <Result>
                  <CertificateSerial>5BC2F4D9349C5E0F2DE978BDBE476FE6</CertificateSerial>
                  <CertificateSubjectName>90-B3-D5-1F-30-01-00-00</CertificateSubjectName>
                  <CertificateStatus>I</CertificateStatus>
                  <CertificateRole>2</CertificateRole>
                  <CertificateUsage>KA</CertificateUsage>
                  <ManufacturingFlag>false</ManufacturingFlag>
                </Result>
                <Result>
                  <CertificateSerial>4FBC525201A1D7586C1BC1C4734DEB9F</CertificateSerial>
                  <CertificateSubjectName>90-B3-D5-1F-30-01-00-00</CertificateSubjectName>
                  <CertificateStatus>I</CertificateStatus>
                  <CertificateRole>2</CertificateRole>
                  <CertificateUsage>DS</CertificateUsage>
                  <ManufacturingFlag>false</ManufacturingFlag>
                </Result>
                <Result>
                  <CertificateSerial>703733774EF2B8E50F7AF2BBB33C198F</CertificateSerial>
                  <CertificateSubjectName>90-B3-D5-1F-30-01-00-00</CertificateSubjectName>
                  <CertificateStatus>I</CertificateStatus>
                  <CertificateRole>2</CertificateRole>
                  <CertificateUsage>KA</CertificateUsage>
                  <ManufacturingFlag>false</ManufacturingFlag>
                </Result>
                <Result>
                  <CertificateSerial>4A07BC01D9253B51FAF01F7EC7DA5B2F</CertificateSerial>
                  <CertificateSubjectName>90-B3-D5-1F-30-01-00-00</CertificateSubjectName>
                  <CertificateStatus>I</CertificateStatus>
                  <CertificateRole>2</CertificateRole>
                  <CertificateUsage>DS</CertificateUsage>
                  <ManufacturingFlag>false</ManufacturingFlag>
                </Result>
                <Result>
                  <CertificateSerial>14BE4AD2EA1D0E4EC7F7156BD24624A7</CertificateSerial>
                  <CertificateSubjectName>90-B3-D5-1F-30-01-00-00</CertificateSubjectName>
                  <CertificateStatus>I</CertificateStatus>
                  <CertificateRole>135</CertificateRole>
                  <CertificateUsage>DS</CertificateUsage>
                  <ManufacturingFlag>false</ManufacturingFlag>
                </Result>
              </CertificateSearchResponse>`,
          } as Response<string>)
        })
      } else {
        return new Promise<Response<string>>((resolve) => {
          const flag =
            (body as string).match('4FBC525201A1D7586C1BC1C4734DEB9F') !== null
          resolve({
            statusCode: 200,
            headers: { 'content-type': 'application/xml; charset=utf-8' },
            body: `
            <?xml version="1.0" encoding="utf-8"?>
            <CertificateDataResponse>
              <ResponseCode>200</ResponseCode>
              <ResponseMessage>Success</ResponseMessage>
              <AuditReference>1234567890-abc123456</AuditReference>
              <CertificateResponse>
              <CertificateSubjectName>90-B3-D5-1F-30-00-00-01</CertificateSubjectName>
              <CertificateSerial>${
                flag
                  ? '4FBC525201A1D7586C1BC1C4734DEB9F'
                  : '4A07BC01D9253B51FAF01F7EC7DA5B2F'
              }</CertificateSerial>
              <CertificateStatus>I</CertificateStatus>
              <CertificateBody>
                ${
                  flag
                    ? orgCert_90b3d51f30010000_ds
                    : orgCert_90b3d51f30010000_ds_b
                }
              </CertificateBody>
              <CertificateRole>2</CertificateRole>
              <CertificateUsage>DS</CertificateUsage>
              <ManufacturingFlag>false</ManufacturingFlag>
              </CertificateResponse>
            </CertificateDataResponse>`,
          } as Response<string>)
        })
      }
    })
    const q = {
      q: {
        CertificateSubjectName: '90-B3-D5-1F-30-01-00-00',
      },
      CertificateUsage: cs.CertificateUsage['Digital Signing'],
      CertificateStatus: cs.CertificateStatus['In use'],
      CertificateRole: cs.CertificateRole.Supplier,
    }
    const x509_1 = new X509Certificate(
      Buffer.from(orgCert_90b3d51f30010000_ds, 'base64'),
    )
    const x509_2 = new X509Certificate(
      Buffer.from(orgCert_90b3d51f30010000_ds_b, 'base64'),
    )
    await expect(cs.search(q, '1.2.3.4')).resolves.toMatchObject(
      expect.arrayContaining([
        {
          meta: buildOrgCertificateMetadata(x509_1),
          x509: x509_1,
        },
        {
          meta: buildOrgCertificateMetadata(x509_2),
          x509: x509_2,
        },
      ]),
    )
    expect(gotMock).toHaveBeenCalledTimes(3)
    expect(gotMock).toHaveBeenNthCalledWith(
      2,
      'http://1.2.3.4:8083/services/retrievecertificate',
      expect.objectContaining({
        body: cs.prepareRequest('CertificateDataRequest', {
          CertificateSerial: '4FBC525201A1D7586C1BC1C4734DEB9F',
        }),
      }),
    )
    expect(gotMock).toHaveBeenNthCalledWith(
      3,
      'http://1.2.3.4:8083/services/retrievecertificate',
      expect.objectContaining({
        body: cs.prepareRequest('CertificateDataRequest', {
          CertificateSerial: '4A07BC01D9253B51FAF01F7EC7DA5B2F',
        }),
      }),
    )
  })

  test('nominal-organisation-supplier1-xmlSign', async () => {
    gotMock.mockImplementation((x, { body }) => {
      if (x.endsWith('certificatesearch')) {
        return new Promise<Response<string>>((resolve) => {
          resolve({
            statusCode: 200,
            headers: { 'content-type': 'application/xml; charset=utf-8' },
            body: `
              <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
              <CertificateSearchResponse>
                <ResponseCode>200</ResponseCode>
                <ResponseMessage>Success</ResponseMessage>
                <AuditReference>1234567890-abc123456</AuditReference>
                <Result>
                  <CertificateSerial>3B362657731E6B2BBE078650CFA14F15</CertificateSerial>
                  <CertificateSubjectName>90-B3-D5-1F-30-01-00-00</CertificateSubjectName>
                  <CertificateStatus>I</CertificateStatus>
                  <CertificateRole>2</CertificateRole>
                  <CertificateUsage>KA</CertificateUsage>
                  <ManufacturingFlag>false</ManufacturingFlag>
                </Result>
                <Result>
                  <CertificateSerial>52D7B8A109F26D898CE821C32878F618</CertificateSerial>
                  <CertificateSubjectName>90-B3-D5-1F-30-01-00-00</CertificateSubjectName>
                  <CertificateStatus>I</CertificateStatus>
                  <CertificateRole>2</CertificateRole>
                  <CertificateUsage>KA</CertificateUsage>
                  <ManufacturingFlag>false</ManufacturingFlag>
                </Result>
                <Result>
                  <CertificateSerial>5BC2F4D9349C5E0F2DE978BDBE476FE6</CertificateSerial>
                  <CertificateSubjectName>90-B3-D5-1F-30-01-00-00</CertificateSubjectName>
                  <CertificateStatus>I</CertificateStatus>
                  <CertificateRole>2</CertificateRole>
                  <CertificateUsage>KA</CertificateUsage>
                  <ManufacturingFlag>false</ManufacturingFlag>
                </Result>
                <Result>
                  <CertificateSerial>4FBC525201A1D7586C1BC1C4734DEB9F</CertificateSerial>
                  <CertificateSubjectName>90-B3-D5-1F-30-01-00-00</CertificateSubjectName>
                  <CertificateStatus>I</CertificateStatus>
                  <CertificateRole>2</CertificateRole>
                  <CertificateUsage>DS</CertificateUsage>
                  <ManufacturingFlag>false</ManufacturingFlag>
                </Result>
                <Result>
                  <CertificateSerial>703733774EF2B8E50F7AF2BBB33C198F</CertificateSerial>
                  <CertificateSubjectName>90-B3-D5-1F-30-01-00-00</CertificateSubjectName>
                  <CertificateStatus>I</CertificateStatus>
                  <CertificateRole>2</CertificateRole>
                  <CertificateUsage>KA</CertificateUsage>
                  <ManufacturingFlag>false</ManufacturingFlag>
                </Result>
                <Result>
                  <CertificateSerial>4A07BC01D9253B51FAF01F7EC7DA5B2F</CertificateSerial>
                  <CertificateSubjectName>90-B3-D5-1F-30-01-00-00</CertificateSubjectName>
                  <CertificateStatus>I</CertificateStatus>
                  <CertificateRole>2</CertificateRole>
                  <CertificateUsage>DS</CertificateUsage>
                  <ManufacturingFlag>false</ManufacturingFlag>
                </Result>
                <Result>
                  <CertificateSerial>14BE4AD2EA1D0E4EC7F7156BD24624A7</CertificateSerial>
                  <CertificateSubjectName>90-B3-D5-1F-30-01-00-00</CertificateSubjectName>
                  <CertificateStatus>I</CertificateStatus>
                  <CertificateRole>135</CertificateRole>
                  <CertificateUsage>DS</CertificateUsage>
                  <ManufacturingFlag>false</ManufacturingFlag>
                </Result>
              </CertificateSearchResponse>`,
          } as Response<string>)
        })
      } else {
        return new Promise<Response<string>>((resolve) => {
          resolve({
            statusCode: 200,
            headers: { 'content-type': 'application/xml; charset=utf-8' },
            body: `
            <?xml version="1.0" encoding="utf-8"?>
            <CertificateDataResponse>
              <ResponseCode>200</ResponseCode>
              <ResponseMessage>Success</ResponseMessage>
              <AuditReference>1234567890-abc123456</AuditReference>
              <CertificateResponse>
              <CertificateSubjectName>90-B3-D5-1F-30-00-00-01</CertificateSubjectName>
              <CertificateSerial>14BE4AD2EA1D0E4EC7F7156BD24624A7</CertificateSerial>
              <CertificateStatus>I</CertificateStatus>
              <CertificateBody>
                ${orgCert_90b3d51f30010000_ds_xmlSign}
              </CertificateBody>
              <CertificateRole>135</CertificateRole>
              <CertificateUsage>DS</CertificateUsage>
              <ManufacturingFlag>false</ManufacturingFlag>
              </CertificateResponse>
            </CertificateDataResponse>`,
          } as Response<string>)
        })
      }
    })
    const q = {
      q: {
        CertificateSubjectName: '90-B3-D5-1F-30-01-00-00',
      },
      CertificateUsage: cs.CertificateUsage['Digital Signing'],
      CertificateStatus: cs.CertificateStatus['In use'],
      CertificateRole: cs.CertificateRole.XmlSign,
    }
    const x509 = new X509Certificate(
      Buffer.from(orgCert_90b3d51f30010000_ds_xmlSign, 'base64'),
    )
    await expect(cs.search(q, '1.2.3.4')).resolves.toMatchObject([
      {
        meta: buildOrgCertificateMetadata(x509),
        x509,
      },
    ])
    expect(gotMock).toHaveBeenCalledTimes(2)
    expect(gotMock).toHaveBeenNthCalledWith(
      2,
      'http://1.2.3.4:8083/services/retrievecertificate',
      expect.objectContaining({
        body: cs.prepareRequest('CertificateDataRequest', {
          CertificateSerial: '14BE4AD2EA1D0E4EC7F7156BD24624A7',
        }),
      }),
    )
  })
})

describe('resolveHeaders', () => {
  test('defined', () => {
    expect(cs.resolveHeaders).toBeDefined()
  })

  test('empty headers', async () => {
    await expect(cs.resolveHeaders()).resolves.toEqual({})
  })

  test('string values', async () => {
    const headers = {
      'content-type': 'application/json',
      'authorization': 'Bearer token123'
    }
    await expect(cs.resolveHeaders(headers)).resolves.toEqual({
      'content-type': 'application/json',
      'authorization': 'Bearer token123'
    })
  })

  test('sync function values', async () => {
    const headers = {
      'x-timestamp': () => '2023-01-01',
      'x-random': () => 'abc123'
    }
    await expect(cs.resolveHeaders(headers)).resolves.toEqual({
      'x-timestamp': '2023-01-01',
      'x-random': 'abc123'
    })
  })

  test('async function values', async () => {
    const headers = {
      'x-async': async () => 'async-value',
      'x-promise': () => Promise.resolve('promise-value')
    }
    await expect(cs.resolveHeaders(headers)).resolves.toEqual({
      'x-async': 'async-value',
      'x-promise': 'promise-value'
    })
  })

  test('mixed value types', async () => {
    const headers = {
      'static': 'static-value',
      'sync-func': () => 'sync-value',
      'async-func': async () => 'async-value'
    }
    await expect(cs.resolveHeaders(headers)).resolves.toEqual({
      'static': 'static-value',
      'sync-func': 'sync-value',
      'async-func': 'async-value'
    })
  })

  test('merge with existing gotHeaders', async () => {
    const headers = {
      'x-custom': 'custom-value'
    }
    const gotHeaders = {
      'content-type': 'application/xml',
      'user-agent': 'test-agent'
    }
    await expect(cs.resolveHeaders(headers, gotHeaders)).resolves.toEqual({
      'content-type': 'application/xml',
      'user-agent': 'test-agent',
      'x-custom': 'custom-value'
    })
  })

  test('override existing gotHeaders', async () => {
    const headers = {
      'content-type': () => 'application/json'
    }
    const gotHeaders = {
      'content-type': 'application/xml'
    }
    await expect(cs.resolveHeaders(headers, gotHeaders)).resolves.toEqual({
      'content-type': 'application/json'
    })
  })
})

describe('parseUrl', () => {
  test('defined', () => {
    expect(cs.parseUrl).toBeDefined()
  })

  describe('minimal', () => {
    test('hostname', () => {
      expect(cs.parseUrl('hello')).toBe('http://hello:8083/')
    })

    test('ipaddress', () => {
      expect(cs.parseUrl('1.2.3.4')).toBe('http://1.2.3.4:8083/')
    })
  })

  describe('port', () => {
    test('hostname', () => {
      expect(cs.parseUrl('hello:999')).toBe('http://hello:999/')
    })

    test('ipaddress', () => {
      expect(cs.parseUrl('1.2.3.4:999')).toBe('http://1.2.3.4:999/')
    })

    test('defaultport', () => {
      expect(cs.parseUrl('hello:80')).toBe('http://hello/')
    })

    test('trailingslash', () => {
      expect(cs.parseUrl('hello:80/')).toBe('http://hello/')
    })
  })

  describe('https', () => {
    test('hostname', () => {
      expect(cs.parseUrl('https://hello')).toBe('https://hello/')
    })

    test('ipaddress', () => {
      expect(cs.parseUrl('https://1.2.3.4')).toBe('https://1.2.3.4/')
    })

    test('trailingslash', () => {
      expect(cs.parseUrl('https://hello/')).toBe('https://hello/')
    })

    describe('port', () => {
      test('hostname', () => {
        expect(cs.parseUrl('https://hello:999')).toBe('https://hello:999/')
      })

      test('ipaddress', () => {
        expect(cs.parseUrl('https://1.2.3.4:999')).toBe('https://1.2.3.4:999/')
      })

      test('defaultport', () => {
        expect(cs.parseUrl('https://hello:443')).toBe('https://hello/')
      })
    })
  })
})
