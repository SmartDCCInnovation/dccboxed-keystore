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

const queryMock = jest.fn()
const searchMock = jest.fn()
jest.mock('../src/certificateSearch', () => ({
  query: queryMock,
  search: searchMock,
  __esModule: true,
}))
import { createPrivateKey, KeyObject, X509Certificate } from 'node:crypto'
import { existsSync } from 'node:fs'
import { rm, stat } from 'node:fs/promises'
import { resolve } from 'node:path'
import * as db from '../src/boxedKeyStore'
import {
  buildDeviceCertificateMetadata,
  EUI,
  KeyUsage,
} from '../src/certificateMetadata'
import { CertificateStatus, CertificateUsage } from '../src/certificateSearch'
import { KeyStoreDB } from '../src/db'

const testIf = existsSync(resolve(__dirname, '..', 'keystore.json'))
  ? test
  : test.skip

describe('BoxedKeyStore', () => {
  const testBackingDbName = resolve(__dirname, 'test-backing.json')
  const testLocalDbName = resolve(__dirname, 'test-local.json')

  const org_90b3d51f30010000_ds_cert = `
    MIIBrDCCAVKgAwIBAgIQT7xSUgGh11hsG8HEc03rnzAKBggqhkjOPQQDAjAaMQsw
    CQYDVQQLEwIwNzELMAkGA1UEAxMCWjEwHhcNMTUxMDMwMDAwMDAwWhcNMjUxMDI5
    MjM1OTU5WjA7MRgwFgYDVQQDDA9HSVRURVNUU1VQUExJRVIxCzAJBgNVBAsMAjAy
    MRIwEAYDVQQtAwkAkLPVHzABAAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQw
    wqtaDRMXJv+9qA55KUzDdTRDKj5CRAW5ejq6D/x53OcpslF1Y8t9lYJ+TFC0jLo9
    h9WJPFG5bYfDReNxf4weo1kwVzAOBgNVHQ8BAf8EBAMCB4AwEQYDVR0OBAoECESJ
    l5LRlvS4MB0GA1UdIAEB/wQTMBEwDwYNKoY6AAGEj7kPAQIBBDATBgNVHSMEDDAK
    gAhPVojX7JM74jAKBggqhkjOPQQDAgNIADBFAiEA39CQ51c+r1+oLhqn242f7VEY
    ObV1LVXRAJHyUP3xiiICIF637Dax9BM+UVV9M7WcSe9rvRDpqksdzZKOZbPprdHF`
  const org_90b3d51f30010000_ds_key = `
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOeBFQ8dm5wsYOZQD
    xySQxQGcGfs6sf1pmawsQTd5enqhRANCAAQwwqtaDRMXJv+9qA55KUzDdTRDKj5C
    RAW5ejq6D/x53OcpslF1Y8t9lYJ+TFC0jLo9h9WJPFG5bYfDReNxf4we`

  const org_90b3d51f30010000_ka_cert = `
    MIIBkjCCATigAwIBAgIQOzYmV3Meayu+B4ZQz6FPFTAKBggqhkjOPQQDAjAaMQsw
    CQYDVQQLEwIwNzELMAkGA1UEAxMCWjEwHhcNMTUxMDMwMDAwMDAwWhcNMjUxMDI5
    MjM1OTU5WjAhMQswCQYDVQQLDAIwMjESMBAGA1UELQMJAJCz1R8wAQAAMFkwEwYH
    KoZIzj0CAQYIKoZIzj0DAQcDQgAEknT/+KOvVtawFtOo+mDaPleVUespWBnIDrek
    PzByKyJVBCheSlF2uWM027cuoM/AycbkCgrjwok3w0JY8OhAuqNZMFcwDgYDVR0P
    AQH/BAQDAgMIMBEGA1UdDgQKBAhAW4xiaH2PcDAdBgNVHSABAf8EEzARMA8GDSqG
    OgABhI+5DwECAQQwEwYDVR0jBAwwCoAIT1aI1+yTO+IwCgYIKoZIzj0EAwIDSAAw
    RQIgFr/75lBWSxc8gzYM2B2KIo9qDgZml43a49UDQDJxy9cCIQCcncpTfMwNiHEJ
    MBqualHKnx28X5I+HWDdRugWzqYbDA==`
  const org_90b3d51f30010000_ka_key = `
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQIg5kNpbNy3E7JbH
    a1dr9dQgbjv9NMv2C2JEjx+bpUShRANCAASSdP/4o69W1rAW06j6YNo+V5VR6ylY
    GcgOt6Q/MHIrIlUEKF5KUXa5YzTbty6gz8DJxuQKCuPCiTfDQljw6EC6`

  const org_90b3d51f30010000_xmlSign_cert = `
    MIIBfzCCASWgAwIBAgIQFL5K0uodDk7H9xVr0kYkpzAKBggqhkjOPQQDAjAaMQsw
    CQYDVQQLDAIwNzELMAkGA1UEAwwCWjEwIBcNMTgwMTAxMDAwMDAwWhgPMjExODAx
    MDEwMDAwMDBaMCExCzAJBgNVBAsMAjg3MRIwEAYDVQQtAwkAkLPVHzABAAAwWTAT
    BgcqhkjOPQIBBggqhkjOPQMBBwNCAASfiKvSIFxEFeHhGzLWEiBlfi045xQ/m4hL
    +s1+SKlje0Vb//LRzGVaUobobAJaVN5cRd43ZiioDY+0cTTwvUcuo0QwQjAdBgNV
    HSABAf8EEzARMA8GDSqGOgABhI+5DwECAQQwEQYDVR0OBAoECEusYLdMsaDbMA4G
    A1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA4LXpqbs5lRubjOM4FtEy
    7rowBKUyf62/hreDAIn3fEoCIDVnSEzk+wBn2NJ392d+S9sd03Wca5m4YVgyb2GT
    eX8c`

  const device_00db1234567890a4_ds_cert = `
    MIIBoTCCAUagAwIBAgIQNkGyIlgJ/7uoGz6OMgqmzzAKBggqhkjOPQQDAjAPMQ0w
    CwYDVQQDEwRFMzU3MCAXDTE2MDQwNjAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjAA
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEys++enzkr2yb4qwOP4Sf/qIJuZeg
    cGYZULUXsSLqDUtkG4DeCKMTe090mEa57ZrHbH3wvfjqeEc1BOm7Scqmx6OBkDCB
    jTAOBgNVHQ8BAf8EBAMCB4AwEQYDVR0OBAoECE/HRnKgmyJhMDUGA1UdEQEB/wQr
    MCmgJwYIKwYBBQUHCASgGzAZBg0qhjoAAYSPuQ8BAgIBBAgA2xI0VniQpDAcBgNV
    HSABAf8EEjAQMA4GDCqGOgAB7e5AAQIBBDATBgNVHSMEDDAKgAhH1ArzQSkEoDAK
    BggqhkjOPQQDAgNJADBGAiEAivHtRK3V4zLGY59T//SnQttB74xz/9A+aRUV5HKo
    H8oCIQDVfXKeMEihJxkOpSGzvT9XEXSU+uOlSTSs4Mmk3NTTGA==`

  const device_00db1234567890a4_ka_cert = `
    MIIBoDCCAUagAwIBAgIQSiNt7Xc0UzIiYPfefETBZjAKBggqhkjOPQQDAjAPMQ0w
    CwYDVQQDEwRFMzU3MCAXDTE2MDQwNjAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjAA
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4WwfjNZwHoDL4DG1QJVIbyWwWn6B
    Kt8SJ2ujFyakONVNyEfnK2E3UgibkuL4hT0+Q84PoO9SDlnsMbcsoUkI06OBkDCB
    jTAOBgNVHQ8BAf8EBAMCAwgwEQYDVR0OBAoECEcMHpw5Eh7IMDUGA1UdEQEB/wQr
    MCmgJwYIKwYBBQUHCASgGzAZBg0qhjoAAYSPuQ8BAgIBBAgA2xI0VniQpDAcBgNV
    HSABAf8EEjAQMA4GDCqGOgAB7e5AAQIBBDATBgNVHSMEDDAKgAhH1ArzQSkEoDAK
    BggqhkjOPQQDAgNIADBFAiBtih3M74gET/t+qE6aRYvvCQfYGqUK26lzVBFwhaxF
    ywIhAMWtZ3u/bQs4oFbKuXDQreKUFw2W7kRVbOa8NbYFXR92`

  /* preload the backing datastore with supplier cert */
  beforeAll(() => {
    const keystore = new KeyStoreDB(testBackingDbName)

    keystore.push({
      certificate: new X509Certificate(
        Buffer.from(org_90b3d51f30010000_ds_cert, 'base64')
      ),
      private: createPrivateKey({
        key: Buffer.from(org_90b3d51f30010000_ds_key, 'base64'),
        format: 'der',
        type: 'pkcs8',
      }),
    })

    keystore.push({
      certificate: new X509Certificate(
        Buffer.from(org_90b3d51f30010000_ka_cert, 'base64')
      ),
      private: createPrivateKey({
        key: Buffer.from(org_90b3d51f30010000_ka_key, 'base64'),
        format: 'der',
        type: 'pkcs8',
      }),
    })

    keystore.push({
      certificate: new X509Certificate(
        Buffer.from(org_90b3d51f30010000_xmlSign_cert, 'base64')
      ),
    })
  })

  afterAll(async () => {
    await rm(testBackingDbName, { force: true })
  })

  beforeEach(() => {
    queryMock.mockReset()
    searchMock.mockReset()
  })

  afterEach(async () => {
    await rm(testLocalDbName, { force: true })
  })

  test('defined', () => {
    expect(db.BoxedKeyStore).toBeDefined()
  })

  test('class', () => {
    expect(
      new db.BoxedKeyStore('1.2.3.4', testLocalDbName, testBackingDbName)
    ).toBeInstanceOf(db.BoxedKeyStore)
  })

  test('local-db-created', async () => {
    await expect(stat(testLocalDbName)).rejects.toMatchObject({
      code: 'ENOENT',
    })
    new db.BoxedKeyStore('1.2.3.4', testLocalDbName, testBackingDbName)
    await expect(stat(testLocalDbName)).resolves.toMatchObject({ size: 2 })
  })

  describe('query', () => {
    test('cache-miss-backing-hit-serial', () => {
      const ks = new db.BoxedKeyStore(
        '1.2.3.4',
        testLocalDbName,
        testBackingDbName
      )
      return expect(
        ks.query({
          lookup: 'certificate',
          serial: BigInt('105986833131214866166891566273223584671'),
        })
      ).resolves.toMatchObject({
        eui: new EUI('90b3d51f30010000'),
        serial: BigInt('105986833131214866166891566273223584671'),
        role: 2,
        keyUsage: [KeyUsage.digitalSignature],
        certificate: new X509Certificate(
          Buffer.from(org_90b3d51f30010000_ds_cert, 'base64')
        ),
      })
    })

    test('cache-miss-backing-hit-search', () => {
      const ks = new db.BoxedKeyStore(
        '1.2.3.4',
        testLocalDbName,
        testBackingDbName
      )
      return expect(
        ks.query({
          lookup: 'privateKey',
          eui: '90-b3-d5-1f-30-01-00-00',
          keyUsage: KeyUsage.digitalSignature,
          role: 2,
        })
      ).resolves.toMatchObject([
        expect.objectContaining({
          eui: new EUI('90b3d51f30010000'),
          serial: BigInt('105986833131214866166891566273223584671'),
          role: 2,
          keyUsage: [KeyUsage.digitalSignature],
          privateKey: expect.any(KeyObject),
        }),
      ])
    })

    test('cache-miss-backing-hit-uint8-search', async () => {
      const ks = new db.BoxedKeyStore(
        '1.2.3.4',
        testLocalDbName,
        testBackingDbName
      )
      await expect(
        ks.query({
          lookup: 'privateKey',
          eui: Buffer.from('90b3d51f30010000', 'hex'),
          keyUsage: KeyUsage.digitalSignature,
          role: 2,
        })
      ).resolves.toMatchObject([
        expect.objectContaining({
          eui: new EUI('90b3d51f30010000'),
          serial: BigInt('105986833131214866166891566273223584671'),
          role: 2,
          keyUsage: [KeyUsage.digitalSignature],
          privateKey: expect.any(KeyObject),
        }),
      ])
      expect(searchMock).toHaveBeenCalledTimes(0)
    })

    test('cache-miss-backing-miss-serial-private', async () => {
      const ks = new db.BoxedKeyStore(
        '1.2.3.4',
        testLocalDbName,
        testBackingDbName
      )
      await expect(
        ks.query({
          lookup: 'privateKey',
          serial: BigInt('9001'),
        })
      ).resolves.toBeNull()
      expect(queryMock).toHaveBeenCalledTimes(0)
    })

    test('cache-miss-backing-miss-serial-certificate', async () => {
      const x509 = new X509Certificate(
        Buffer.from(device_00db1234567890a4_ds_cert, 'base64')
      )
      queryMock.mockReturnValue(
        new Promise((resolves) =>
          resolves({
            meta: buildDeviceCertificateMetadata(x509),
            x509,
          })
        )
      )
      const ks = new db.BoxedKeyStore(
        '1.2.3.4',
        testLocalDbName,
        testBackingDbName
      )
      await expect(stat(testLocalDbName)).resolves.toMatchObject({
        size: 2,
      })
      await expect(
        ks.query({
          lookup: 'certificate',
          serial: BigInt('72119424058103965276745519964518786767'),
        })
      ).resolves.toMatchObject({
        eui: new EUI('00db1234567890a4'),
        serial: BigInt('72119424058103965276745519964518786767'),
        keyUsage: [KeyUsage.digitalSignature],
        certificate: x509,
      })
      expect(queryMock).toHaveBeenCalledTimes(1)
      expect(queryMock).toHaveBeenNthCalledWith(
        1,
        '3641B2225809FFBBA81B3E8E320AA6CF'.toLowerCase(),
        '1.2.3.4'
      )
      await expect(stat(testLocalDbName)).resolves.not.toMatchObject({
        size: 2,
      })
    })
  })

  test('cache-miss-backing-miss-search-certificate', async () => {
    const x509 = new X509Certificate(
      Buffer.from(device_00db1234567890a4_ka_cert, 'base64')
    )
    searchMock.mockReturnValue(
      new Promise((resolves) =>
        resolves([
          {
            meta: buildDeviceCertificateMetadata(x509),
            x509,
          },
        ])
      )
    )
    const ks = new db.BoxedKeyStore(
      '1.2.3.4',
      testLocalDbName,
      testBackingDbName
    )
    await expect(stat(testLocalDbName)).resolves.toMatchObject({
      size: 2,
    })
    await expect(
      ks.query({
        lookup: 'certificate',
        eui: '00db1234567890a4',
        keyUsage: KeyUsage.keyAgreement,
      })
    ).resolves.toEqual([
      expect.objectContaining({
        eui: new EUI('00db1234567890a4'),
        serial: BigInt('98546831674745780667197067843932045670'),
        keyUsage: [KeyUsage.keyAgreement],
        certificate: x509,
      }),
    ])
    expect(searchMock).toHaveBeenCalledTimes(1)
    expect(searchMock).toHaveBeenNthCalledWith(
      1,
      {
        CertificateUsage: CertificateUsage['Key Agreement'],
        CertificateStatus: CertificateStatus['In use'],
        q: {
          CertificateSubjectAltName: '00-db-12-34-56-78-90-a4',
        },
      },
      '1.2.3.4'
    )
    await expect(stat(testLocalDbName)).resolves.not.toMatchObject({
      size: 2,
    })
  })

  test('cache-miss-backing-miss-search-certificate-v2', async () => {
    const x509 = new X509Certificate(
      Buffer.from(device_00db1234567890a4_ds_cert, 'base64')
    )
    searchMock.mockReturnValue(
      new Promise((resolves) =>
        resolves([
          {
            meta: buildDeviceCertificateMetadata(x509),
            x509,
          },
        ])
      )
    )
    const ks = new db.BoxedKeyStore(
      '1.2.3.4',
      testLocalDbName,
      testBackingDbName
    )
    await expect(stat(testLocalDbName)).resolves.toMatchObject({
      size: 2,
    })
    await expect(
      ks.query({
        lookup: 'certificate',
        eui: '00db1234567890a4',
        keyUsage: KeyUsage.digitalSignature,
      })
    ).resolves.toMatchObject([
      expect.objectContaining({
        eui: new EUI('00db1234567890a4'),
        serial: BigInt('72119424058103965276745519964518786767'),
        keyUsage: [KeyUsage.digitalSignature],
        certificate: x509,
      }),
    ])
    expect(searchMock).toHaveBeenCalledTimes(1)
    expect(searchMock).toHaveBeenNthCalledWith(
      1,
      {
        CertificateUsage: CertificateUsage['Digital Signing'],
        CertificateStatus: CertificateStatus['In use'],
        q: {
          CertificateSubjectAltName: '00-db-12-34-56-78-90-a4',
        },
      },
      '1.2.3.4'
    )
    await expect(stat(testLocalDbName)).resolves.not.toMatchObject({
      size: 2,
    })
  })

  test('cache-miss-backing-miss-search-certificate-organisation', async () => {
    const ks = new db.BoxedKeyStore(
      '1.2.3.4',
      testLocalDbName,
      testBackingDbName
    )
    await expect(
      ks.query({
        lookup: 'certificate',
        eui: '00db1234567890a4',
        role: 2,
        keyUsage: KeyUsage.keyAgreement,
      })
    ).resolves.toBeNull()
    expect(queryMock).toHaveBeenCalledTimes(0)
  })

  test('cache-hit', async () => {
    const x509 = new X509Certificate(
      Buffer.from(device_00db1234567890a4_ds_cert, 'base64')
    )
    searchMock.mockReturnValue(
      new Promise((resolves) =>
        resolves([
          {
            meta: buildDeviceCertificateMetadata(x509),
            x509,
          },
        ])
      )
    )
    const ks = new db.BoxedKeyStore(
      '1.2.3.4',
      testLocalDbName,
      testBackingDbName
    )
    await expect(stat(testLocalDbName)).resolves.toMatchObject({
      size: 2,
    })
    await expect(
      ks.query({
        lookup: 'certificate',
        eui: '00db1234567890a4',
        keyUsage: KeyUsage.digitalSignature,
      })
    ).resolves.toBeDefined()
    expect(searchMock).toHaveBeenCalledTimes(1)
    expect(searchMock).toHaveBeenNthCalledWith(
      1,
      {
        CertificateUsage: CertificateUsage['Digital Signing'],
        CertificateStatus: CertificateStatus['In use'],
        q: {
          CertificateSubjectAltName: '00-db-12-34-56-78-90-a4',
        },
      },
      '1.2.3.4'
    )
    await expect(stat(testLocalDbName)).resolves.not.toMatchObject({
      size: 2,
    })
    searchMock.mockReset()
    await expect(
      ks.query({
        lookup: 'certificate',
        eui: '00db1234567890a4',
        keyUsage: KeyUsage.digitalSignature,
      })
    ).resolves.toBeDefined()
    expect(searchMock).toHaveBeenCalledTimes(0)
  })

  test('cache-miss-backing-miss-uint8-search-certificate', async () => {
    const x509 = new X509Certificate(
      Buffer.from(device_00db1234567890a4_ka_cert, 'base64')
    )
    searchMock.mockReturnValue(
      new Promise((resolves) =>
        resolves([
          {
            meta: buildDeviceCertificateMetadata(x509),
            x509,
          },
        ])
      )
    )
    const ks = new db.BoxedKeyStore(
      '1.2.3.4',
      testLocalDbName,
      testBackingDbName
    )
    await expect(stat(testLocalDbName)).resolves.toMatchObject({
      size: 2,
    })
    await expect(
      ks.query({
        lookup: 'certificate',
        eui: Buffer.from('00db1234567890a4', 'hex'),
        keyUsage: KeyUsage.keyAgreement,
      })
    ).resolves.toEqual([
      expect.objectContaining({
        eui: new EUI('00db1234567890a4'),
        serial: BigInt('98546831674745780667197067843932045670'),
        keyUsage: [KeyUsage.keyAgreement],
        certificate: x509,
      }),
    ])
    expect(searchMock).toHaveBeenCalledTimes(1)
    expect(searchMock).toHaveBeenNthCalledWith(
      1,
      {
        CertificateUsage: CertificateUsage['Key Agreement'],
        CertificateStatus: CertificateStatus['In use'],
        q: {
          CertificateSubjectAltName: '00-db-12-34-56-78-90-a4',
        },
      },
      '1.2.3.4'
    )
  })

  test('unsupported-keyUsage', () => {
    const ks = new db.BoxedKeyStore(
      '1.2.3.4',
      testLocalDbName,
      testBackingDbName
    )
    return expect(
      ks.query({
        lookup: 'certificate',
        eui: '90-b3-d5-1f-30-01-00-00',
        keyUsage: KeyUsage.decipherOnly,
        role: 2,
      })
    ).resolves.toBeNull()
  })

  testIf('nominal', () => {
    const ks = new db.BoxedKeyStore('1.2.3.4')
    return expect(
      ks.query({
        lookup: 'certificate',
        eui: '90-b3-d5-1f-30-01-00-00',
        keyUsage: KeyUsage.keyAgreement,
        role: 2,
      })
    ).resolves.toBeDefined()
  })

  describe('cleanup', () => {
    test('does-not-remove-provided-file', async () => {
      const ks = new db.BoxedKeyStore(
        '1.2.3.4',
        testLocalDbName,
        testBackingDbName
      )
      await expect(ks.cleanup()).resolves.toBeUndefined()
      await expect(stat(testLocalDbName)).resolves.toBeDefined()
    })

    testIf('removes-temporary-file', async () => {
      const ks = new db.BoxedKeyStore('1.2.3.4')
      expect(typeof ks.temporyFile).toBe('string')
      await expect(stat(ks.temporyFile as string)).resolves.toBeDefined()
      await expect(ks.cleanup()).resolves.toBeUndefined()
      await expect(stat(ks.temporyFile as string)).rejects.toMatchObject({
        code: 'ENOENT',
      })
    })
  })
})
