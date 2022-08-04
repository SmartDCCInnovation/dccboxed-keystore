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

import { createPrivateKey, X509Certificate } from 'node:crypto'
import { readFile, rm, stat } from 'node:fs/promises'
import { resolve } from 'node:path'
import { EUI, KeyUsage } from '../src/certificateMetadata'
import * as db from '../src/db'

describe('KeyStoreDB', () => {
  const testDbName = resolve(__dirname, 'test-dummy.json')
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

  const device_00db1234567890a4_ds_key = `
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgASmcyoHIuO4eHiN0
    AIf2MYX0N+aQPMiuiAY7LdwrMKmhRANCAATKz756fOSvbJvirA4/hJ/+ogm5l6Bw
    ZhlQtRexIuoNS2QbgN4IoxN7T3SYRrntmsdsffC9+Op4RzUE6btJyqbH`

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

  const device_00db1234567890a4_ka_key = `
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVHfYJyrMcZGMfeZK
    /lNvp99GmjC+qzdW5rJMq4M4cr2hRANCAAThbB+M1nAegMvgMbVAlUhvJbBafoEq
    3xIna6MXJqQ41U3IR+crYTdSCJuS4viFPT5Dzg+g71IOWewxtyyhSQjT`

  const org_90b3d51f30000001_ds_cert = `
    MIIBkjCCATigAwIBAgIQRpr+wufAyq7IpAB2m3AryDAKBggqhkjOPQQDAjAaMQsw
    CQYDVQQLEwIwNzELMAkGA1UEAxMCWjEwHhcNMTUxMDMwMDAwMDAwWhcNMjUxMDI5
    MjM1OTU5WjAhMQswCQYDVQQLDAIwMTESMBAGA1UELQMJAJCz1R8wAAABMFkwEwYH
    KoZIzj0CAQYIKoZIzj0DAQcDQgAEX9CL9uFDiw2je8JkE1vpZfLVIrsqJmM1OgI5
    7QIKhacanY2F2HzDikhNorxT729KFo0M6IYcQKVDxM0VsnZm+aNZMFcwDgYDVR0P
    AQH/BAQDAgeAMBEGA1UdDgQKBAhB+supVvg9hzAdBgNVHSABAf8EEzARMA8GDSqG
    OgABhI+5DwECAQQwEwYDVR0jBAwwCoAIT1aI1+yTO+IwCgYIKoZIzj0EAwIDSAAw
    RQIgFUzuFGjfksF5+XNiopwuwpQJobd1GmBl9SKG+6d7y9oCIQCLDPSUJlfX4clm
    ZOLPpTSroslJqBT+gh8fKXK0Rhbbtw==`
  const org_90b3d51f30000001_ds_key = `
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgswDOxJfzLJjgQ7io
    z/Aq1B50g3eV6MORa+c+ekzHRLihRANCAARf0Iv24UOLDaN7wmQTW+ll8tUiuyom
    YzU6AjntAgqFpxqdjYXYfMOKSE2ivFPvb0oWjQzohhxApUPEzRWydmb5`

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

  const https_cert = `
    MIIEUzCCAzugAwIBAgISBCg4mAiwPnQSxQjt3wL8sVEuMA0GCSqGSIb3DQEBCwUA
    MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
    EwJSMzAeFw0yMjA2MjgyMTA3MjRaFw0yMjA5MjYyMTA3MjNaMBIxEDAOBgNVBAMT
    B2xhcG8uaXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARliQaE++bzrSRNmBVb
    iiQg9Xm9Okka3VwCZmFSXbzIzEp/sk64BiIbaIB6zC6FVQ7aQFDYkSqiarR/0QuZ
    aQeko4ICTDCCAkgwDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMB
    BggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQUpQr4+sfTEl9agWrE
    7ekjY5rVhTAfBgNVHSMEGDAWgBQULrMXt1hWy65QCUDmH6+dixTCxjBVBggrBgEF
    BQcBAQRJMEcwIQYIKwYBBQUHMAGGFWh0dHA6Ly9yMy5vLmxlbmNyLm9yZzAiBggr
    BgEFBQcwAoYWaHR0cDovL3IzLmkubGVuY3Iub3JnLzAdBgNVHREEFjAUggkqLmxh
    cG8uaXSCB2xhcG8uaXQwTAYDVR0gBEUwQzAIBgZngQwBAgEwNwYLKwYBBAGC3xMB
    AQEwKDAmBggrBgEFBQcCARYaaHR0cDovL2Nwcy5sZXRzZW5jcnlwdC5vcmcwggED
    BgorBgEEAdZ5AgQCBIH0BIHxAO8AdgDfpV6raIJPH2yt7rhfTj5a6s2iEqRqXo47
    EsAgRFwqcwAAAYGsWt3QAAAEAwBHMEUCIGYSOc513T0WRQUfRD2FoljMCIeud/vR
    NQDNeiaXvvi5AiEA7CtzDy7p0DC8lrLxn6dwMzaUX/8iA9ChL2nvlYzyzcUAdQBG
    pVXrdfqRIDC1oolp9PN9ESxBdL79SbiFq/L8cP5tRwAAAYGsWt4vAAAEAwBGMEQC
    IHlb3NR242mygRgcltc1Tm4i5/1xklZvyD26Ar9JWGo0AiAFB42qQAcbbT2WXfoO
    96beXpff0hn8piUPuvML28ZBhTANBgkqhkiG9w0BAQsFAAOCAQEAP8ipkaImmJGP
    qAobhtpEr57nwhLRx8vmorTvfS1ZSU8i3/ESHlUMuC5jLDzIGefRS0oGNDC9eVDn
    Fb9razEW3LWY/qi+5cKEo3ZmVaFFSp08j0RwsUK2D7DS5WF7Y5tLl0xbz9ySQ/Gm
    LhM8Rsm53cwieXBH8spluXVEjRP6CEH25ouB0fqrRWX8ju5C4IyxOD8TMRo3SdHL
    mlNQBr1naMf05e++dcmRMK0z6Fjf9+F+MJZK/Wme8BOnR8UPregwq4HVXLuHFbfe
    7LWOL2iY/Bw+Cq2gJd00X9PHhSnbpdGjcBQVSEk5uyXhFvjm8dyO8JPau1aPPqou
    1izP8hIwHQ==`

  afterEach(async () => {
    await rm(testDbName, { force: true })
  })

  test('defined', () => {
    expect(db.KeyStoreDB).toBeDefined()
  })

  test('constructor', async () => {
    await expect(stat(testDbName)).rejects.toMatchObject({ code: 'ENOENT' })
    expect(new db.KeyStoreDB(testDbName)).toBeInstanceOf(db.KeyStoreDB)
    await expect(stat(testDbName)).resolves.toMatchObject({ size: 2 })
  })

  describe('push', () => {
    test('push-cert', async () => {
      await expect(stat(testDbName)).rejects.toMatchObject({ code: 'ENOENT' })
      const keystore = new db.KeyStoreDB(testDbName)
      const x509_ds = new X509Certificate(
        Buffer.from(org_90b3d51f30000001_ds_cert, 'base64')
      )
      expect(
        keystore.push({
          certificate: x509_ds,
        })
      ).toMatchObject({
        eui: new EUI('90b3d51f30000001'),
        role: 1,
        keyUsage: [KeyUsage.digitalSignature],
        serial: BigInt('93850740595185438017946775787620281288'),
      })
      await expect(
        readFile(testDbName, { encoding: 'utf-8' }).then(JSON.parse)
      ).resolves.toStrictEqual({
        '90b3d51f30000001': {
          digitalSignature: {
            '93850740595185438017946775787620281288': {
              role: 1,
              certificate: expect.stringContaining(
                org_90b3d51f30000001_ds_cert.slice(-20)
              ),
            },
          },
        },
      })
    })

    test('push-cert-key', async () => {
      await expect(stat(testDbName)).rejects.toMatchObject({ code: 'ENOENT' })
      const keystore = new db.KeyStoreDB(testDbName)
      const x509_ds = new X509Certificate(
        Buffer.from(org_90b3d51f30000001_ds_cert, 'base64')
      )
      const key_ds = createPrivateKey({
        key: Buffer.from(org_90b3d51f30000001_ds_key, 'base64'),
        format: 'der',
        type: 'pkcs8',
      })
      expect(
        keystore.push({
          certificate: x509_ds,
          private: key_ds,
        })
      ).toMatchObject({
        eui: new EUI('90b3d51f30000001'),
        role: 1,
        keyUsage: [KeyUsage.digitalSignature],
        serial: BigInt('93850740595185438017946775787620281288'),
      })
      await expect(
        readFile(testDbName, { encoding: 'utf-8' }).then(JSON.parse)
      ).resolves.toStrictEqual({
        '90b3d51f30000001': {
          digitalSignature: {
            '93850740595185438017946775787620281288': {
              role: 1,
              certificate: expect.stringContaining(
                org_90b3d51f30000001_ds_cert.slice(-20)
              ),
              privateKey: expect.stringContaining(
                org_90b3d51f30000001_ds_key.slice(-20)
              ),
            },
          },
        },
      })
    })

    test('push-cert-key-duplicate', async () => {
      await expect(stat(testDbName)).rejects.toMatchObject({ code: 'ENOENT' })
      const keystore = new db.KeyStoreDB(testDbName)
      const x509_ds = new X509Certificate(
        Buffer.from(org_90b3d51f30000001_ds_cert, 'base64')
      )
      const key_ds = createPrivateKey({
        key: Buffer.from(org_90b3d51f30000001_ds_key, 'base64'),
        format: 'der',
        type: 'pkcs8',
      })
      expect(
        keystore.push({
          certificate: x509_ds,
          private: key_ds,
        })
      ).toBeDefined()
      expect(
        keystore.push({
          certificate: x509_ds,
          private: key_ds,
        })
      ).toBeDefined()
      await expect(
        readFile(testDbName, { encoding: 'utf-8' }).then(JSON.parse)
      ).resolves.toStrictEqual({
        '90b3d51f30000001': {
          digitalSignature: {
            '93850740595185438017946775787620281288': {
              role: 1,
              certificate: expect.stringContaining(
                org_90b3d51f30000001_ds_cert.slice(-20)
              ),
              privateKey: expect.stringContaining(
                org_90b3d51f30000001_ds_key.slice(-20)
              ),
            },
          },
        },
      })
    })

    test('push-cert-key-sequential', async () => {
      await expect(stat(testDbName)).rejects.toMatchObject({ code: 'ENOENT' })
      const keystore = new db.KeyStoreDB(testDbName)
      const x509_ds = new X509Certificate(
        Buffer.from(org_90b3d51f30000001_ds_cert, 'base64')
      )
      const key_ds = createPrivateKey({
        key: Buffer.from(org_90b3d51f30000001_ds_key, 'base64'),
        format: 'der',
        type: 'pkcs8',
      })
      expect(
        keystore.push({
          certificate: x509_ds,
        })
      ).toBeDefined()
      expect(
        keystore.push({
          meta: {
            eui: '90-B3-D5-1F-30-00-00-01',
            serial: BigInt('93850740595185438017946775787620281288'),
            keyUsage: [KeyUsage.digitalSignature],
            role: 1,
          },
          private: key_ds,
        })
      ).toBeDefined()
      await expect(
        readFile(testDbName, { encoding: 'utf-8' }).then(JSON.parse)
      ).resolves.toStrictEqual({
        '90b3d51f30000001': {
          digitalSignature: {
            '93850740595185438017946775787620281288': {
              role: 1,
              certificate: expect.stringContaining(
                org_90b3d51f30000001_ds_cert.slice(-20)
              ),
              privateKey: expect.stringContaining(
                org_90b3d51f30000001_ds_key.slice(-20)
              ),
            },
          },
        },
      })
    })

    test('push-cert-key-sequential-missing-role', async () => {
      await expect(stat(testDbName)).rejects.toMatchObject({ code: 'ENOENT' })
      const keystore = new db.KeyStoreDB(testDbName)
      const x509_ds = new X509Certificate(
        Buffer.from(org_90b3d51f30000001_ds_cert, 'base64')
      )
      const key_ds = createPrivateKey({
        key: Buffer.from(org_90b3d51f30000001_ds_key, 'base64'),
        format: 'der',
        type: 'pkcs8',
      })
      expect(
        keystore.push({
          certificate: x509_ds,
        })
      ).toBeDefined()
      expect(
        keystore.push({
          meta: {
            eui: '90-B3-D5-1F-30-00-00-01',
            serial: BigInt('93850740595185438017946775787620281288'),
            keyUsage: [KeyUsage.digitalSignature],
          },
          private: key_ds,
        })
      ).toBeDefined()
      await expect(
        readFile(testDbName, { encoding: 'utf-8' }).then(JSON.parse)
      ).resolves.toStrictEqual({
        '90b3d51f30000001': {
          digitalSignature: {
            '93850740595185438017946775787620281288': {
              role: 1,
              certificate: expect.stringContaining(
                org_90b3d51f30000001_ds_cert.slice(-20)
              ),
              privateKey: expect.stringContaining(
                org_90b3d51f30000001_ds_key.slice(-20)
              ),
            },
          },
        },
      })
    })

    test('push-cert-key-multiple-usage', async () => {
      await expect(stat(testDbName)).rejects.toMatchObject({ code: 'ENOENT' })
      const keystore = new db.KeyStoreDB(testDbName)
      const x509_ds = new X509Certificate(
        Buffer.from(org_90b3d51f30010000_ds_cert, 'base64')
      )
      const key_ds = createPrivateKey({
        key: Buffer.from(org_90b3d51f30010000_ds_key, 'base64'),
        format: 'der',
        type: 'pkcs8',
      })
      const x509_ka = new X509Certificate(
        Buffer.from(org_90b3d51f30010000_ka_cert, 'base64')
      )
      const key_ka = createPrivateKey({
        key: Buffer.from(org_90b3d51f30010000_ka_key, 'base64'),
        format: 'der',
        type: 'pkcs8',
      })
      expect(
        keystore.push({
          certificate: x509_ds,
          private: key_ds,
        })
      ).toBeDefined()
      expect(
        keystore.push({
          certificate: x509_ka,
          private: key_ka,
        })
      ).toBeDefined()
      await expect(
        readFile(testDbName, { encoding: 'utf-8' }).then(JSON.parse)
      ).resolves.toStrictEqual({
        '90b3d51f30010000': {
          digitalSignature: {
            '105986833131214866166891566273223584671': {
              role: 2,
              certificate: expect.stringContaining(
                org_90b3d51f30010000_ds_cert.slice(-20)
              ),
              privateKey: expect.stringContaining(
                org_90b3d51f30010000_ds_key.slice(-20)
              ),
            },
          },
          keyAgreement: {
            '78705613441713544701898588866012598037': {
              role: 2,
              certificate: expect.stringContaining(
                org_90b3d51f30010000_ka_cert.slice(-20)
              ),
              privateKey: expect.stringContaining(
                org_90b3d51f30010000_ka_key.slice(-20)
              ),
            },
          },
        },
      })
    })

    test('push-device-cert-key-multiple-usage', async () => {
      await expect(stat(testDbName)).rejects.toMatchObject({ code: 'ENOENT' })
      const keystore = new db.KeyStoreDB(testDbName)
      const x509_ds = new X509Certificate(
        Buffer.from(device_00db1234567890a4_ds_cert, 'base64')
      )
      const key_ds = createPrivateKey({
        key: Buffer.from(device_00db1234567890a4_ds_key, 'base64'),
        format: 'der',
        type: 'pkcs8',
      })
      const x509_ka = new X509Certificate(
        Buffer.from(device_00db1234567890a4_ka_cert, 'base64')
      )
      const key_ka = createPrivateKey({
        key: Buffer.from(device_00db1234567890a4_ka_key, 'base64'),
        format: 'der',
        type: 'pkcs8',
      })
      expect(
        keystore.push({
          certificate: x509_ds,
          private: key_ds,
        })
      ).toBeDefined()
      expect(
        keystore.push({
          certificate: x509_ka,
          private: key_ka,
        })
      ).toBeDefined()
      await expect(
        readFile(testDbName, { encoding: 'utf-8' }).then(JSON.parse)
      ).resolves.toStrictEqual({
        '00db1234567890a4': {
          digitalSignature: {
            '72119424058103965276745519964518786767': {
              certificate: expect.stringContaining(
                device_00db1234567890a4_ds_cert.slice(-20)
              ),
              privateKey: expect.stringContaining(
                device_00db1234567890a4_ds_key.slice(-20)
              ),
            },
          },
          keyAgreement: {
            '98546831674745780667197067843932045670': {
              certificate: expect.stringContaining(
                device_00db1234567890a4_ka_cert.slice(-20)
              ),
              privateKey: expect.stringContaining(
                device_00db1234567890a4_ka_key.slice(-20)
              ),
            },
          },
        },
      })
    })

    test('push-multiple-eui', async () => {
      await expect(stat(testDbName)).rejects.toMatchObject({ code: 'ENOENT' })
      const keystore = new db.KeyStoreDB(testDbName)
      const x509_ds = new X509Certificate(
        Buffer.from(org_90b3d51f30010000_ds_cert, 'base64')
      )
      const key_ds = createPrivateKey({
        key: Buffer.from(org_90b3d51f30010000_ds_key, 'base64'),
        format: 'der',
        type: 'pkcs8',
      })
      const x509_ka = new X509Certificate(
        Buffer.from(device_00db1234567890a4_ka_cert, 'base64')
      )
      const key_ka = createPrivateKey({
        key: Buffer.from(device_00db1234567890a4_ka_key, 'base64'),
        format: 'der',
        type: 'pkcs8',
      })
      expect(
        keystore.push({
          certificate: x509_ds,
          private: key_ds,
        })
      ).toBeDefined()
      expect(
        keystore.push({
          certificate: x509_ka,
          private: key_ka,
        })
      ).toBeDefined()
      await expect(
        readFile(testDbName, { encoding: 'utf-8' }).then(JSON.parse)
      ).resolves.toStrictEqual({
        '00db1234567890a4': {
          keyAgreement: expect.any(Object),
        },
        '90b3d51f30010000': {
          digitalSignature: expect.any(Object),
        },
      })
    })

    describe('errors', () => {
      test('invalid-keypair', () => {
        const keystore = new db.KeyStoreDB(testDbName)
        const x509_ds = new X509Certificate(
          Buffer.from(org_90b3d51f30010000_ds_cert, 'base64')
        )
        const key_ka = createPrivateKey({
          key: Buffer.from(device_00db1234567890a4_ka_key, 'base64'),
          format: 'der',
          type: 'pkcs8',
        })
        expect(() =>
          keystore.push({
            certificate: x509_ds,
            private: key_ka,
          })
        ).toThrow('key pair')
      })

      test('bad-cert', () => {
        const keystore = new db.KeyStoreDB(testDbName)
        const x509_ds = new X509Certificate(Buffer.from(https_cert, 'base64'))
        expect(() =>
          keystore.push({
            certificate: x509_ds,
          })
        ).toThrow('unable to extract metadata from certificate')
      })

      test('no-keyUsage', () => {
        const keystore = new db.KeyStoreDB(testDbName)
        const key_ka = createPrivateKey({
          key: Buffer.from(device_00db1234567890a4_ka_key, 'base64'),
          format: 'der',
          type: 'pkcs8',
        })
        expect(() =>
          keystore.push({
            meta: {
              eui: '00db1234567890a4',
              serial: BigInt('72119424058103965276745519964518786767'),
              keyUsage: [],
            },
            private: key_ka,
          })
        ).toThrow('unsupported keyUsage')
      })
    })

    test('push-cert-name', async () => {
      await expect(stat(testDbName)).rejects.toMatchObject({ code: 'ENOENT' })
      const keystore = new db.KeyStoreDB(testDbName)
      const x509_ds = new X509Certificate(
        Buffer.from(org_90b3d51f30000001_ds_cert, 'base64')
      )
      expect(
        keystore.push({
          certificate: x509_ds,
          name: 'test name',
        })
      ).toMatchObject({
        eui: new EUI('90b3d51f30000001'),
        role: 1,
        keyUsage: [KeyUsage.digitalSignature],
        serial: BigInt('93850740595185438017946775787620281288'),
      })
      await expect(
        readFile(testDbName, { encoding: 'utf-8' }).then(JSON.parse)
      ).resolves.toStrictEqual({
        '90b3d51f30000001': {
          digitalSignature: {
            '93850740595185438017946775787620281288': {
              role: 1,
              certificate: expect.stringContaining(
                org_90b3d51f30000001_ds_cert.slice(-20)
              ),
              name: 'test name',
            },
          },
        },
      })
    })
  })

  describe('query', () => {
    let keystore: db.KeyStoreDB

    /* preload the datastore with a device and supplier cert */
    beforeEach(() => {
      keystore = new db.KeyStoreDB(testDbName)

      keystore.push({
        certificate: new X509Certificate(
          Buffer.from(device_00db1234567890a4_ka_cert, 'base64')
        ),
      })

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
        name: 'Z1-supplier-ka',
      })

      keystore.push({
        certificate: new X509Certificate(
          Buffer.from(org_90b3d51f30010000_xmlSign_cert, 'base64')
        ),
      })
    })

    test('query-certificate-serial', () => {
      return expect(
        keystore.query({
          serial: BigInt('98546831674745780667197067843932045670'),
          lookup: 'certificate',
        })
      ).resolves.toMatchObject({
        eui: new EUI('00db1234567890a4'),
        serial: BigInt('98546831674745780667197067843932045670'),
        keyUsage: [KeyUsage.keyAgreement],
        certificate: new X509Certificate(
          Buffer.from(device_00db1234567890a4_ka_cert, 'base64')
        ),
      })
    })

    test('query-privateKey-serial-miss', () => {
      return expect(
        keystore.query({
          serial: BigInt('98546831674745780667197067843932045670'),
          lookup: 'privateKey',
        })
      ).resolves.toBeNull()
    })

    test('query-serial-miss', () => {
      return expect(
        keystore.query({
          serial: BigInt('9854683167474567843932045670'),
          lookup: 'certificate',
        })
      ).resolves.toBeNull()
    })

    test('query-certificate-serial-v2', () => {
      return expect(
        keystore.query({
          serial: BigInt('105986833131214866166891566273223584671'),
          lookup: 'certificate',
        })
      ).resolves.toMatchObject({
        serial: BigInt('105986833131214866166891566273223584671'),
        keyUsage: [KeyUsage.digitalSignature],
        certificate: new X509Certificate(
          Buffer.from(org_90b3d51f30000001_ds_cert, 'base64')
        ),
        role: 2,
      })
    })

    test('query-privateKey-serial-v2', () => {
      return expect(
        keystore.query({
          serial: BigInt('105986833131214866166891566273223584671'),
          lookup: 'privateKey',
        })
      ).resolves.toMatchObject({
        serial: BigInt('105986833131214866166891566273223584671'),
        keyUsage: [KeyUsage.digitalSignature],
        privateKey: createPrivateKey({
          key: Buffer.from(org_90b3d51f30000001_ds_key, 'base64'),
          format: 'der',
          type: 'pkcs8',
        }),
        role: 2,
      })
    })

    test('query-certificate-search', () => {
      return expect(
        keystore.query({
          eui: '00-db-12-34-56-78-90-a4',
          keyUsage: KeyUsage.keyAgreement,
          lookup: 'certificate',
        })
      ).resolves.toMatchObject([
        {
          eui: new EUI('00db1234567890a4'),
          serial: BigInt('98546831674745780667197067843932045670'),
          keyUsage: [KeyUsage.keyAgreement],
          certificate: new X509Certificate(
            Buffer.from(device_00db1234567890a4_ka_cert, 'base64')
          ),
        },
      ])
    })

    test('query-privateKey-search-miss', () => {
      return expect(
        keystore.query({
          eui: '00-db-12-34-56-78-90-a4',
          keyUsage: KeyUsage.keyAgreement,
          lookup: 'privateKey',
        })
      ).resolves.toBeNull()
    })

    test('query-search-eui-miss', () => {
      return expect(
        keystore.query({
          eui: 'ff-db-12-34-56-78-90-a4',
          keyUsage: KeyUsage.keyAgreement,
          lookup: 'certificate',
        })
      ).resolves.toBeNull()
    })

    test('query-search-keyUsage-miss', () => {
      return expect(
        keystore.query({
          eui: '00-db-12-34-56-78-90-a4',
          keyUsage: KeyUsage.digitalSignature,
          lookup: 'certificate',
        })
      ).resolves.toBeNull()
    })

    test('query-certificate-role-search', () => {
      return expect(
        keystore.query({
          eui: '90B3D51F30010000',
          keyUsage: KeyUsage.digitalSignature,
          lookup: 'certificate',
          role: 135,
        })
      ).resolves.toMatchObject([
        {
          eui: new EUI('90B3D51F30010000'),
          serial: BigInt('27572613927499351639968579586655397031'),
          keyUsage: [KeyUsage.digitalSignature],
          certificate: new X509Certificate(
            Buffer.from(org_90b3d51f30010000_xmlSign_cert, 'base64')
          ),
          role: 135,
        },
      ])
    })

    test('query-privateKey-search', () => {
      return expect(
        keystore.query({
          eui: '90B3D51F30010000',
          keyUsage: KeyUsage.digitalSignature,
          lookup: 'privateKey',
          role: 2,
        })
      ).resolves.toMatchObject([
        {
          eui: new EUI('90B3D51F30010000'),
          serial: BigInt('105986833131214866166891566273223584671'),
          keyUsage: [KeyUsage.digitalSignature],
          privateKey: createPrivateKey({
            key: Buffer.from(org_90b3d51f30010000_ds_key, 'base64'),
            format: 'der',
            type: 'pkcs8',
          }),
          role: 2,
        },
      ])
    })

    test('query-certificate-search-multiple-results', () => {
      return expect(
        keystore.query({
          eui: '90B3D51F30010000',
          keyUsage: KeyUsage.digitalSignature,
          lookup: 'certificate',
        })
      ).resolves.toMatchObject(
        expect.arrayContaining([
          {
            eui: new EUI('90B3D51F30010000'),
            serial: BigInt('27572613927499351639968579586655397031'),
            keyUsage: [KeyUsage.digitalSignature],
            certificate: expect.any(X509Certificate),
            role: 135,
          },
          {
            eui: new EUI('90B3D51F30010000'),
            serial: BigInt('105986833131214866166891566273223584671'),
            keyUsage: [KeyUsage.digitalSignature],
            certificate: expect.any(X509Certificate),
            role: 2,
          },
        ])
      )
    })

    test('query-certificate-search-name', () => {
      return expect(
        keystore.query({
          eui: '90B3D51F30010000',
          keyUsage: KeyUsage.keyAgreement,
          lookup: 'certificate',
          role: 2,
        })
      ).resolves.toMatchObject(
        expect.arrayContaining([
          expect.objectContaining({
            name: 'Z1-supplier-ka',
          }),
        ])
      )
    })

    test('query-certificate-serial-name', () => {
      return expect(
        keystore.query({
          serial: BigInt('78705613441713544701898588866012598037'),
          lookup: 'certificate',
        })
      ).resolves.toEqual(
        expect.objectContaining({
          name: 'Z1-supplier-ka',
        })
      )
    })
  })
})
