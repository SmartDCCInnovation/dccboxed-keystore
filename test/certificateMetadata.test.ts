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

import { BERElement } from 'asn1-ts'
import { X509Certificate } from 'crypto'
import * as cm from '../src/certificateMetadata'

describe('normaliseEUI', () => {
  test('defined', () => {
    expect(cm.normaliseEUI).toBeDefined()
  })

  test('hyphen', () => {
    expect(cm.normaliseEUI('11-22-33-44-55-66-77-88')).toBe('1122334455667788')
  })

  test('to-lower-case', () => {
    expect(cm.normaliseEUI('A1-A2-A3-A4-A5-A6-A7-A8')).toBe('a1a2a3a4a5a6a7a8')
  })

  test('space', () => {
    expect(cm.normaliseEUI('11 22 33 44 55 66 77 88')).toBe('1122334455667788')
  })

  test('space-v2', () => {
    expect(cm.normaliseEUI('1\t1\n22      3\t3 44\n55 667  788')).toBe(
      '1122334455667788',
    )
  })

  test('uint8', () => {
    expect(cm.normaliseEUI(Buffer.from('A1A2A3A4A5A6A7A8', 'hex'))).toBe(
      'a1a2a3a4a5a6a7a8',
    )
  })

  test('EUI', () => {
    expect(cm.normaliseEUI(new cm.EUI('A1A2A3A4A5A6A7A8'))).toBe(
      'a1a2a3a4a5a6a7a8',
    )
  })

  describe('error', () => {
    test('too-long', () => {
      expect(() => cm.normaliseEUI('A1-A2-A3-A4-A5-A6-A7-A81')).toThrow(
        'not a valid',
      )
    })

    test('too-long-uint8', () => {
      expect(() =>
        cm.normaliseEUI(Buffer.from('A1A2A3A4A5A6A7A8A9', 'hex')),
      ).toThrow('not a valid')
    })

    test('too-short', () => {
      expect(() => cm.normaliseEUI('A1-A2-A3-A4-A5-A6-A7-A')).toThrow(
        'not a valid',
      )
    })

    test('too-short-uint8', () => {
      expect(() =>
        cm.normaliseEUI(Buffer.from('A1A2A3A4A5A6A7', 'hex')),
      ).toThrow('not a valid')
    })

    test('invalid-chars', () => {
      expect(() => cm.normaliseEUI('A1-A2-A3-A4-A5-A6-A7-G8')).toThrow(
        'not a valid',
      )
    })

    test('empty', () => {
      expect(() => cm.normaliseEUI('')).toThrow('not a valid')
    })

    test('undefined', () => {
      expect(() => cm.normaliseEUI(undefined as unknown as string)).toThrow(
        TypeError,
      )
    })
  })
})

describe('EUI', () => {
  test('defined', () => {
    expect(cm.EUI).toBeDefined()
  })

  test('new', () => {
    expect(new cm.EUI('A1A2A3A4A5A6A7A8')).toBeDefined()
  })

  test('new-invalid-eui', () => {
    expect(() => new cm.EUI('A1A2A3A4A5A6A7A')).toThrow('not a valid')
  })

  test('toString', () => {
    expect(new cm.EUI('A1A2A3A4A5A6A7A8').toString()).toBe('a1a2a3a4a5a6a7a8')
  })

  test('valueOf', () => {
    expect(new cm.EUI('A1A2A3A4A5A6A7A8').valueOf()).toBe('a1a2a3a4a5a6a7a8')
  })

  test('equals-string', () => {
    expect(
      new cm.EUI('A1A2A3A4A5A6A7A8').equals('a1a2a3a4a5a6a7a8'),
    ).toBeTruthy()
  })

  test('equals-buffer', () => {
    expect(
      new cm.EUI('A1A2A3A4A5A6A7A8').equals(
        Buffer.from('A1A2A3A4A5A6A7A8', 'hex'),
      ),
    ).toBeTruthy()
  })

  test('equals-eui', () => {
    expect(
      new cm.EUI('A1A2A3A4A5A6A7A8').equals(
        new cm.EUI('A1-A2-A3-A4-A5-A6-A7-A8'),
      ),
    ).toBeTruthy()
  })

  test('not-equals-string', () => {
    expect(
      new cm.EUI('A1A2A3A4A5A6A7A8').equals('a1a2a3a4a5a6a7a7'),
    ).toBeFalsy()
  })

  test('not-equals-buffer', () => {
    expect(
      new cm.EUI('A1A2A3A4A5A6A7A8').equals(
        Buffer.from('A1A2A3A4A5A6A7A7', 'hex'),
      ),
    ).toBeFalsy()
  })

  test('not-equals-eui', () => {
    expect(
      new cm.EUI('A1A2A3A4A5A6A7A8').equals(
        new cm.EUI('A1-A2-A3-A4-A5-A6-A7-A7'),
      ),
    ).toBeFalsy()
  })

  test('not-equals-invalid', () => {
    expect(new cm.EUI('A1A2A3A4A5A6A7A8').equals('hello world')).toBeFalsy()
  })
})

describe('parseOrganisationSubject', () => {
  test('defined', () => {
    expect(cm.parseOrganisationSubject).toBeDefined()
  })

  test('nominal', () => {
    const root = new BERElement()
    root.fromBytes(
      Buffer.from(
        '303B3118301606035504030C0F47495454455354535550504C494552310B3009060355040B0C02303231123010060355042D03090090B3D51F30010000',
        'hex',
      ),
    )
    expect(cm.parseOrganisationSubject(root.sequence)).toMatchObject({
      eui: new cm.EUI('90 B3 D5 1F 30 01 00 00'),
      role: 2,
    })
  })

  test('nominal-different-order', () => {
    const root = new BERElement()
    root.fromBytes(
      Buffer.from(
        '303B31123010060355042D03090090B3D51F30010000310B3009060355040B0C0230323118301606035504030C0F47495454455354535550504C494552',
        'hex',
      ),
    )
    expect(cm.parseOrganisationSubject(root.sequence)).toMatchObject({
      eui: new cm.EUI('90 B3 D5 1F 30 01 00 00'),
      role: 2,
    })
  })

  test('missing-role', () => {
    const root = new BERElement()
    root.fromBytes(
      Buffer.from(
        '302E3118301606035504030C0F47495454455354535550504C49455231123010060355042D03090090B3D51F30010000',
        'hex',
      ),
    )
    expect(() => cm.parseOrganisationSubject(root.sequence)).toThrow('invalid')
  })

  test('missing-unique-identifier', () => {
    const root = new BERElement()
    root.fromBytes(
      Buffer.from(
        '30273118301606035504030C0F47495454455354535550504C494552310B3009060355040B0C023032',
        'hex',
      ),
    )
    expect(() => cm.parseOrganisationSubject(root.sequence)).toThrow('invalid')
  })

  test('role-non-hex', () => {
    const root = new BERElement()
    root.fromBytes(
      Buffer.from(
        '303B3118301606035504030C0F47495454455354535550504C494552310B3009060355040B0C02304831123010060355042D03090090B3D51F30010000',
        'hex',
      ),
    )
    expect(() => cm.parseOrganisationSubject(root.sequence)).toThrow('invalid')
  })

  test('role-too-long', () => {
    const root = new BERElement()
    root.fromBytes(
      Buffer.from(
        '303C3118301606035504030C0F47495454455354535550504C494552310C300A060355040B0C0330323231123010060355042D03090090B3D51F30010000',
        'hex',
      ),
    )
    expect(() => cm.parseOrganisationSubject(root.sequence)).toThrow('invalid')
  })

  test('id-too-long', () => {
    const root = new BERElement()
    root.fromBytes(
      Buffer.from(
        '303C3118301606035504030C0F47495454455354535550504C494552310B3009060355040B0C02303231133011060355042D030A0090B3D51F30010000ff',
        'hex',
      ),
    )
    expect(() => cm.parseOrganisationSubject(root.sequence)).toThrow('invalid')
  })
})

describe('parseKeyUsageFromExtensions', () => {
  test('defined', () => {
    expect(cm.parseKeyUsageFromExtensions).toBeDefined()
  })

  test('nominal-digitalSignature', () => {
    const root = new BERElement()
    root.fromBytes(
      Buffer.from(
        `\
        a3 59 30 57 30 0e 06 03 55 1d 0f 01 01 ff 04 04 \
        03 02 07 80 30 11 06 03 55 1d 0e 04 0a 04 08 44 \
        89 97 92 d1 96 f4 b8 30 1d 06 03 55 1d 20 01 01 \
        ff 04 13 30 11 30 0f 06 0d 2a 86 3a 00 01 84 8f \
        b9 0f 01 02 01 04 30 13 06 03 55 1d 23 04 0c 30 \
        0a 80 08 4f 56 88 d7 ec 93 3b e2`.replace(/ /g, ''),
        'hex',
      ),
    )
    expect(cm.parseKeyUsageFromExtensions([root])).toMatchObject([
      cm.KeyUsage.digitalSignature,
    ])
  })

  test('nominal-digitalSignature', () => {
    const root = new BERElement()
    root.fromBytes(
      Buffer.from(
        `\
        a3 59 30 57 30 0e 06 03 55 1d 0f 01 01 ff 04 04 \
        03 02 07 80 30 11 06 03 55 1d 0e 04 0a 04 08 44 \
        89 97 92 d1 96 f4 b8 30 1d 06 03 55 1d 20 01 01 \
        ff 04 13 30 11 30 0f 06 0d 2a 86 3a 00 01 84 8f \
        b9 0f 01 02 01 04 30 13 06 03 55 1d 23 04 0c 30 \
        0a 80 08 4f 56 88 d7 ec 93 3b e2`.replace(/ /g, ''),
        'hex',
      ),
    )
    expect(cm.parseKeyUsageFromExtensions([root])).toMatchObject([
      cm.KeyUsage.digitalSignature,
    ])
  })

  test('nominal-keyAgreement', () => {
    const root = new BERElement()
    root.fromBytes(
      Buffer.from(
        `\
        a3 59 30 57 30 0e 06 03 55 1d 0f 01 01 ff 04 04 \
        03 02 03 08 30 11 06 03 55 1d 0e 04 0a 04 08 40 \
        5b 8c 62 68 7d 8f 70 30 1d 06 03 55 1d 20 01 01 \
        ff 04 13 30 11 30 0f 06 0d 2a 86 3a 00 01 84 8f \
        b9 0f 01 02 01 04 30 13 06 03 55 1d 23 04 0c 30 \
        0a 80 08 4f 56 88 d7 ec 93 3b e2`.replace(/ /g, ''),
        'hex',
      ),
    )
    expect(cm.parseKeyUsageFromExtensions([root])).toMatchObject([
      cm.KeyUsage.keyAgreement,
    ])
  })

  test('missing-keyUsage', () => {
    const root = new BERElement()
    root.fromBytes(
      Buffer.from(
        `\
        a3 49 30 47 30 11 06 03 55 1d 0e 04 0a 04 08 40 \
        5b 8c 62 68 7d 8f 70 30 1d 06 03 55 1d 20 01 01 \
        ff 04 13 30 11 30 0f 06 0d 2a 86 3a 00 01 84 8f \
        b9 0f 01 02 01 04 30 13 06 03 55 1d 23 04 0c 30 \
        0a 80 08 4f 56 88 d7 ec 93 3b e2`.replace(/ /g, ''),
        'hex',
      ),
    )
    expect(() => cm.parseKeyUsageFromExtensions([root])).toThrow(
      'keyUsage extension not found',
    )
  })

  test('missing-extensions', () => {
    const root = new BERElement()
    root.fromBytes(
      Buffer.from(
        `\
        a4 49 30 47 30 11 06 03 55 1d 0e 04 0a 04 08 40 \
        5b 8c 62 68 7d 8f 70 30 1d 06 03 55 1d 20 01 01 \
        ff 04 13 30 11 30 0f 06 0d 2a 86 3a 00 01 84 8f \
        b9 0f 01 02 01 04 30 13 06 03 55 1d 23 04 0c 30 \
        0a 80 08 4f 56 88 d7 ec 93 3b e2`.replace(/ /g, ''),
        'hex',
      ),
    )
    expect(() => cm.parseKeyUsageFromExtensions([root])).toThrow(
      'keyUsage extension not found',
    )
  })
})

describe('buildOrgCertificateMetadata', () => {
  test('defined', () => {
    expect(cm.buildOrgCertificateMetadata).toBeDefined()
  })

  test('nominal-supplier1-ka', () => {
    const cert = new X509Certificate(
      Buffer.from(
        `
        MIIBkjCCATigAwIBAgIQOzYmV3Meayu+B4ZQz6FPFTAKBggqhkjOPQQDAjAaMQsw
        CQYDVQQLEwIwNzELMAkGA1UEAxMCWjEwHhcNMTUxMDMwMDAwMDAwWhcNMjUxMDI5
        MjM1OTU5WjAhMQswCQYDVQQLDAIwMjESMBAGA1UELQMJAJCz1R8wAQAAMFkwEwYH
        KoZIzj0CAQYIKoZIzj0DAQcDQgAEknT/+KOvVtawFtOo+mDaPleVUespWBnIDrek
        PzByKyJVBCheSlF2uWM027cuoM/AycbkCgrjwok3w0JY8OhAuqNZMFcwDgYDVR0P
        AQH/BAQDAgMIMBEGA1UdDgQKBAhAW4xiaH2PcDAdBgNVHSABAf8EEzARMA8GDSqG
        OgABhI+5DwECAQQwEwYDVR0jBAwwCoAIT1aI1+yTO+IwCgYIKoZIzj0EAwIDSAAw
        RQIgFr/75lBWSxc8gzYM2B2KIo9qDgZml43a49UDQDJxy9cCIQCcncpTfMwNiHEJ
        MBqualHKnx28X5I+HWDdRugWzqYbDA==`,
        'base64',
      ),
    )
    expect(cm.buildOrgCertificateMetadata(cert)).toMatchObject({
      eui: new cm.EUI('90 B3 D5 1F 30 01 00 00'),
      serial: BigInt('78705613441713544701898588866012598037'),
      role: 2,
      keyUsage: [cm.KeyUsage.keyAgreement],
    })
  })

  test('nominal-supplier1-ds', () => {
    const cert = new X509Certificate(
      Buffer.from(
        `
        MIIBrDCCAVKgAwIBAgIQT7xSUgGh11hsG8HEc03rnzAKBggqhkjOPQQDAjAaMQsw
        CQYDVQQLEwIwNzELMAkGA1UEAxMCWjEwHhcNMTUxMDMwMDAwMDAwWhcNMjUxMDI5
        MjM1OTU5WjA7MRgwFgYDVQQDDA9HSVRURVNUU1VQUExJRVIxCzAJBgNVBAsMAjAy
        MRIwEAYDVQQtAwkAkLPVHzABAAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQw
        wqtaDRMXJv+9qA55KUzDdTRDKj5CRAW5ejq6D/x53OcpslF1Y8t9lYJ+TFC0jLo9
        h9WJPFG5bYfDReNxf4weo1kwVzAOBgNVHQ8BAf8EBAMCB4AwEQYDVR0OBAoECESJ
        l5LRlvS4MB0GA1UdIAEB/wQTMBEwDwYNKoY6AAGEj7kPAQIBBDATBgNVHSMEDDAK
        gAhPVojX7JM74jAKBggqhkjOPQQDAgNIADBFAiEA39CQ51c+r1+oLhqn242f7VEY
        ObV1LVXRAJHyUP3xiiICIF637Dax9BM+UVV9M7WcSe9rvRDpqksdzZKOZbPprdHF`,
        'base64',
      ),
    )
    expect(cm.buildOrgCertificateMetadata(cert)).toMatchObject({
      eui: new cm.EUI('90 B3 D5 1F 30 01 00 00'),
      serial: BigInt('105986833131214866166891566273223584671'),
      role: 2,
      keyUsage: [cm.KeyUsage.digitalSignature],
    })
  })

  test('non-org-certificate', () => {
    const cert = new X509Certificate(
      Buffer.from(
        `
        MIIBoDCCAUagAwIBAgIQSiNt7Xc0UzIiYPfefETBZjAKBggqhkjOPQQDAjAPMQ0w
        CwYDVQQDEwRFMzU3MCAXDTE2MDQwNjAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjAA
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4WwfjNZwHoDL4DG1QJVIbyWwWn6B
        Kt8SJ2ujFyakONVNyEfnK2E3UgibkuL4hT0+Q84PoO9SDlnsMbcsoUkI06OBkDCB
        jTAOBgNVHQ8BAf8EBAMCAwgwEQYDVR0OBAoECEcMHpw5Eh7IMDUGA1UdEQEB/wQr
        MCmgJwYIKwYBBQUHCASgGzAZBg0qhjoAAYSPuQ8BAgIBBAgA2xI0VniQpDAcBgNV
        HSABAf8EEjAQMA4GDCqGOgAB7e5AAQIBBDATBgNVHSMEDDAKgAhH1ArzQSkEoDAK
        BggqhkjOPQQDAgNIADBFAiBtih3M74gET/t+qE6aRYvvCQfYGqUK26lzVBFwhaxF
        ywIhAMWtZ3u/bQs4oFbKuXDQreKUFw2W7kRVbOa8NbYFXR92`,
        'base64',
      ),
    )
    expect(() => cm.buildOrgCertificateMetadata(cert)).toThrow('invalid')
  })

  test('https-cert', () => {
    const cert = new X509Certificate(
      Buffer.from(
        `
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
        1izP8hIwHQ==`,
        'base64',
      ),
    )
    expect(() => cm.buildOrgCertificateMetadata(cert)).toThrow('expected ECDSA')
  })
})

describe('parseSubjectAltNameFromExtensions', () => {
  test('defined', () => {
    expect(cm.parseSubjectAltNameFromExtensions).toBeDefined()
  })

  test('missing-subjectAltName', () => {
    const root = new BERElement()
    root.fromBytes(
      Buffer.from(
        `\
        a3 59 30 57 30 0e 06 03 55 1d 0f 01 01 ff 04 04 \
        03 02 07 80 30 11 06 03 55 1d 0e 04 0a 04 08 44 \
        89 97 92 d1 96 f4 b8 30 1d 06 03 55 1d 20 01 01 \
        ff 04 13 30 11 30 0f 06 0d 2a 86 3a 00 01 84 8f \
        b9 0f 01 02 01 04 30 13 06 03 55 1d 23 04 0c 30 \
        0a 80 08 4f 56 88 d7 ec 93 3b e2`.replace(/ /g, ''),
        'hex',
      ),
    )
    expect(() => cm.parseSubjectAltNameFromExtensions([root])).toThrow(
      'extension not found',
    )
  })

  test('nominal', () => {
    const root = new BERElement()
    root.fromBytes(
      Buffer.from(
        `\
        30 82 01 46 a0 03 02 01 02 02 10 4a 23 6d ed 77 \
        34 53 32 22 60 f7 de 7c 44 c1 66 30 0a 06 08 2a \
        86 48 ce 3d 04 03 02 30 0f 31 0d 30 0b 06 03 55 \
        04 03 13 04 45 33 35 37 30 20 17 0d 31 36 30 34 \
        30 36 30 30 30 30 30 30 5a 18 0f 39 39 39 39 31 \
        32 33 31 32 33 35 39 35 39 5a 30 00 30 59 30 13 \
        06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d \
        03 01 07 03 42 00 04 e1 6c 1f 8c d6 70 1e 80 cb \
        e0 31 b5 40 95 48 6f 25 b0 5a 7e 81 2a df 12 27 \
        6b a3 17 26 a4 38 d5 4d c8 47 e7 2b 61 37 52 08 \
        9b 92 e2 f8 85 3d 3e 43 ce 0f a0 ef 52 0e 59 ec \
        31 b7 2c a1 49 08 d3 a3 81 90 30 81 8d 30 0e 06 \
        03 55 1d 0f 01 01 ff 04 04 03 02 03 08 30 11 06 \
        03 55 1d 0e 04 0a 04 08 47 0c 1e 9c 39 12 1e c8 \
        30 35 06 03 55 1d 11 01 01 ff 04 2b 30 29 a0 27 \
        06 08 2b 06 01 05 05 07 08 04 a0 1b 30 19 06 0d \
        2a 86 3a 00 01 84 8f b9 0f 01 02 02 01 04 08 00 \
        db 12 34 56 78 90 a4 30 1c 06 03 55 1d 20 01 01 \
        ff 04 12 30 10 30 0e 06 0c 2a 86 3a 00 01 ed ee \
        40 01 02 01 04 30 13 06 03 55 1d 23 04 0c 30 0a \
        80 08 47 d4 0a f3 41 29 04 a0`.replace(/ /g, ''),
        'hex',
      ),
    )
    expect(cm.parseSubjectAltNameFromExtensions(root.sequence)).toStrictEqual(
      new cm.EUI('00DB1234567890A4'),
    )
  })

  test('https-cert', () => {
    const root = new BERElement()
    root.fromBytes(
      Buffer.from(
        `
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
        1izP8hIwHQ==`,
        'base64',
      ),
    )
    expect(() =>
      cm.parseSubjectAltNameFromExtensions(root.sequence[0].sequence),
    ).toThrow('hwSerialNum not found')
  })
})

describe('buildDeviceCertificateMetadata', () => {
  test('defined', () => {
    expect(cm.buildDeviceCertificateMetadata).toBeDefined()
  })

  test('nominal', () => {
    const cert = new X509Certificate(
      Buffer.from(
        `
        MIIBoDCCAUagAwIBAgIQSiNt7Xc0UzIiYPfefETBZjAKBggqhkjOPQQDAjAPMQ0w
        CwYDVQQDEwRFMzU3MCAXDTE2MDQwNjAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjAA
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4WwfjNZwHoDL4DG1QJVIbyWwWn6B
        Kt8SJ2ujFyakONVNyEfnK2E3UgibkuL4hT0+Q84PoO9SDlnsMbcsoUkI06OBkDCB
        jTAOBgNVHQ8BAf8EBAMCAwgwEQYDVR0OBAoECEcMHpw5Eh7IMDUGA1UdEQEB/wQr
        MCmgJwYIKwYBBQUHCASgGzAZBg0qhjoAAYSPuQ8BAgIBBAgA2xI0VniQpDAcBgNV
        HSABAf8EEjAQMA4GDCqGOgAB7e5AAQIBBDATBgNVHSMEDDAKgAhH1ArzQSkEoDAK
        BggqhkjOPQQDAgNIADBFAiBtih3M74gET/t+qE6aRYvvCQfYGqUK26lzVBFwhaxF
        ywIhAMWtZ3u/bQs4oFbKuXDQreKUFw2W7kRVbOa8NbYFXR92`,
        'base64',
      ),
    )
    expect(cm.buildDeviceCertificateMetadata(cert)).toMatchObject({
      eui: new cm.EUI('00DB1234567890A4'),
      keyUsage: [cm.KeyUsage.keyAgreement],
      serial: BigInt('98546831674745780667197067843932045670'),
    })
  })
})
