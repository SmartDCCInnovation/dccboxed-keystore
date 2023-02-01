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

import { argv as _argv, exit } from 'process'
import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import got from 'got'
import { parse as contentType } from 'content-type'
import AdmZip from 'adm-zip'
import { dirname } from 'node:path/posix'
import { createPrivateKey, X509Certificate } from 'crypto'
import { query } from '../src/certificateSearch'
import { stat } from 'fs/promises'
import { KeyStoreDB } from '../src/db'
import { KeyUsage } from '../src/certificateMetadata'

yargs(hideBin(_argv))
  .command(
    ['build <boxedAddress> [output] [options]', '$0'],
    'build a json keystore database from a DCC Boxed server by downloading the crypto.zip package',
    (yargs) =>
      yargs
        .positional('boxedAddress', {
          describe: 'ip address of DCC Boxed server',
          type: 'string',
        })
        .positional('output', {
          describe: 'output filename (json)',
          type: 'string',
          default: 'keystore.json',
        })
        .option('serial', {
          describe:
            'certificate serial numbers to lookup from local smki service',
          type: 'array',
        }),
    async (args) => {
      if (
        await stat(args.output)
          .then(() => true)
          .catch(() => false)
      ) {
        console.log(`[E] output file ${args.output} already exists`)
        return
      }
      const db = await KeyStoreDB.new(args.output)
      console.log(`[*] server: ${args.boxedAddress}`)
      console.log(`[*] checking for: org-crypto.zip`)
      const result = await got(
        `http://${args.boxedAddress}/assets/crypto/org-crypto.zip`,
        {
          timeout: { lookup: 500, connect: 1000, request: 5000 },
          method: 'HEAD',
          throwHttpErrors: false,
        }
      )
      if (result.statusCode !== 200) {
        console.log(
          `[E] request was not successful: ${
            result.errored ?? result.statusCode
          }`
        )
        exit(1)
      }
      if (
        result.headers['content-type'] === undefined ||
        result.headers['content-length'] === undefined
      ) {
        console.log('[E] unexpected result returned from server')
        exit(1)
      }
      const ct = contentType(result.headers['content-type'])
      if (ct.type !== 'application/zip') {
        console.log(`[E] expected zip file, received: ${ct.type}`)
        exit(1)
      }
      if (Number(result.headers['content-length']) <= 0) {
        console.log(
          `[E] expected content length > 0: ${result.headers['content-length']}`
        )
        exit(1)
      }
      console.log(
        `[*] found file with size ${result.headers['content-length']}`
      )
      const resultCrypto = await got(
        `http://${args.boxedAddress}/assets/crypto/org-crypto.zip`,
        {
          timeout: { lookup: 500, connect: 1000, request: 5000 },
          method: 'GET',
          responseType: 'buffer',
          headers: { 'Accept-Encoding': 'identity' },
        }
      )
      if (
        resultCrypto.body.length !== Number(result.headers['content-length'])
      ) {
        console.log(
          `[E] received content length not as expected: ${resultCrypto.body.length}`
        )
        exit(1)
      }

      const zip = new AdmZip(resultCrypto.body, { readEntries: true })
      await Promise.all(
        zip.getEntries().map(async (e) => {
          if (
            !e.isDirectory &&
            e.name.endsWith('.pem') &&
            dirname(e.entryName).search('cert') >= 0
          ) {
            console.log(`[*] found: ${e.name}`)
            const keyFileName = e.entryName
              .replace(/\/cert\//, '/key/')
              .replace(/.pem$/, '.key')
            const keyEntry = zip.getEntry(keyFileName)
            if (keyEntry === null) {
              console.log(`[W] could not find ${keyFileName}`)
              return
            }
            const certPem = e.getData()
            const certificate = new X509Certificate(certPem)
            const privKeyPem = keyEntry.getData()
            const privKey = createPrivateKey(privKeyPem)
            if (!certificate.checkPrivateKey(privKey)) {
              console.log(`[W] failed pub/private key check for ${e.name}`)
              return
            }
            try {
              const meta = await db.push({
                certificate,
                private: privKey,
                name: e.name.replace(/\.pem$/, ''),
              })
              console.log(
                `[*] stored key pair ${meta.eui.toString()} ${meta.keyUsage.map(
                  (x) => KeyUsage[x]
                )}`
              )
            } catch (err) {
              console.log(`[W] bad org cert ${e.name} ${err}`)
            }
          }
        })
      )

      if (Array.isArray(args.serial)) {
        for (const serial of args.serial) {
          const qr = await query(String(serial), `${args.boxedAddress}`)
          if (qr) {
            db.push({
              certificate: qr?.x509,
            })
            console.log(
              `[*] fetched and stored certificate ${qr.meta.eui.toString()} ${qr.meta.keyUsage.map(
                (x) => KeyUsage[x]
              )}`
            )
          }
        }
      }
    }
  )
  .parse()
