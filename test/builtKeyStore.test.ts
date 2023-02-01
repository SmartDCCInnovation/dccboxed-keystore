/*
 * Created on Wed Feb 01 2023
 *
 * Copyright (c) 2023 Smart DCC Limited
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

import { EUI, KeyUsage } from '../src/certificateMetadata'
import * as db from '../src/db'

interface TestSpec {
  serial: string
  eui: string
  keyUsage: KeyUsage
}

describe('BuiltKeyStore', () => {
  describe('query', () => {
    let keystore: db.KeyStoreDB
    const testSpec: TestSpec[] = [
      // other user
      {
        serial: '90325540810335457430706996363193666853',
        eui: '00db123456780004',
        keyUsage: KeyUsage.digitalSignature,
      },
      {
        serial: '32929455378241508330757616006438899512',
        eui: '00db123456780004',
        keyUsage: KeyUsage.keyAgreement,
      },
      // supplier
      {
        serial: '105986833131214866166891566273223584671',
        eui: '90b3d51f30010000',
        keyUsage: KeyUsage.digitalSignature,
      },
      {
        serial: '78705613441713544701898588866012598037',
        eui: '90b3d51f30010000',
        keyUsage: KeyUsage.keyAgreement,
      },
      // network operator
      {
        serial: '106006686783879999060382759530209331431',
        eui: '90b3d51f30020000',
        keyUsage: KeyUsage.digitalSignature,
      },
      {
        serial: '100975650324440424410683132663933689085',
        eui: '90b3d51f30020000',
        keyUsage: KeyUsage.keyAgreement,
      },
    ]

    /* load keystore from disk fresh every test */
    beforeEach(async () => {
      keystore = await db.KeyStoreDB.new('keystore.json')
    })

    testSpec.forEach((ts) => {
      describe(`${ts.eui}/${ts.serial}`, () => {
        test(`${KeyUsage[ts.keyUsage]}/certificate`, () => {
          return expect(
            keystore.query({
              serial: BigInt(ts.serial),
              lookup: 'certificate',
            })
          ).resolves.toMatchObject({
            eui: new EUI(ts.eui),
            keyUsage: [ts.keyUsage],
          })
        })
        test(`${KeyUsage[ts.keyUsage]}/privateKey`, () => {
          return expect(
            keystore.query({
              serial: BigInt(ts.serial),
              lookup: 'privateKey',
            })
          ).resolves.toMatchObject({
            eui: new EUI(ts.eui),
            keyUsage: [ts.keyUsage],
          })
        })
      })
    })
  })
})
