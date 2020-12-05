/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sm2

import (
	"bytes"
	"math/big"
	"testing"
)

func TestKEB2(t *testing.T) {
	ida := []byte{'1', '2', '3', '4', '5', '6', '7', '8',
		'1', '2', '3', '4', '5', '6', '7', '8'}
	idb := []byte{'1', '2', '3', '4', '5', '6', '7', '8',
		'1', '2', '3', '4', '5', '6', '7', '8'}
	daBuf := []byte{0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1,
		0x6D, 0xF1, 0x16, 0x49, 0x5F, 0x90, 0x69, 0x52,
		0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C, 0x4A, 0xE1,
		0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29}
	dbBuf := []byte{0x78, 0x51, 0x29, 0x91, 0x7D, 0x45, 0xA9, 0xEA,
		0x54, 0x37, 0xA5, 0x93, 0x56, 0xB8, 0x23, 0x38,
		0xEA, 0xAD, 0xDA, 0x6C, 0xEB, 0x19, 0x90, 0x88,
		0xF1, 0x4A, 0xE1, 0x0D, 0xEF, 0xA2, 0x29, 0xB5}
	raBuf := []byte{0xD4, 0xDE, 0x15, 0x47, 0x4D, 0xB7, 0x4D, 0x06,
		0x49, 0x1C, 0x44, 0x0D, 0x30, 0x5E, 0x01, 0x24,
		0x00, 0x99, 0x0F, 0x3E, 0x39, 0x0C, 0x7E, 0x87,
		0x15, 0x3C, 0x12, 0xDB, 0x2E, 0xA6, 0x0B, 0xB3}

	rbBuf := []byte{0x7E, 0x07, 0x12, 0x48, 0x14, 0xB3, 0x09, 0x48,
		0x91, 0x25, 0xEA, 0xED, 0x10, 0x11, 0x13, 0x16,
		0x4E, 0xBF, 0x0F, 0x34, 0x58, 0xC5, 0xBD, 0x88,
		0x33, 0x5C, 0x1F, 0x9D, 0x59, 0x62, 0x43, 0xD6}

	expk := []byte{0x6C, 0x89, 0x34, 0x73, 0x54, 0xDE, 0x24, 0x84,
		0xC6, 0x0B, 0x4A, 0xB1, 0xFD, 0xE4, 0xC6, 0xE5}

	curve := P256Sm2()
	curve.ScalarBaseMult(daBuf)
	da := new(PrivateKey)
	da.PublicKey.Curve = curve
	da.D = new(big.Int).SetBytes(daBuf)
	da.PublicKey.X, da.PublicKey.Y = curve.ScalarBaseMult(daBuf)

	db := new(PrivateKey)
	db.PublicKey.Curve = curve
	db.D = new(big.Int).SetBytes(dbBuf)
	db.PublicKey.X, db.PublicKey.Y = curve.ScalarBaseMult(dbBuf)

	ra := new(PrivateKey)
	ra.PublicKey.Curve = curve
	ra.D = new(big.Int).SetBytes(raBuf)
	ra.PublicKey.X, ra.PublicKey.Y = curve.ScalarBaseMult(raBuf)

	rb := new(PrivateKey)
	rb.PublicKey.Curve = curve
	rb.D = new(big.Int).SetBytes(rbBuf)
	rb.PublicKey.X, rb.PublicKey.Y = curve.ScalarBaseMult(rbBuf)

	k1, Sb, S2, err := KeyExchangeB(16, ida, idb, db, &da.PublicKey, rb, &ra.PublicKey, nil)
	if err != nil {
		t.Error(err)
	}
	k2, S1, Sa, err := KeyExchangeA(16, ida, idb, da, &db.PublicKey, ra, &rb.PublicKey, nil)
	if err != nil {
		t.Error(err)
	}
	if bytes.Compare(k1, k2) != 0 {
		t.Error("key exchange differ")
	}
	if bytes.Compare(k1, expk) != 0 {
		t.Errorf("expected %x, found %x", expk, k1)
	}
	if bytes.Compare(S1, Sb) != 0 {
		t.Error("hash verfication failed")
	}
	if bytes.Compare(Sa, S2) != 0 {
		t.Error("hash verfication failed")
	}
}
