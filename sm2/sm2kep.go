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
	"errors"
	"hash"
	"math/big"

	"github.com/studyzy/gmcrypto/sm3"
)

//**************************Key agreement algorithm**************************//
// KeyExchangeB 协商第二部，用户B调用， 返回共享密钥k
func KeyExchangeB(klen int, ida, idb []byte, priB *PrivateKey, pubA *PublicKey, rpri *PrivateKey, rpubA *PublicKey, hashFn hash.Hash) (k, s1, s2 []byte, err error) {
	return keyExchange(klen, ida, idb, priB, pubA, rpri, rpubA, false, hashFn)
}

// KeyExchangeA 协商第二部，用户A调用，返回共享密钥k
func KeyExchangeA(klen int, ida, idb []byte, priA *PrivateKey, pubB *PublicKey, rpri *PrivateKey, rpubB *PublicKey, hashFn hash.Hash) (k, s1, s2 []byte, err error) {
	return keyExchange(klen, ida, idb, priA, pubB, rpri, rpubB, true, hashFn)
}

// keyExchange 为SM2密钥交换算法的第二部和第三步复用部分，协商的双方均调用此函数计算共同的字节串
// klen: 密钥长度
// ida, idb: 协商双方的标识，ida为密钥协商算法发起方标识，idb为响应方标识
// pri: 函数调用者的密钥
// pub: 对方的公钥
// rpri: 函数调用者生成的临时SM2密钥
// rpub: 对方发来的临时SM2公钥
// thisIsA: 如果是A调用，文档中的协商第三步，设置为true，否则设置为false
// 返回 k 为klen长度的字节串
func keyExchange(klen int, ida, idb []byte, pri *PrivateKey, pub *PublicKey, rpri *PrivateKey, rpub *PublicKey, thisISA bool, hashFn hash.Hash) (k, s1, s2 []byte, err error) {
	curve := P256Sm2()
	N := curve.Params().N
	x2hat := keXHat(rpri.PublicKey.X)
	x2rb := new(big.Int).Mul(x2hat, rpri.D)
	tbt := new(big.Int).Add(pri.D, x2rb)
	tb := new(big.Int).Mod(tbt, N)
	if !curve.IsOnCurve(rpub.X, rpub.Y) {
		err = errors.New("Ra not on curve")
		return
	}
	x1hat := keXHat(rpub.X)
	ramx1, ramy1 := curve.ScalarMult(rpub.X, rpub.Y, x1hat.Bytes())
	vxt, vyt := curve.Add(pub.X, pub.Y, ramx1, ramy1)

	vx, vy := curve.ScalarMult(vxt, vyt, tb.Bytes())
	pza := pub
	if thisISA {
		pza = &pri.PublicKey
	}
	if hashFn == nil {
		hashFn = sm3.New()
	}
	za, err := ZA(pza, ida, hashFn)
	if err != nil {
		return
	}
	zero := new(big.Int)
	if vx.Cmp(zero) == 0 || vy.Cmp(zero) == 0 {
		err = errors.New("V is infinite")
	}
	pzb := pub
	if !thisISA {
		pzb = &pri.PublicKey
	}
	zb, err := ZA(pzb, idb, hashFn)
	k, ok := kdf(klen, vx.Bytes(), vy.Bytes(), za, zb)
	if !ok {
		err = errors.New("kdf: zero key")
		return
	}
	h1 := BytesCombine(vx.Bytes(), za, zb, rpub.X.Bytes(), rpub.Y.Bytes(), rpri.X.Bytes(), rpri.Y.Bytes())
	if !thisISA {
		h1 = BytesCombine(vx.Bytes(), za, zb, rpri.X.Bytes(), rpri.Y.Bytes(), rpub.X.Bytes(), rpub.Y.Bytes())
	}
	hashValue := sm3.Sm3Sum(h1)
	h2 := BytesCombine([]byte{0x02}, vy.Bytes(), hashValue)
	S1 := sm3.Sm3Sum(h2)
	h3 := BytesCombine([]byte{0x03}, vy.Bytes(), hashValue)
	S2 := sm3.Sm3Sum(h3)
	return k, S1, S2, nil
}

func kdf(length int, x ...[]byte) ([]byte, bool) {
	var c []byte

	ct := 1
	h := sm3.New()
	for i, j := 0, (length+31)/32; i < j; i++ {
		h.Reset()
		for _, xx := range x {
			h.Write(xx)
		}
		h.Write(intToBytes(ct))
		hash := h.Sum(nil)
		if i+1 == j && length%32 != 0 {
			c = append(c, hash[:length%32]...)
		} else {
			c = append(c, hash...)
		}
		ct++
	}
	for i := 0; i < length; i++ {
		if c[i] != 0 {
			return c, true
		}
	}
	return c, false
}

// keXHat 计算 x = 2^w + (x & (2^w-1))
// 密钥协商算法辅助函数
func keXHat(x *big.Int) (xul *big.Int) {
	buf := x.Bytes()
	for i := 0; i < len(buf)-16; i++ {
		buf[i] = 0
	}
	if len(buf) >= 16 {
		c := buf[len(buf)-16]
		buf[len(buf)-16] = c & 0x7f
	}

	r := new(big.Int).SetBytes(buf)
	_2w := new(big.Int).SetBytes([]byte{
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return r.Add(r, _2w)
}
