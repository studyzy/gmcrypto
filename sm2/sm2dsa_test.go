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
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func TestSm2(t *testing.T) {
	priv, err := GenerateKey(rand.Reader) // 生成密钥对
	fmt.Println(priv)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
	pub := &priv.PublicKey
	msg := []byte("123456")
	d0, err := pub.EncryptAsn1(msg, rand.Reader)
	if err != nil {
		fmt.Printf("Error: failed to encrypt %s: %v\n", msg, err)
		return
	}
	// fmt.Printf("Cipher text = %v\n", d0)
	d1, err := priv.DecryptAsn1(d0)
	if err != nil {
		fmt.Printf("Error: failed to decrypt: %v\n", err)
	}
	fmt.Printf("clear text = %s\n", d1)

	msg, _ = ioutil.ReadFile("ifile")             // 从文件读取数据
	sign, err := priv.Sign(rand.Reader, msg, nil) // 签名
	if err != nil {
		t.Fatal(err)
	}

	err = ioutil.WriteFile("TestResult", sign, os.FileMode(0644))
	if err != nil {
		t.Fatal(err)
	}
	signdata, _ := ioutil.ReadFile("TestResult")
	ok := priv.Verify(msg, signdata, nil) // 密钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}
	pubKey := priv.PublicKey
	ok = pubKey.Verify(msg, signdata, nil) // 公钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}

}

func BenchmarkSM2(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("test")
	priv, err := GenerateKey(nil) // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sign, err := priv.Sign(nil, msg, nil) // 签名
		if err != nil {
			t.Fatal(err)
		}
		priv.Verify(msg, sign, nil) // 密钥验证
	}
}
