package x509

import (
	"encoding/pem"
	"io/ioutil"
	"testing"
)

func TestParseGMCertificate(t *testing.T) {
	certPEM, err := ioutil.ReadFile("testdata/cfca root cert.pem") // 从文件读取数据
	if err != nil {
		t.Fail()
	}
	certContent, _ := pem.Decode([]byte(certPEM))
	cert, err := ParseCertificate(certContent.Bytes)
	if err != nil {
		t.Errorf("parse GM cert error:%s", err)
		return
	}
	t.Logf("Cert name:%s", cert.Subject.CommonName)
	//_,err= cert.Verify(VerifyOptions{})
	//if err!=nil{
	//	t.Errorf("verify cert error:%s",err)
	//}
}
