// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"sync"
)

var (
	once           sync.Once
	systemRoots    *CertPool
	systemRootsErr error
)

func systemRootsPool() *CertPool {
	once.Do(initSystemRoots)
	return systemRoots
}

func initSystemRoots() {
	systemRoots, systemRootsErr = loadSystemRoots()
	if systemRootsErr != nil {
		systemRoots = nil
	}
	//将CFCA ROOT添加到RootCA
	cfcaPEM := "-----BEGIN CERTIFICATE-----\nMIICqzCCAlCgAwIBAgIQH10EBogVDrqVextSeIErwjAMBggqgRzPVQGDdQUAMC4x\nCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVOUkNBQzEPMA0GA1UEAwwGUk9PVENBMB4X\nDTE1MDcxMDAzMjg0M1oXDTM1MDcwNTAzMjg0M1owWDELMAkGA1UEBhMCQ04xMDAu\nBgNVBAoMJ0NoaW5hIEZpbmFuY2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEX\nMBUGA1UEAwwOQ0ZDQSBDUyBTTTIgQ0EwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNC\nAATuRh26wmtyKNMz+Pmneo3aSme+BCjRon8SvAxZBgLSuIxNUewq4kNujeb1I4A0\nyg7xNcjuOgXglAoQv+Tc+P0Vo4IBIjCCAR4wHwYDVR0jBBgwFoAUTDKxl9kzG8Sm\nBcHG5YtiW/CXdlgwDwYDVR0TAQH/BAUwAwEB/zCBugYDVR0fBIGyMIGvMEGgP6A9\npDswOTELMAkGA1UEBhMCQ04xDjAMBgNVBAoMBU5SQ0FDMQwwCgYDVQQLDANBUkwx\nDDAKBgNVBAMMA2FybDAqoCigJoYkaHR0cDovL3d3dy5yb290Y2EuZ292LmNuL2Fy\nbC9hcmwuY3JsMD6gPKA6hjhsZGFwOi8vbGRhcC5yb290Y2EuZ292LmNuOjM4OS9D\nTj1hcmwsT1U9QVJMLE89TlJDQUMsQz1DTjAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0O\nBBYEFOSO3dSj57YP7h0nls113CUlcmndMAwGCCqBHM9VAYN1BQADRwAwRAIgcb12\n5/U5+MQGf//g3KDhFZHC8Zddm4V3g3yFRvDPNzoCIDUcGrkdD+B4TIUM/DhvQuaX\nkofm32rToZePkvxWGMou\n-----END CERTIFICATE-----"
	//pemData,_:= pem.Decode([]byte(cfcaPEM))
	//cfcaCert,_:= ParseCertificate(pemData.Bytes)
	systemRoots.AppendCertsFromPEM([]byte(cfcaPEM))
}
