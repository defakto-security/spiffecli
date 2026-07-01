package testkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"runtime"
	"strings"
	"sync"
)

var (
	keys          Keys
	rsa2048Bucket bucket[rsa2048KeyType, *rsa.PrivateKey]
	rsa4096Bucket bucket[rsa4096KeyType, *rsa.PrivateKey]
	ec256Bucket   bucket[ec256KeyType, *ecdsa.PrivateKey]
	ec384Bucket   bucket[ec384KeyType, *ecdsa.PrivateKey]
	ed25519Bucket bucket[ed25519KeyType, ed25519.PrivateKey]
)

// RSA2048 returns an 2048-bit RSA key for test use. To reduce the number of
// generated test keys, this function can only be called at package
// initialization time.
func RSA2048() *rsa.PrivateKey {
	checkCaller()
	return keys.RSA2048()
}

// RSA4096 returns an 4096-bit RSA key for test use. To reduce the number of
// generated test keys, this function can only be called at package
// initialization time.
func RSA4096() *rsa.PrivateKey {
	checkCaller()
	return keys.RSA4096()
}

// EC256 returns an EC key on the P-256 curve for test use. To reduce the
// number of generated test keys, this function can only be called at package
// initialization time.
func EC256() *ecdsa.PrivateKey {
	checkCaller()
	return keys.EC256()
}

// EC384 returns an EC key on the P-384 curve for test use. To reduce the
// number of generated test, this function can only be called at package
// initialization time.
func EC384() *ecdsa.PrivateKey {
	checkCaller()
	return keys.EC384()
}

// ED25519 returns an EC key on the P-256 curve for test use. To reduce the
// number of generated test keys, this function can only be called at package
// initialization time.
func ED25519() ed25519.PrivateKey {
	checkCaller()
	return keys.ED25519()
}

type Keys struct {
	mtx        sync.Mutex
	rsa2048Idx int
	rsa4096Idx int
	ec256Idx   int
	ec384Idx   int
	ed25519Idx int
}

func (ks *Keys) RSA2048() *rsa.PrivateKey {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	key, err := rsa2048Bucket.At(ks.rsa2048Idx)
	checkErr(err)
	ks.rsa2048Idx++
	return key
}

func (ks *Keys) RSA4096() *rsa.PrivateKey {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	key, err := rsa4096Bucket.At(ks.rsa4096Idx)
	checkErr(err)
	ks.rsa4096Idx++
	return key
}

func (ks *Keys) EC256() *ecdsa.PrivateKey {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	key, err := ec256Bucket.At(ks.ec256Idx)
	checkErr(err)
	ks.ec256Idx++
	return key
}

func (ks *Keys) EC384() *ecdsa.PrivateKey {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	key, err := ec384Bucket.At(ks.ec384Idx)
	checkErr(err)
	ks.ec384Idx++
	return key
}

func (ks *Keys) ED25519() ed25519.PrivateKey {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	key, err := ed25519Bucket.At(ks.ed25519Idx)
	checkErr(err)
	ks.ed25519Idx++
	return key
}

type rsa2048KeyType struct{}

func (rsa2048KeyType) FileName() string { return "rsa2048.pem" }

func (rsa2048KeyType) GenerateKey() (*rsa.PrivateKey, error) {
	checkGenOK()
	return rsa.GenerateKey(rand.Reader, 2048)
}

type rsa4096KeyType struct{}

func (rsa4096KeyType) FileName() string { return "rsa4096.pem" }

func (rsa4096KeyType) GenerateKey() (*rsa.PrivateKey, error) {
	checkGenOK()
	return rsa.GenerateKey(rand.Reader, 4096)
}

type ec256KeyType struct{}

func (ec256KeyType) FileName() string { return "ec256.pem" }

func (ec256KeyType) GenerateKey() (*ecdsa.PrivateKey, error) {
	checkGenOK()
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

type ec384KeyType struct{}

func (ec384KeyType) FileName() string { return "ec384.pem" }

func (ec384KeyType) GenerateKey() (*ecdsa.PrivateKey, error) {
	checkGenOK()
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

type ed25519KeyType struct{}

func (ed25519KeyType) FileName() string { return "ed25519.pem" }

func (ed25519KeyType) GenerateKey() (ed25519.PrivateKey, error) {
	checkGenOK()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	return key, err
}

func checkCaller() {
	callers := make([]uintptr, 16)
	for {
		n := runtime.Callers(2, callers)
		if n == len(callers) {
			callers = make([]uintptr, len(callers)*2)
			continue
		}
		callers = callers[:n]
		break
	}

	frames := runtime.CallersFrames(callers)
	for {
		frame, _ := frames.Next()
		if frame == (runtime.Frame{}) {
			break
		}
		if strings.HasSuffix(frame.Function, ".init") {
			return
		}
	}
	panic("testkey package functions can only be called at package init time")
}

func checkGenOK() {
	// If we're running in CI/CD, don't generate new test keys. If new keys
	// are needed, they should be auto-generated during local development
	// and committed.
	if os.Getenv("CI") == "true" {
		panic("newly generated test keys should be committed before pushing to CI/CD")
	}
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
