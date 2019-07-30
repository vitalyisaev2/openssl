package openssl

// #include "shim.h"
import "C"
import (
	"fmt"
	"runtime"
	"unsafe"
)

// DigestType represents the hashing algorithm supported by OpenSSL
type DigestType int

const (
	Digest_BLAKE2B_512 DigestType = iota
	Digest_BLAKE2S_256
	Digest_GOST
	Digest_MD2
	Digest_MD4
	Digest_MD5
	Digest_RMD160
	Digest_SHA1
	Digest_SHA224
	Digest_SHA256
	Digest_SHA384
	Digest_SHA512
	Digest_SHA512_224
	Digest_SHA512_256
	Digest_SHA3_224
	Digest_SHA3_256
	Digest_SHA3_384
	Digest_SHA3_512
	Digest_SHAKE128
	Digest_SHAKE256
)

func (dt DigestType) Size() int {
	var bits int
	switch dt {
	case Digest_BLAKE2B_512:
		bits = 512
	case Digest_BLAKE2S_256:
		bits = 256
	case Digest_GOST:
		bits = 256
	case Digest_MD2:
		bits = 128
	case Digest_MD4:
		bits = 128
	case Digest_MD5:
		bits = 128
	case Digest_RMD160:
		bits = 160
	case Digest_SHA1:
		bits = 160
	case Digest_SHA224:
		bits = 224
	case Digest_SHA256:
		bits = 256
	case Digest_SHA384:
		bits = 384
	case Digest_SHA512:
		bits = 512
	case Digest_SHA512_224:
		bits = 224
	case Digest_SHA512_256:
		bits = 256
	case Digest_SHA3_224:
		bits = 224
	case Digest_SHA3_256:
		bits = 256
	case Digest_SHA3_384:
		bits = 384
	case Digest_SHA3_512:
		bits = 512
	case Digest_SHAKE128:
		bits = 128
	case Digest_SHAKE256:
		bits = 256
	}
	return bits / 8
}

func (dt DigestType) BlockSize() int {
	var bits int
	switch dt {
	case Digest_BLAKE2B_512:
		bits = 1024
	case Digest_BLAKE2S_256:
		bits = 512
	case Digest_GOST:
		bits = 256
	case Digest_MD2:
		bits = 128
	case Digest_MD4:
		bits = 512
	case Digest_MD5:
		bits = 512
	case Digest_RMD160:
		bits = 512
	case Digest_SHA1:
		bits = 512
	case Digest_SHA224:
		bits = 512
	case Digest_SHA256:
		bits = 512
	case Digest_SHA384:
		bits = 1024
	case Digest_SHA512:
		bits = 1024
	case Digest_SHA512_224:
		bits = 1024
	case Digest_SHA512_256:
		bits = 1024
	case Digest_SHA3_224:
		bits = 1124
	case Digest_SHA3_256:
		bits = 1088
	case Digest_SHA3_384:
		bits = 832
	case Digest_SHA3_512:
		bits = 576
	case Digest_SHAKE128:
		bits = 1344
	case Digest_SHAKE256:
		bits = 1088
	}
	return bits / 8
}

func (dt DigestType) String() string {
	switch dt {
	case Digest_BLAKE2B_512:
		return "BLAKE2B_512"
	case Digest_BLAKE2S_256:
		return "BLAKE2S_256"
	case Digest_GOST:
		return "GOST"
	case Digest_MD2:
		return "MD2"
	case Digest_MD4:
		return "MD4"
	case Digest_MD5:
		return "MD5"
	case Digest_RMD160:
		return "RMD160"
	case Digest_SHA1:
		return "SHA1"
	case Digest_SHA224:
		return "SHA224"
	case Digest_SHA256:
		return "SHA256"
	case Digest_SHA384:
		return "SHA384"
	case Digest_SHA512:
		return "SHA512"
	case Digest_SHA512_224:
		return "SHA512_224"
	case Digest_SHA512_256:
		return "SHA512_256"
	case Digest_SHA3_224:
		return "SHA3_224"
	case Digest_SHA3_256:
		return "SHA3_256"
	case Digest_SHA3_384:
		return "SHA3_384"
	case Digest_SHA3_512:
		return "SHA3_512"
	case Digest_SHAKE128:
		return "SHAKE128"
	case Digest_SHAKE256:
		return "SHAKE256"
	default:
		return "UNKNOWN"
	}
}

func (dt DigestType) evpMP() (evpMD *C.EVP_MD) {
	switch dt {
	case Digest_BLAKE2B_512:
		evpMD = C.X_EVP_blake2b512()
	case Digest_BLAKE2S_256:
		evpMD = C.X_EVP_blake2s256()
	case Digest_GOST:
		panic("Not implemented yet")
	case Digest_MD2:
		evpMD = C.X_EVP_md2()
	case Digest_MD4:
		evpMD = C.X_EVP_md4()
	case Digest_MD5:
		evpMD = C.X_EVP_md5()
	case Digest_RMD160:
		evpMD = C.X_EVP_ripemd160()
	case Digest_SHA1:
		evpMD = C.X_EVP_sha1()
	case Digest_SHA224:
		evpMD = C.X_EVP_sha224()
	case Digest_SHA256:
		evpMD = C.X_EVP_sha256()
	case Digest_SHA384:
		evpMD = C.X_EVP_sha384()
	case Digest_SHA512:
		evpMD = C.X_EVP_sha512()
	case Digest_SHA512_224:
		evpMD = C.X_EVP_sha512_224()
	case Digest_SHA512_256:
		evpMD = C.X_EVP_sha512_256()
	case Digest_SHA3_224:
		evpMD = C.X_EVP_sha3_224()
	case Digest_SHA3_256:
		evpMD = C.X_EVP_sha3_256()
	case Digest_SHA3_384:
		evpMD = C.X_EVP_sha3_384()
	case Digest_SHA3_512:
		evpMD = C.X_EVP_sha3_512()
	case Digest_SHAKE128:
		evpMD = C.X_EVP_shake128()
	case Digest_SHAKE256:
		evpMD = C.X_EVP_shake256()
	default:
		panic("Not implemented yet ")
	}
	return
}

// DigestComputer is a generic structure to compute message digest
// with any hash function supported by OpenSSL
type DigestComputer struct {
	ctx        *C.EVP_MD_CTX
	engine     *Engine
	digestType DigestType
}

func NewDigestComputer(digestType DigestType) (*DigestComputer, error) {
	return NewDigestComputerWithEngine(nil, digestType)
}

func NewDigestComputerWithEngine(e *Engine, digestType DigestType) (*DigestComputer, error) {
	hash := &DigestComputer{engine: e, digestType: digestType}
	hash.ctx = C.X_EVP_MD_CTX_new()
	if hash.ctx == nil {
		return nil, fmt.Errorf("openssl: %s: unable to allocate ctx", digestType.String())
	}
	runtime.SetFinalizer(hash, func(hash *DigestComputer) { hash.Close() })
	if err := hash.Reset(); err != nil {
		return nil, err
	}
	return hash, nil
}

func (s *DigestComputer) Close() {
	if s.ctx != nil {
		C.X_EVP_MD_CTX_free(s.ctx)
		s.ctx = nil
	}
}

func (s *DigestComputer) Reset() error {
	if 1 != C.X_EVP_DigestInit_ex(s.ctx, s.digestType.evpMP(), engineRef(s.engine)) {
		return fmt.Errorf("openssl: %v: cannot init digestType ctx", s.digestType.String())
	}
	return nil
}

func (s *DigestComputer) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if 1 != C.X_EVP_DigestUpdate(s.ctx, unsafe.Pointer(&p[0]),
		C.size_t(len(p))) {
		return 0, fmt.Errorf("openssl: %v: cannot update digestType", s.digestType.String())
	}
	return len(p), nil
}

func (s *DigestComputer) Sum() ([]byte, error) {
	result := make([]byte, s.digestType.Size())
	if 1 != C.X_EVP_DigestFinal_ex(s.ctx,
		(*C.uchar)(unsafe.Pointer(&result[0])), nil) {
		return result, fmt.Errorf("openssl: %v: cannot finalize ctx", s.digestType.String())
	}
	return result, s.Reset()
}
