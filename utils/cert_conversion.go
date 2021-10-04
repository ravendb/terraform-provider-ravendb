package utils


//#cgo CFLAGS: "-IC:/Program Files/OpenSSL-Win64/include"
//#cgo LDFLAGS: "-LC:/Program Files/OpenSSL-Win64/lib" -llibcrypto
// #include "pfx.h"
import "C"

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

var initialized bool
// from:
// https://github.com/spacemonkeygo/openssl/blob/c2dcc5cca94ac8f7f3f0c20e20050d4cce9d9730/init.go
func errorFromErrorQueue() string {
	if initialized == false {
		initialized = true
		C.init_errors()
	}
	var errs []string
	for {
		err := C.ERR_get_error()
		if err == 0 {
			break
		}
		errs = append(errs, fmt.Sprintf("%s:%s:%s",
			C.GoString(C.ERR_lib_error_string(err)),
			C.GoString(C.ERR_func_error_string(err)),
			C.GoString(C.ERR_reason_error_string(err))))
	}
	return fmt.Sprintf("SSL errors: %s", strings.Join(errs, "\n"))
}

func PfxToPem(pfx []byte) (keyBuf []byte, crtBuf []byte, err error) {
	var key *C.void
	var crt *C.void
	rc := C.pfx_to_pem(unsafe.Pointer(&pfx[0]), C.long(len(pfx)), nil,
		(*unsafe.Pointer)(unsafe.Pointer(&key)),
		(*unsafe.Pointer)(unsafe.Pointer(&crt)))

	if rc != nil {
		err = errors.New(C.GoString(rc) + "\n" + errorFromErrorQueue())
		return
	}
	defer C.free_pem(unsafe.Pointer(key))
	defer C.free_pem(unsafe.Pointer(crt))

	size := C.get_pem_size(unsafe.Pointer(key))
	keyBuf = make([]byte, int(size))
	C.copy_pem_to(unsafe.Pointer(key), unsafe.Pointer(&keyBuf[0]), size)

	size = C.get_pem_size(unsafe.Pointer(key))
	crtBuf = make([]byte, int(size))
	C.copy_pem_to(unsafe.Pointer(crt), unsafe.Pointer(&crtBuf[0]), size)

	return
}

