package GoCBDC

import (
	"Asyn_CBDC/enroll"
	"Asyn_CBDC/offlinetx"
	"Asyn_CBDC/onlinetx"
	"bytes"

	log "github.com/consensys/gnark/logger"
)

func GO_CBDC() string {
	output := "enroll:\n"
	buf := new(bytes.Buffer)
	log.SetOutput(buf)
	enroll.T_Enroll()
	output += buf.String()
	//cmpplatypus.Holdinglimit() //11584
	//utils.T_enc()
	output += "\noffline:\n"
	buf = new(bytes.Buffer)
	log.SetOutput(buf)
	offlinetx.T_OfflineTx()
	output += buf.String()
	output += "\nonline:\n"

	output += onlinetx.Verify()

	return output
}

// //export GO_CBDC
// func GO_CBDC() *C.char {
// 	output := "enroll:\n"
// 	buf := new(bytes.Buffer)
// 	log.SetOutput(buf)
// 	enroll.T_Enroll()
// 	output += buf.String()
// 	//cmpplatypus.Holdinglimit() //11584
// 	//utils.T_enc()
// 	output += "\noffline:\n"
// 	buf = new(bytes.Buffer)
// 	log.SetOutput(buf)
// 	offlinetx.T_OfflineTx()
// 	output += buf.String()
// 	output += "\nonline:\n"

// 	output += onlinetx.Verify()

// 	cOutPut := C.CString(output)
// 	return cOutPut
// }
