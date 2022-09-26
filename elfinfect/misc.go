package elfinfect

import (
	"encoding/hex"
	"fmt"
)

const(
	NoPres InfectOpts = 1 << 7
	NoRest InfectOpts = 1 << 6
	NoRetOEP InfectOpts = 1 << 5
	CtorsHijack InfectOpts = 1 << 4
)

func printPayload(p []byte) {
	fmt.Println("------------------PAYLOAD----------------------------")
	fmt.Printf("%s", hex.Dump(p))
	fmt.Println("--------------------END------------------------------")
}
