package elfinfect

import (
	"encoding/hex"
	"fmt"
)

func printPayload(p []byte) {
	fmt.Println("------------------PAYLOAD----------------------------")
	fmt.Printf("%s", hex.Dump(p))
	fmt.Println("--------------------END------------------------------")
}
