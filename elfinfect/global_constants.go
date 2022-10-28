package elfinfect

const (
	WRITE_PAYLOAD                 string = "[+] writing payload into the binary"
	MOD_ENTRY_POINT               string = "[+] Modifed entry point from 0x%x to 0x%x\n"
	PAYLOAD_LEN_PRE_EPILOGUE      string = "[+] Payload size pre-epilogue 0x%x\n"
	PAYLOAD_LEN_POST_EPILOGUE     string = "[+] Payload size post-epilogue 0x%x\n"
	DEFAULT_RESTORATION_APPENDED  string = "[+] Appended default restoration stub"
	GENERATED_AND_APPEND_PIC_STUB string = "[+] Generated and appended position independent return 2 OEP stub to payload"
	INFECTED_NAME                 string = "%s-infected"
)
