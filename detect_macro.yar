rule detect_macro

{

meta:
    description = "Rule to detect whether there is a macro or not in the document"

strings:
    $s1 = "VbaProject" ascii nocase 
    $s2 = "00 41 74 74 72 69 62 75 74 00"
    $t1 = "Auto_Open" ascii nocase
    $t2 = "Macros" wide nocase 

condition:
    (uint32be(0) == 0x504B0304 or
    uint32be(0) == 0xD0CF11E0) and (any of ($s*) or all of ($t*))
}
