#pragma once

ULONG_PTR NTAPI FindObjectByNameHook(
    _In_ PCSTR pObjectName,
    _In_ ULONG_PTR RootDir,
    _In_ ULONG_PTR /*Unused*/	//required to have the same prototype as the orginal function
);

struct SymbolInfo_t {
    ULONG       SizeOfStruct;
    ULONG       TypeIndex;        // Type Index of symbol
    ULONG64     Reserved[2];
    ULONG       Index;
    ULONG       Size;
    ULONG64     ModBase;          // Base Address of module comtaining this symbol
    ULONG       Flags;
    ULONG64     Value;            // Value of symbol, ValuePresent should be 1
    ULONG64     Address;          // Address of symbol including base address of module
    ULONG       Register;         // register holding value or pointer to value
    ULONG       Scope;            // scope of the symbol
    ULONG       Tag;              // pdb classification
    ULONG       NameLen;          // Actual length of name
    ULONG       MaxNameLen;
    CHAR        Name[100];          // Name of symbol
};

