#pragma once

//
// Object Directory Entry Structure
//
typedef struct _OBJECT_DIRECTORY_ENTRY {
    ULONG_PTR ChainLink; //struct _OBJECT_DIRECTORY_ENTRY* 
    ULONG_PTR Object;
    ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, * POBJECT_DIRECTORY_ENTRY;

#define NUMBER_HASH_BUCKETS 37

typedef struct _OBJECT_DIRECTORY {
    ULONG_PTR HashBuckets[NUMBER_HASH_BUCKETS]; //struct _OBJECT_DIRECTORY_ENTRY*
    //... unused
} OBJECT_DIRECTORY, * POBJECT_DIRECTORY;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT* Buffer;
#else // MIDL_PASS
    ULONG_PTR  Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;

typedef struct _OBJECT_HEADER_NAME_INFO {
    POBJECT_DIRECTORY Directory;
    UNICODE_STRING Name;
    ULONG QueryReferences;
#if DBG
    ULONG Reserved2;
    LONG DbgDereferenceCount;
#ifdef _WIN64
    ULONG64  Reserved3;   // Win64 requires these structures to be 16 byte aligned.
#endif
#endif
} OBJECT_HEADER_NAME_INFO, * POBJECT_HEADER_NAME_INFO;