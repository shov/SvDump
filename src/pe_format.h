#define ZM_SIGNATURE						0x4d5a		
#define MZ_SIGNATURE						0x5a4d		
#define PE_SIGNATURE						0x4550		 
#define IMAGE_FILE_MACHINE_I386				0x014c		// Intel 386.
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC		0x10b		// PE 32
#define SIZEOF_PE_SIGNATURE					0x4
#define IMAGE_SIZEOF_SHORT_NAME			8			// Size of section name
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES	12			// Data Directory Number of element
#define IMAGE_DIRECTORY_ENTRY_IMPORT		1			// Import Directory
#define MAX_NUMBER_OF_SECTIONS			255
#define MAX_DLL_NAME_LEN					255
#define MAX_FUNC_NAME_LEN					255
#define IMAGE_FILE_EXECUTABLE_IMAGE			0x0002		//Mask for Pe File Header Characteristics.
#define SIZEOF_OPT_HEADER					0x60 		//DataDirs[] less
#define SIZEOF_DATADIR_ELEM					0x8
#define FILE_ALIG_MIN						0x200
#define SECT_ALIG_MIN						0x1000
#define WITHOUT_LAST						1
#define HINT_SIZE							0x2
#define ORDINAL_BASE						0x80000000	//The most negative number
#define RADIX16							0x10
#define DEFAULT_DUMP_SIZE					0x106
#define ADDR_BLOCK						0x10
#define QUEST_STR							"??"
#define ZERO_BYTE							0x00
#define SPACE_BYTE							0x20
#define DOT_BYTE							0x2E
#define EH_ERROR							1	
#define EH_WARNING						0
const char WARNING_PREFIX[8] =				"Warning";
const char ERROR_PREFIX[6]	 =				"Error";
#define COL_SIZE							4
#define MAX_SIZE_OF_COLS					16
#define INC								0
#define PRN_SEP							1
#define RESET								2
#define OUT_END							1
#define ADD_SYMB							0
#define PRN_ASCII							1
#define ASCII_SIZE							16
#define QUEST								0
#define TO_NULL							1
// type
typedef unsigned char BYTE;
typedef unsigned short	WORD;
typedef unsigned long	DWORD;

typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    DWORD e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    DWORD   VirtualSize;
    DWORD   VirtualOffset;
    DWORD   RawSize;
    DWORD   RawOffset;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
    DWORD TimeDateStamp;
    WORD OffsetModuleName;
    WORD NumberOfModuleForwarderRefs;
} IMAGE_BOUND_IMPORT_DESCRIPTOR, *PIMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
        DWORD OriginalFirstThunk;
        DWORD TimeDateStamp; 
        DWORD ForwarderChain; // -1 if no forwarders
        DWORD Name;
        DWORD FirstThunk;     // RVA to IAT
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _OFT {
		WORD hint;
		char fname[255]; 
} OFT;

//nezumi's macro
#define Is2power(x) (!(x & (x - 1)))
