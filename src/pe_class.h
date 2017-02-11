/******************
**    PE_IMAGE   **
******************/
#include "pe_format.h" //constants and WinNT.h structures

class pe_image
{	
	public:
		pe_image(void);
		~pe_image(void);
		int load(char* fname);
		void dump(DWORD e_addr, DWORD size);
		int  import_dir_print(void);

		DWORD get_imagebase(void);
		int already_loaded(int spec);

	private:
		FILE* pe_file;
		DWORD pe_addr;
		DWORD pe_file_size;
		IMAGE_NT_HEADERS32 pe_header;
		IMAGE_SECTION_HEADER* sections;
		IMAGE_IMPORT_DESCRIPTOR id_table;

		
		int   pe_load(FILE* pe_file);
		int   sections_load(FILE* pe_file);
		DWORD rva2raw(DWORD raw, int spec = 0);
		void  rep_aligs(DWORD* FA, DWORD* SA);
		int	  rep_alig(DWORD alig, DWORD spec);
		void f_data_print(DWORD fthunk);
		int	  aligning(DWORD rva, DWORD alig);
		void  err_handler(const char* message, const int spec, int num = -1);
		void separating_output(int spec = 0, DWORD va = 0, int end = 0);
		void ascii_output(int spec, char symb = ZERO_BYTE);
};

