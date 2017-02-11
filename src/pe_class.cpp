/******************
**    PE_IMAGE   **
******************/
#include "stdlib.h"
#include "stdio.h"
#include "pe_class.h"


pe_image::pe_image(void)
{
	pe_file   = NULL;
	sections = NULL;
	pe_header.Signature = NULL;
}

int pe_image::load(char* fname)
{
	if ((pe_file = fopen(fname, "rb")) == NULL)\
	{
		err_handler("File not found!", EH_ERROR);
		return 0;
	}

	if (pe_load(pe_file)) if (sections_load(pe_file)) return 1;
	return 0;
}

int pe_image::pe_load(FILE* pe_file)
{
	fseek(pe_file, 0, SEEK_END);
	pe_file_size = ftell(pe_file);
	fseek(pe_file, 0, SEEK_SET);

	if (pe_file_size < sizeof(IMAGE_NT_HEADERS32)-3)\
	{
		err_handler("Too small file size!", EH_ERROR);
		return 0;
	}

	IMAGE_DOS_HEADER dos_header;
	if (!fread(&dos_header, sizeof(IMAGE_DOS_HEADER), 1, pe_file))\
	{
		err_handler("Can't read DOS header!", EH_ERROR);
		return 0;
	}
		
	if(dos_header.e_magic != MZ_SIGNATURE)
	{
		err_handler("Bad MZ signature! Trying find ZM.", EH_WARNING);
		if(dos_header.e_magic != ZM_SIGNATURE)\
		{
			err_handler("Not executable file!", EH_ERROR);
			return 0;
		}
	}

	pe_addr = dos_header.e_lfanew; //for sections_load() 
	fseek(pe_file, pe_addr, SEEK_SET);

	if(!fread(&pe_header, sizeof(IMAGE_NT_HEADERS32), 1, pe_file))\
	{
		err_handler("Not PE file!", EH_ERROR);
		return 0;
	}

	if(pe_header.Signature != PE_SIGNATURE)\
	{
		err_handler("Bad PE signature!", EH_ERROR);
		return 0;
	}
	
	if(pe_header.FileHeader.Machine != IMAGE_FILE_MACHINE_I386)\
	{
		err_handler("Not for Intel 386 machine!", EH_ERROR);
		return 0;
	}

	if(pe_header.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)\
	{
		err_handler("Not PE32 format!", EH_ERROR);
		return 0;
	}

	if(!(pe_header.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))\
	{	
		err_handler("Not executable file!", EH_ERROR);
		return 0;
	}

	return 1;
}

int pe_image::sections_load(FILE* pe_file)
{
	if(!pe_header.FileHeader.NumberOfSections)\
	{	
		err_handler("Not found declared sections!", EH_ERROR);
		return 0;
	}

	rep_aligs(&pe_header.OptionalHeader.FileAlignment, &pe_header.OptionalHeader.SectionAlignment);

	if(pe_header.FileHeader.NumberOfSections > MAX_NUMBER_OF_SECTIONS)\
		(pe_header.FileHeader.NumberOfSections = MAX_NUMBER_OF_SECTIONS),\
		err_handler("Number of sections exceeded the allowable value, and was fixed to 255!", EH_WARNING);

/*	for validation of sections by checking her definition on entry to pe_header space.
	DWORD real_end_of_pe = pe_addr + SIZEOF_PE_SIGNATURE +\
		sizeof(IMAGE_FILE_HEADER) + SIZEOF_OPT_HEADER +\
		(pe_header.OptionalHeader.NumberOfRvaAndSizes * SIZEOF_DATADIR_ELEM) -\
		SIZEOF_DATADIR_ELEM;
*/

	DWORD addr_of_sections_header = pe_addr + SIZEOF_PE_SIGNATURE +\
		sizeof(IMAGE_FILE_HEADER) + pe_header.FileHeader.SizeOfOptionalHeader;
	fseek(pe_file, addr_of_sections_header, SEEK_SET);
	
	sections = new IMAGE_SECTION_HEADER[pe_header.FileHeader.NumberOfSections+1];//+1 for imaginary MZ-PE section
	for(int i = 0; i < pe_header.FileHeader.NumberOfSections; i++)
	{
		if(!fread((void*)&sections[i], sizeof(IMAGE_SECTION_HEADER), 1, pe_file))\
		{
			err_handler("Can't read the section header #", EH_ERROR, i);
			return 0;
		}

		if(!sections[i].RawOffset && sections[i].VirtualOffset)\
			sections[i].RawSize = 0;									//?? why?
		
		if(sections[i].RawOffset < pe_header.OptionalHeader.FileAlignment)\
			sections[i].RawOffset = 0;
		else sections[i].RawOffset = aligning(sections[i].RawOffset, pe_header.OptionalHeader.FileAlignment);

		if(sections[i].RawSize)\
			sections[i].RawSize = aligning(sections[i].RawSize, pe_header.OptionalHeader.FileAlignment);

		if(sections[i].RawOffset + sections[i].RawSize > pe_file_size)\
			sections[i].RawSize = pe_file_size - sections[i].RawOffset; //if unexpected end of file
		
		//if this (see below) false, virtual offset stand by zero.
		//then OptionalHeader.SizeOfHeader is meaningless, and can't be less than 1;
		if(sections[i].RawOffset || sections[i].VirtualOffset)\
			sections[i].VirtualOffset =  \
			aligning(sections[i].VirtualOffset, pe_header.OptionalHeader.SectionAlignment);
/*
		if((ftell(pe_file) - sizeof(IMAGE_SECTION_HEADER)) < real_end_of_pe)\
			sections[i].RawSize = 0;									//if define section on pe_headers space
		//use real_end_of_pe
*/
		sections[i].VirtualSize = \
			aligning(sections[i].VirtualSize, pe_header.OptionalHeader.SectionAlignment);
	}

	//define MZ-PE as last section
	sections[pe_header.FileHeader.NumberOfSections].RawOffset = 0;
	
	//calculate raw size of MZ-PE "section"
	sections[pe_header.FileHeader.NumberOfSections].RawSize = addr_of_sections_header +\
		pe_header.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);	//don't work, if pe header on end or center of file!!!
	if(sections[pe_header.FileHeader.NumberOfSections].RawSize < pe_header.OptionalHeader.SizeOfHeaders)\
		sections[pe_header.FileHeader.NumberOfSections].RawSize = pe_header.OptionalHeader.SizeOfHeaders;
	//end of calculate MZ-PE "section" raw size

	sections[pe_header.FileHeader.NumberOfSections].VirtualOffset = 0;
	
	//calculate virtual size of MZ-PE "section"
	sections[pe_header.FileHeader.NumberOfSections].VirtualSize =\
		sections[pe_header.FileHeader.NumberOfSections].RawSize;
	sections[pe_header.FileHeader.NumberOfSections].VirtualSize =  \
		aligning(sections[pe_header.FileHeader.NumberOfSections].RawSize,\
		         pe_header.OptionalHeader.SectionAlignment);
	//end of calculate MZ-PE "section" virtual size 

	++pe_header.FileHeader.NumberOfSections;
	
	return 1;
}

void pe_image::rep_aligs(DWORD* FA, DWORD* SA)
{
	if (!((*FA && *SA) && (*FA == *SA) && (*FA > 0)))
	{
		*SA = pe_image::rep_alig(*SA, SECT_ALIG_MIN);
		*FA = pe_image::rep_alig(*FA, FILE_ALIG_MIN);
	}
}

int pe_image::rep_alig(DWORD alig, DWORD spec)
{
	if (alig < spec) return spec;
	while (!Is2power(alig)) alig++;
	return alig;
}

int	  pe_image::aligning(DWORD rva, DWORD alig)
{
	if (rva < alig) return alig;
	if (!(rva % alig)) return rva;
	return rva-(rva % alig)+alig;
}

DWORD pe_image::rva2raw(DWORD rva, int spec)
{
	int snum = -1;

	for (int i = 0; i < pe_header.FileHeader.NumberOfSections; i++)
	{
		if ((rva < sections[i].VirtualOffset+sections[i].VirtualSize)\
								&& (rva >= sections[i].VirtualOffset))
		{
			snum = i;
			break;
		}
	}
	if (snum < 0) return 0;
	if (snum == pe_header.FileHeader.NumberOfSections-1 && spec)\
		return 0; // if choice without last section
	return rva-sections[snum].VirtualOffset+sections[snum].RawOffset;
}

int pe_image::import_dir_print(void)
{
	DWORD id_raw = rva2raw(pe_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if(!id_raw) return 0;
	
	fseek(pe_file, id_raw, SEEK_SET);
	int num_of_id = 0;
	static char dll_name[255];
	DWORD bak_seek;
	int dn_ptr;

	for(;;){
		if(!fread(&id_table, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, pe_file))\
		{
			err_handler("Can't read the import table #", EH_ERROR, num_of_id);
			return 0;
		}
		
		if(!id_table.FirstThunk || !rva2raw(id_table.Name)) break; //whether it is necessary and sufficient condition?
		
		bak_seek = ftell(pe_file);
		/// Read and print DLL Name
			fseek(pe_file, rva2raw(id_table.Name), SEEK_SET);
			dn_ptr = -1;
			do{
				++dn_ptr;
				if(!fread(&dll_name[dn_ptr], sizeof(char), 1, pe_file))\
				{
					err_handler("Can't read Name of DLL #", EH_ERROR, num_of_id);
					return 0;
				}

				if(dn_ptr == MAX_DLL_NAME_LEN)
				{
					err_handler("Name is too long for the DLL #", EH_WARNING, num_of_id);
					dll_name[dn_ptr] = '\0';
				}
			}while(dll_name[dn_ptr]);
			printf("\n-------------------------\n");
			printf("DLL Name: %s\n", dll_name);
		
		/// Read and print Thunk (IAT) array
			printf("\n%-6s| %-25s\n\n", " Hint", "Function Name/ Ordinal");

			if(!id_table.OriginalFirstThunk || !rva2raw(id_table.OriginalFirstThunk, WITHOUT_LAST))\
			{f_data_print(id_table.FirstThunk); printf("\nFunction data was loaded from IAT (Thunks array).\n");}
			else\
			{f_data_print(id_table.OriginalFirstThunk); printf("\nFunction data was loaded from Original Thunks array.\n");}
		///
		fseek(pe_file, bak_seek, SEEK_SET);
		++num_of_id;
	} //end for(;;)
	return 1;	
}


void pe_image::f_data_print(DWORD fthunk)
{

	DWORD bak_seek;
	DWORD thunk;
	int fn_ptr;
	static OFT f_data;

	fseek(pe_file, rva2raw(fthunk), SEEK_SET);
	for(;;){
		if(!fread(&thunk, sizeof(DWORD), 1, pe_file))\
		{	err_handler("Can't read the thunk data!", EH_ERROR);
			return;
		}
		if (!thunk) break;
			
		if (thunk & ORDINAL_BASE)	// Import by Ordinal
		{
			printf("[%-4s]| #%-24d\n", "----", (thunk ^ ORDINAL_BASE));
		} else						// Import by Name
		{	
			if (!rva2raw(thunk)) break;
			
			bak_seek = ftell(pe_file);
			fseek(pe_file, rva2raw(thunk), SEEK_SET);

			if(!fread(&f_data.hint, sizeof(WORD), 1, pe_file))\
			{
				err_handler("Can't read hint data!", EH_ERROR);
				return;
			}
			
			fn_ptr = -1;
			do{	
				++fn_ptr;
	
				if(!fread(&f_data.fname[fn_ptr], sizeof(char), 1, pe_file))\
				{
					err_handler("Can't read function name!", EH_ERROR);
					return;
				}

				if(fn_ptr == MAX_FUNC_NAME_LEN)
				{
					err_handler("Name of function is too long!", EH_WARNING);
					f_data.fname[fn_ptr] = '\0';
				}
			}while(f_data.fname[fn_ptr]);
				printf("[%4d]| %-24s\n", f_data.hint, f_data.fname);
			fseek(pe_file, bak_seek, SEEK_SET);
		}
	} //end for(;;)
}

void pe_image::separating_output(int spec, DWORD va, int end)
{
	static int count = 0;
		 
		 if(spec == INC)   ++count;
	else if(spec == RESET)
	{
		if ((count != MAX_SIZE_OF_COLS) && (count))
		{
			if(count && !(count % COL_SIZE))
			{
				printf("%3c", SPACE_BYTE);
				++count;
			}			
			for(count; count <= MAX_SIZE_OF_COLS; count++)
			{				
				separating_output(PRN_SEP, 0, OUT_END); //then the count can be reset
				if(!count) break;			 	          //then check this
				if(count != MAX_SIZE_OF_COLS) printf("%3c", SPACE_BYTE);
			}
		}
		count = 0;
	}
	//spec == PRN_SEP:
	else if(count == MAX_SIZE_OF_COLS)
	{	
		ascii_output(PRN_ASCII);
		if (!end) printf("\n.%08X ", va);
		count = 0;
	}
	else if(count && !(count % COL_SIZE)) printf("|");
}

void pe_image::ascii_output(int spec, char symb)
{
	static char ascii_str[ASCII_SIZE];
	static int	ascii_ptr = 0;

	if(spec == ADD_SYMB)
	{
		if(symb < SPACE_BYTE) symb = DOT_BYTE; //conversion of ASCII control symbols
		ascii_str[ascii_ptr] = symb;
		++ascii_ptr;
	}
	else
	if (spec == PRN_ASCII)
	{
		for(ascii_ptr; ascii_ptr < ASCII_SIZE; ascii_ptr++)
		{
			ascii_str[ascii_ptr] = SPACE_BYTE;
		}

		for(ascii_ptr = 0; ascii_ptr < ASCII_SIZE; ascii_ptr++)
		{
			printf("%c", ascii_str[ascii_ptr]);
		}

		ascii_ptr = 0;
	}
}

void pe_image::dump(DWORD e_addr, DWORD size)
{	
	BYTE dbyte;

	struct {
		int read_outside_img:1;   
		int read_between_sec:1;
		int superpos_of_sect:1;
	} warning;
	warning.read_outside_img = 0;
	warning.read_between_sec = 0;
	warning.superpos_of_sect = 0;

	int snum_mem = -1;

	printf("\nImage Base: 0x%X\n\n", pe_header.OptionalHeader.ImageBase);
	printf(".%08X ", e_addr); // first VA print
	
	if(e_addr % ADDR_BLOCK) //alignment output
	{
		for(int i = 1; i <= (e_addr % ADDR_BLOCK); i++)
		{
			separating_output(INC);
			printf("%3c", SPACE_BYTE);
			ascii_output(ADD_SYMB, SPACE_BYTE);
			separating_output(PRN_SEP);
		}
	}

	for(size; size > 0; size--)
	{
		separating_output(INC);
		//try to defined the section
		int snum = -1;
		for (int scount = 0; scount < pe_header.FileHeader.NumberOfSections; scount++)
		{	
			if ((e_addr >= sections[scount].VirtualOffset + pe_header.OptionalHeader.ImageBase)\
				&& (e_addr < sections[scount].VirtualOffset\
				+ sections[scount].VirtualSize + pe_header.OptionalHeader.ImageBase))\
				{
					snum = scount;
					break;
				}
		} //end for(scount)

		if ((snum_mem < 0) && (snum >= 0)) snum_mem = snum;

		if (snum < 0) //section wasn't defined, outside image
		{
			if (!warning.read_outside_img)	warning.read_outside_img = 1;
			printf("%02s ", QUEST_STR);
			ascii_output(ADD_SYMB, '?');
			e_addr++;
			separating_output(PRN_SEP, e_addr, (size == OUT_END));
			continue;
		}

		if ((snum_mem >=0) && (snum_mem != snum) && !warning.read_between_sec)\
			warning.read_between_sec= 1;
		
		//try to find physical section
		DWORD raw_e_addr = rva2raw(e_addr - pe_header.OptionalHeader.ImageBase);


		//check on superposition physical sections
		int phsnum = 0;
		for(int scount = 0; scount < pe_header.FileHeader.NumberOfSections; scount++)
		{
			if((raw_e_addr >= sections[scount].RawOffset)\
				&& (raw_e_addr < sections[scount].RawOffset + sections[scount].RawSize))\
			{
				if (!phsnum) phsnum = 1;
				else
				if (!warning.superpos_of_sect) warning.superpos_of_sect = 1;				
			}
		}//end for(scount)
		
		//zero-part of section
		if((raw_e_addr < sections[snum].RawOffset)\
				|| (raw_e_addr >= sections[snum].RawOffset + sections[snum].RawSize))\
		{
			printf("%02X ", ZERO_BYTE);
			ascii_output(ADD_SYMB);
			e_addr++;
			separating_output(PRN_SEP, e_addr, (size == OUT_END));
			continue;
		}

		//read data byte
		fseek(pe_file , raw_e_addr, SEEK_SET);
		if(!fread(&dbyte, sizeof(BYTE), 1, pe_file)) //End of physical file (or read error)
		{
			err_handler("Can't read data byte on section #", EH_ERROR, snum);
			return;
		}

		printf("%02X ", dbyte);
		ascii_output(ADD_SYMB, dbyte);
		e_addr++;
		separating_output(PRN_SEP, e_addr, (size == OUT_END));

	}//end for(size)
	
	separating_output(RESET);
	printf("\n\n"); //after last data byte

	if (warning.superpos_of_sect)	err_handler("Superposition of physical sections!", EH_WARNING);	
	if (warning.read_between_sec)  err_handler("Was reading between the sections!", EH_WARNING);
	if (warning.read_outside_img)	err_handler("Was reading outside image!", EH_WARNING);
}

DWORD pe_image::get_imagebase(void)
{
	return pe_header.OptionalHeader.ImageBase;
}

int pe_image::already_loaded(int spec)
{
	if(spec)
	{
		if(pe_header.Signature = NULL)		return 0; //reset to NULL
		else							return 1;
	}
	else if (pe_header.Signature != NULL) 	return 1;
	else								return 0;
}

void pe_image::err_handler(const char* message, const int spec, int num)
{
	const char * E_MSG;
	if (spec) E_MSG = ERROR_PREFIX;
	else	  E_MSG = WARNING_PREFIX;

		if(!(num+1))\
		printf("%s: %s\n", E_MSG, message); else\
		printf("%s: %s%d\n", E_MSG, message, num);
}

pe_image::~pe_image(void)
{
	if (!sections ) delete sections;
	if ((void*)pe_file != NULL ) fclose(pe_file);
}