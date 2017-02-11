#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "pe_class.h"

#define PROMPT_STR	">"
pe_image pe;

void help_out(void);
void fload(char* cl);
void fimportd(void);
void fdump(char* cl);


int main(int argc, char* argv[])
{
	pe = pe_image();
	char cl[255];
	for(;;)
	{
		printf("%s", PROMPT_STR); //prompt
		fflush(stdin);
		gets(cl);
		if (!strcmp(cl, "exit")) break;
		else if(!strcmp(cl, "q")) break;
		else if(!strcmp(cl, "help")) help_out();
		else if(strstr(cl, "fload ") == cl) fload(cl);
		else if(!strcmp(cl, "fimportd")) fimportd();
		else if(strstr(cl, "fdump") == cl) fdump(cl);
		else if(cl[0]) printf("Unknown command or bad format, try to use command \"help\"\n");
	}	
	return 0;
}

void fload(char* cl)
{	char fname[255];
	
	if(cl[sizeof("fload")])
	{
		strcpy(fname, cl+sizeof("fload"));
		if(pe.load(fname)) printf("Loading was successful.\n");
		else printf("Loading failed!\n"), pe.already_loaded(TO_NULL);
	}
	else printf("Bad format, after command need write file name!\n");
}

void fimportd(void)
{
	if(pe.already_loaded(QUEST))
	{
		pe.import_dir_print();
	}
	else printf("First load PE executable file!\n");
}

void fdump(char* cl)
{
	char * end_byte;
	DWORD e_addr, size;
	char params[255];
	char str_e_addr[255] ;
	char str_size[255] ;
	int	sof_e_addr = 0;
	int	sof_size = 0;
	if(cl[sizeof("fdump")-1] == SPACE_BYTE)
	{       
		int start_par = sizeof("fdump");
		while(cl[start_par] == SPACE_BYTE)	++start_par;

		strcpy(params, cl+start_par);
		for(int i = 0; i < sizeof(str_e_addr); i++)
		{	
			str_e_addr[sof_e_addr] = params[sof_e_addr];
			if(str_e_addr[sof_e_addr] == SPACE_BYTE) str_e_addr[sof_e_addr] = ZERO_BYTE;
			++sof_e_addr;
			if(str_e_addr[sof_e_addr-1] == ZERO_BYTE) break;
		}
		
		str_e_addr[sizeof(str_e_addr)-1] = ZERO_BYTE;
		
		if(sof_e_addr > 1) //1st parameter not defined (e_addr)
		{
			e_addr = (DWORD)strtoul(str_e_addr, &end_byte, RADIX16);
			start_par += sof_e_addr;
			while(cl[start_par] == SPACE_BYTE)	++start_par;
	
			strcpy(params, cl+start_par);
			for(int i = 0; i < sizeof(str_size); i++)
			{	
				str_size[sof_size] = params[sof_size];
				if(str_size[sof_size] == SPACE_BYTE) str_size[sof_size] = ZERO_BYTE;
				++sof_size;
				if(str_size[sof_size-1] == ZERO_BYTE) break;
			}
			
			str_size[sizeof(str_size)-1] = ZERO_BYTE;
			
			if(sof_size > 1) size = (DWORD)strtoul(str_size, &end_byte, RADIX16);
		 	else 		      size = DEFAULT_DUMP_SIZE;
		}
		else
		{
			e_addr = pe.get_imagebase();
			size 	   = DEFAULT_DUMP_SIZE;
		}

		if(pe.already_loaded(QUEST))
		{
			pe.dump(e_addr, size);
		}
		else printf("First load PE executable file!\n");
		
	} 
	else if(!cl[sizeof("fdump")-1])
	{
		if(pe.already_loaded(QUEST))
		{
			pe.dump(pe.get_imagebase(), DEFAULT_DUMP_SIZE);
		}
		else printf("First load PE executable file!\n");
	}
	else printf("Bad format. After command, through gap need write inital (and final)\nvirtual addresses!\n");
}

void help_out(void)
{
	printf("\nfload <file name> - to load PE executable file.\n");
	printf("fimportd - to output ImoptDirectory\n");
	printf("fdump [start address] [size] - to dump file image on VAs\n");
	printf("exit or just q - to exit.\n");
}