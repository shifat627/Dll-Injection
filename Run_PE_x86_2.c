#include<stdio.h>
#include<windows.h>
#include<winnt.h>
#include<winternl.h>


typedef struct _relocation_entry_
{
    WORD offset:12;WORD type:4;
}TYPE_ENTRY , *LPTYPE_ENTRY;

typedef struct CUSTOM_TEB {
  PVOID Reserved1[12];
  PPEB  ProcessEnvironmentBlock;
  PVOID Reserved2[399];
  BYTE  Reserved3[1952];
  PVOID TlsSlots[64];
  BYTE  Reserved4[8];
  PVOID Reserved5[26];
  PVOID ReservedForOle;
  PVOID Reserved6[4];
  PVOID TlsExpansionSlots;
} MYTEB, *PMYTEB;


typedef struct _LDR_MODULE {



  LIST_ENTRY              InLoadOrderModuleList;
  LIST_ENTRY              InMemoryOrderModuleList;
  LIST_ENTRY              InInitializationOrderModuleList;
  PVOID                   BaseAddress;
  PVOID                   EntryPoint;
  ULONG                   SizeOfImage;
  UNICODE_STRING          FullDllName;
  UNICODE_STRING          BaseDllName;
  ULONG                   Flags;
  SHORT                   LoadCount;
  SHORT                   TlsIndex;
  LIST_ENTRY              HashTableEntry;
  ULONG                   TimeDateStamp;

} LDR_MODULE, *PLDR_MODULE;


#ifdef _WIN64
#define BASE_REL_TYPE 10
#else
#define BASE_REL_TYPE 3
#endif // _WIN64
typedef PVOID __stdcall (*LoadLibraryAPointer)(LPSTR name);
typedef PVOID __stdcall (*GetProcAddressPointer)(PVOID base,LPSTR func);

char StringCompare(char * src, char * dest){
	while( (*src!=0) && (*dest !=0) ){
		if(*src != *dest){
			return 0;
		}
		
		src++;
		dest++;
	}
	
	if( (*src!=0) && (*dest !=0) ){
		return 0;
	}
	
	return 1;
}

BOOL __stdcall GetEssentialFunctionAddress(UINT_PTR * GetProc, UINT_PTR * LoadLib){
	
	
	PPEB peb = ((PMYTEB)NtCurrentTeb())->ProcessEnvironmentBlock;
	PLIST_ENTRY entry = peb->Ldr->InMemoryOrderModuleList.Flink;
	PLDR_MODULE module;
	
	
	UINT_PTR base,LoadLib_Addr,GetProc_Addr;LoadLib_Addr=GetProc_Addr=0;
	PIMAGE_EXPORT_DIRECTORY exp;
	PIMAGE_NT_HEADERS nt;
	
	
	PDWORD addr_list,name_list;
	PWORD ord_list;
	char * func_name;
	
	module = ((LPVOID)entry->Flink->Flink) - FIELD_OFFSET(LDR_MODULE,InMemoryOrderModuleList);
	
	//printf("Address of Kernel32 (Manual)%p-(Function)%p\n",module->BaseAddress,LoadLibraryA("kernel32.dll"));
	
	base = module->BaseAddress;
	
	nt = (PIMAGE_NT_HEADERS)(base+ ((PIMAGE_DOS_HEADER)base)->e_lfanew );
	
	if(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress){
		exp = base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		
		addr_list = base + exp->AddressOfFunctions;
		name_list = base + exp->AddressOfNames;
		ord_list = base + exp->AddressOfNameOrdinals;
		
		int i = 0;
		
		for(i=0;i<exp->NumberOfNames;i++){
			func_name = base + name_list[i];
			if(StringCompare(func_name,"LoadLibraryA")){
				LoadLib_Addr = base + addr_list[ord_list[i]];
			}
			
			if(StringCompare(func_name,"GetProcAddress")){
				GetProc_Addr = base + addr_list[ord_list[i]];
			}
		}
	}
	
	if(LoadLib_Addr){
		*LoadLib = LoadLib_Addr;
	}
	
	if(GetProc_Addr){
		*GetProc = GetProc_Addr;
	}
	
	
	if(GetProc_Addr &&  LoadLib_Addr )
	return 1;
	
	
	return 0;
}

void PeConfig(void * BaseAddress){
	
	PIMAGE_BASE_RELOCATION  relocation;
	PIMAGE_NT_HEADERS nt;
	
	GetProcAddressPointer GetProc;
	LoadLibraryAPointer LoadLib;
	
	UINT_PTR base_delta=0;
	
	nt = (PIMAGE_NT_HEADERS) ( BaseAddress + ((PIMAGE_DOS_HEADER)BaseAddress)->e_lfanew );
	
	
	//Relocating Base
	if((UINT_PTR)nt->OptionalHeader.ImageBase != (UINT_PTR) BaseAddress){
		printf("Relocating\n");
		base_delta = (UINT_PTR) BaseAddress - nt->OptionalHeader.ImageBase;
		
		if(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress){
			
			relocation = (PIMAGE_BASE_RELOCATION) (BaseAddress + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			
			while(relocation->VirtualAddress){
				
				LPVOID Dest_addr = BaseAddress + relocation->VirtualAddress;
				LPTYPE_ENTRY entry = (LPTYPE_ENTRY)(relocation+1);
				
				int nEntry = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/2;
				
				int i;
				
				for(i=0;i<nEntry;i++,entry++){
					if(entry->type == BASE_REL_TYPE){
						
						UINT_PTR * p = (PUINT_PTR)(Dest_addr + entry->offset);
						*p = *p + base_delta;
						
					}
					
					
				}
				
				relocation = (PIMAGE_BASE_RELOCATION) ((LPVOID)(relocation) + relocation->SizeOfBlock );
			}
				
		}
		else{
			return;
		}
		
		
		
	}
	
	//-----------------------------------------------------
	
	//Finding Address Of GetProcAddress() And LoadLibrary()
	
	if(!GetEssentialFunctionAddress((UINT_PTR *)&GetProc,(PUINT_PTR)&LoadLib)){
		return ;
	}
	printf("%p %p\n",GetProc,LoadLib);
	//-----------------------------------------------------
	
	//Importing Functions
	if(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress){
		printf("Importing Lirbary\n");
		PIMAGE_IMPORT_DESCRIPTOR import =(PIMAGE_IMPORT_DESCRIPTOR) (BaseAddress + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		PIMAGE_THUNK_DATA fthunk,othunk;
		
		
		while(import->Name){
			LPVOID dll = LoadLib(BaseAddress + import->Name);
			printf("Importing %s\n",BaseAddress + import->Name);
			if(dll){
				printf("\tAddress %p\n",dll);
				fthunk = (PIMAGE_THUNK_DATA)(BaseAddress+import->FirstThunk);
				othunk = (PIMAGE_THUNK_DATA)(BaseAddress+import->OriginalFirstThunk);
				
				if(!import->OriginalFirstThunk){
					othunk = fthunk;
				}
				
				while(othunk->u1.AddressOfData){
					if(othunk->u1.Ordinal & IMAGE_ORDINAL_FLAG){
						*((UINT_PTR *)fthunk )=(UINT_PTR) GetProc(dll,(char *)IMAGE_ORDINAL(othunk->u1.Ordinal));
					}
					else{
						PIMAGE_IMPORT_BY_NAME nm = (PIMAGE_IMPORT_BY_NAME)(BaseAddress+othunk->u1.AddressOfData);
						*((UINT_PTR *)fthunk )= (UINT_PTR) GetProc(dll,nm->Name);
					}
					
					printf("Function Address %p\n",fthunk->u1.AddressOfData);
					
					++othunk;
					++fthunk;
				}
				
			}
			++import;
		}
	}
	
	
	//------------------------------------------------------------------------------
	//calling TLS callbacks
	
	if(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress){
		printf("CALLING TLS\n");
		PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(BaseAddress+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		
		if(tls->AddressOfCallBacks){
			PIMAGE_TLS_CALLBACK * callback = tls->AddressOfCallBacks;
			while(*callback){
				PIMAGE_TLS_CALLBACK func = *callback;
				(*callback)(BaseAddress,1,NULL);
				callback++;
			}
			
		}
	}
	
	void (*Entry)(LPVOID , DWORD , LPVOID) = (BaseAddress+nt->OptionalHeader.AddressOfEntryPoint);
	printf("Calling Entry\n");
	(*Entry)(BaseAddress,1,NULL);
	printf("Bye\n");
}


LPVOID Memory_Map_File(const char * Filename)
{
	HANDLE f,mmap;
	
	
	if((f=CreateFileA(Filename,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL))==INVALID_HANDLE_VALUE)
	{
		printf("[-]Failed To Open File");
		return NULL;
	}
	
	if((mmap=CreateFileMappingA(f,NULL,PAGE_READONLY,0,0,NULL))==NULL)
	{
		printf("[-]CreateFileMappingA() Failed..");
		return NULL;
	}
	
	return MapViewOfFile(mmap,FILE_MAP_READ,0,0,0);
}


int main(int i,char *arg[])
{
	LPVOID base,Rbase;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_SECTION_HEADER sec;
	
	HANDLE proc;
	LPVOID dll;
	if(i!=2)
	{
		printf("[!]Usage %s <DLL>",arg[0]);
		return 1;
	}
	
	if((base=Memory_Map_File(arg[1]))==NULL)
	{
		printf("[-]Failed To Memory Map File");
		return 1;
	}
	
	printf("[+]File is Memory Mapped Successfully\n");
	
	
	
	dos=(PIMAGE_DOS_HEADER)base;
	
	if(dos->e_magic!=23117)
	{
		printf("\n[-]Invalid PE");
		return 1;
	}
	
	nt=(PIMAGE_NT_HEADERS)(base+dos->e_lfanew);
	
	if(nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR_MAGIC)
	{
		printf("[-]Please use x86 PE");
		return 1;
	}
	
	
	
	 
	 
	 
	if((Rbase=VirtualAlloc(NULL,nt->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE ,PAGE_EXECUTE_READWRITE))==NULL)
	{
	
		if((Rbase=VirtualAlloc(NULL,nt->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE ,PAGE_EXECUTE_READWRITE))==NULL)
	 	{
	 		printf("\n[-]Failed To Allocate Memory Into Remote Process");
	 		CloseHandle(proc);
	 		return 1;
		}
	}
	
	
	proc=GetCurrentProcess();
	
	printf("\n[+]Copying File Content\n");
	
	WriteProcessMemory(proc,Rbase,base,nt->OptionalHeader.SizeOfHeaders,NULL);
	
	sec=(PIMAGE_SECTION_HEADER)((LPVOID)nt+sizeof(IMAGE_NT_HEADERS));
	
	for(i=0;i<nt->FileHeader.NumberOfSections;i++)
	{
		WriteProcessMemory(proc,Rbase+sec->VirtualAddress,base+sec->PointerToRawData,sec->SizeOfRawData,NULL);
		sec++;
	} 	
		
	PeConfig(Rbase);
	
	printf("Bye");
	return 0;
}

