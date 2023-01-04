#include<stdio.h>
#include<windows.h>

typedef struct _PE_INFO_
{
	BOOL Brloc;
	LPVOID Get_Proc;
	LPVOID Load_Dll;
	LPVOID base;
} PE_INFO , * LPE_INFO ;

typedef UINT_PTR WINAPI (*GetProcAddr)(HINSTANCE module,const char * name);
typedef HINSTANCE WINAPI (*Load_DLL)(const char * name);

/*
typedef UINT_PTR __stdcall (*GetProcAddr)(HINSTANCE module,const char * name);
typedef HINSTANCE __stdcall (*Load_DLL)(const char * name);


*/

void Adjust_PE(LPE_INFO pe)
{
	LPVOID base;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_BASE_RELOCATION rloc;
	PIMAGE_TLS_DIRECTORY tls;
	PIMAGE_TLS_CALLBACK * Callback;
	PIMAGE_IMPORT_DESCRIPTOR imp;
	PIMAGE_THUNK_DATA Othunk,Fthunk;
	void (*Entry)(LPVOID , DWORD , LPVOID);
	
	
	base=pe->base;
	dos=(PIMAGE_DOS_HEADER)base;
	nt=(PIMAGE_NT_HEADERS)(base+dos->e_lfanew);
	
	
	GetProcAddr Get_Proc;
	Load_DLL Load_Dll;
	
	Get_Proc=pe->Get_Proc;
	Load_Dll=pe->Load_Dll;
	
	if(!pe->Brloc)
	goto Load_Import;
	
	Base_Reloc:
		if(!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
		goto Load_Import;
		
		ULONG delta=(ULONG)base-nt->OptionalHeader.ImageBase;
		rloc=(PIMAGE_BASE_RELOCATION)(base+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while(rloc->VirtualAddress)
		{
			LPVOID Dest=base+rloc->VirtualAddress;
			int n=(rloc->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/2;
			int i;
			PWORD data=(PWORD)((LPVOID)rloc+sizeof(IMAGE_BASE_RELOCATION));
			for(i=0;i<n;i++,data++)
			{
				if(((*data)>>12)==3)
				{
					PULONG p=(PULONG)(Dest+((*data)&0xfff));
					*p+=delta;
				}
			}
			rloc=(PIMAGE_BASE_RELOCATION)((LPVOID)rloc+rloc->SizeOfBlock);
		}
	
	Load_Import:
		if(!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
		goto TLS;
		
		imp=(PIMAGE_IMPORT_DESCRIPTOR)(base+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while(imp->Name)
		{
			LPVOID dll=Load_Dll((char *)(base+imp->Name));
			Othunk=(PIMAGE_THUNK_DATA)(base+imp->OriginalFirstThunk);
			Fthunk=(PIMAGE_THUNK_DATA)(base+imp->FirstThunk);
			
			if(!imp->OriginalFirstThunk)
			Othunk=Fthunk;
			
			while(Othunk->u1.AddressOfData)
			{
				if(Othunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					*(PULONG)Fthunk=(ULONG)Get_Proc(dll,(char *)IMAGE_ORDINAL(Othunk->u1.Ordinal));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME fn=(PIMAGE_IMPORT_BY_NAME)(base+Othunk->u1.AddressOfData);
					*(PULONG)Fthunk=(ULONG)Get_Proc(dll,fn->Name);
				}
				
				Othunk++;
				Fthunk++;
			}
			imp++;
		}
	TLS:
		if(!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
		goto Execute_Entry;
		
		tls=(PIMAGE_TLS_DIRECTORY)(base+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		if(!tls->AddressOfCallBacks)
		goto Execute_Entry;
		
		Callback=(PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
		while(*Callback)
		{
			(*Callback)(base,1,NULL);
			Callback++;
		}
		
	Execute_Entry:
		
		Entry=(base+nt->OptionalHeader.AddressOfEntryPoint);
		(*Entry)(base,1,NULL);
	
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
	PE_INFO pe;
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
	
	ZeroMemory(&pe,sizeof(pe));
	
	dos=(PIMAGE_DOS_HEADER)base;
	
	if(dos->e_magic!=23117)
	{
		printf("\n[-]Invalid PE");
		return 1;
	}
	dll=LoadLibraryA("kernel32.dll");
	nt=(PIMAGE_NT_HEADERS)(base+dos->e_lfanew);
	
	if(nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		printf("[-]Please use x86 PE");
		return 1;
	}
	
	
	
	 
	 
	 
	if((Rbase=VirtualAlloc((LPVOID)nt->OptionalHeader.ImageBase,nt->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE ,PAGE_EXECUTE_READWRITE))==NULL)
	{
		pe.Brloc=TRUE;
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
		
	pe.base=Rbase;
	pe.Get_Proc=GetProcAddress(dll,"GetProcAddress");
	pe.Load_Dll=GetProcAddress(dll,"LoadLibraryA");
	printf("[+]Adjusting PE And Executing...");

	
	Adjust_PE(&pe);
	

	return 0;
}

