#include<stdio.h>
#include<windows.h>
#include<string.h>

void * GetFunc(LPVOID base,WORD ord);
void Fix_Reloc(LPVOID base,PIMAGE_BASE_RELOCATION reloc,ULONGLONG delta);
void Load_Import(LPVOID base,PIMAGE_IMPORT_DESCRIPTOR import);
void Call_Tls(LPVOID base,PIMAGE_TLS_DIRECTORY  tls);

int main(int i,char **arg)
{
	HANDLE File,proc;
	LPVOID file,base;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_SECTION_HEADER sec;
	BOOL Rr=0;
	DWORD Size;
	//BOOL (*Entry)(LPVOID hinstDLL,DWORD fdwReason,LPVOID lpvReserved);
	
	BOOL (*Entry)();
	if(i!=2)
	{
		printf("Usage %s <Pe>\n",*arg);
		return 0;
	}
	
	
	if((File=CreateFileA(*(arg+1),GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL))==INVALID_HANDLE_VALUE)
	{
		printf("Failed to Open File");
		return 0;
	}
	
	Size=GetFileSize(File,NULL);
	
	
	file=VirtualAlloc(NULL,Size,MEM_RESERVE | MEM_COMMIT,PAGE_READWRITE);
	if(file==NULL)
	{
		printf("Failed To Allocate Memory");
		return 0;
	}
	
	
	ReadFile(File,file,Size,0,0);
	
	CloseHandle(File);
	
	
	if(((PIMAGE_DOS_HEADER)file)->e_magic!=23117)
	{
		printf("Invalid PE");
		VirtualFree(file,0,MEM_RELEASE);
		return 0;
	}
	
	nt=(PIMAGE_NT_HEADERS)(file+((PIMAGE_DOS_HEADER)file)->e_lfanew);
	if(nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		printf("Please Supply 64 bit pe");
		VirtualFree(file,0,MEM_RELEASE);
		return 0;
	}
	
	if((base=VirtualAlloc((LPVOID)nt->OptionalHeader.ImageBase,nt->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE))==NULL)
	{
		Rr=1;
		
		if((base=VirtualAlloc(NULL,nt->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE))==NULL)
		{
			printf("Failed To Allocate Memory");
			return 0;
		}
	}
	
	proc=GetCurrentProcess();
	
	//copying Image
	
	printf("[+]Copying Image\n");
	WriteProcessMemory(proc,base,file,nt->OptionalHeader.SizeOfHeaders,NULL);
	
	printf("[+]Copying Sections\n");
	
	sec=(PIMAGE_SECTION_HEADER)((LPVOID)nt+24+nt->FileHeader.SizeOfOptionalHeader);
	
	//Copying Sections
	for(i=0;i<nt->FileHeader.NumberOfSections;i++)
	{
		
		WriteProcessMemory(proc,base+sec->VirtualAddress,file+sec->PointerToRawData,sec->SizeOfRawData,0);sec++;
	}
	
	VirtualFree(file,0,MEM_RELEASE);
	
	nt=(PIMAGE_NT_HEADERS)(base+((PIMAGE_DOS_HEADER)base)->e_lfanew);
	
	//Base Relocation
	if(Rr)
	{
		printf("[+]Fixing Relocation\n");
		if(nt->OptionalHeader.DataDirectory[5].VirtualAddress==0)
		printf("[!]There is no Relocation Table\n");
		else
		Fix_Reloc(base,(PIMAGE_BASE_RELOCATION)(base+nt->OptionalHeader.DataDirectory[5].VirtualAddress),(ULONGLONG)base-nt->OptionalHeader.ImageBase);
	}
	
	printf("[+]Loading Imports\n");
	//Loading Imports
	if(nt->OptionalHeader.DataDirectory[1].VirtualAddress==0)
	{
		printf("[!]There is no Import Table\n");
	}
	else
	Load_Import(base,(PIMAGE_IMPORT_DESCRIPTOR)(base+nt->OptionalHeader.DataDirectory[1].VirtualAddress));
	
	
	
	printf("[+]Calling TLS Callbacks\n");
	//Calling TLS callbacks
	if(nt->OptionalHeader.DataDirectory[9].VirtualAddress==0)
	printf("[!]There is No TLS Directory\n");
	else
	Call_Tls(base,(PIMAGE_TLS_DIRECTORY)(base+nt->OptionalHeader.DataDirectory[9].VirtualAddress));
	
	
	Entry=(base+nt->OptionalHeader.AddressOfEntryPoint);
	printf("[!]Dll base: %#p\n[!]Entry: %#p\n",base,Entry);
	printf("[+]Executing....\n");
	
	(*Entry)();
	
	
	VirtualFree(base,0,MEM_RELEASE);
	
	return 0;
	
	
}

void Fix_Reloc(LPVOID base,PIMAGE_BASE_RELOCATION reloc,ULONGLONG delta)
{
	int i=0,n,offset;
	PWORD d;
	LPVOID dest;
	ULONGLONG * p;
	while(reloc->VirtualAddress)
	{
		dest=base+reloc->VirtualAddress;
		n=(reloc->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/2;
		d=(PWORD)((LPVOID)reloc+sizeof(IMAGE_BASE_RELOCATION));
		for(i=0;i<n;i++,d++)
		{
			if((*(d)>>12)==10)
			{
				offset=*(d)&0xfff;
				p=(ULONGLONG *)(dest+offset);
				*p+=delta;
			}
			
		}
		reloc=((LPVOID)reloc+reloc->SizeOfBlock);
	}
}

void * GetFunc(LPVOID base,WORD ord)
{
	PIMAGE_EXPORT_DIRECTORY exp;
	PDWORD Func_list;
	
	PIMAGE_NT_HEADERS nt;
	int i;
	
	nt=(PIMAGE_NT_HEADERS)(base+((PIMAGE_DOS_HEADER)base)->e_lfanew);
	
	exp=(PIMAGE_EXPORT_DIRECTORY)(base+nt->OptionalHeader.DataDirectory[0].VirtualAddress);
	
	
	Func_list=(PDWORD)(base+exp->AddressOfFunctions);
	
	
	if(base==NULL)
	return NULL;
	
	if(ord>=exp->NumberOfFunctions)
	return NULL;
	
	
	
	return (base+Func_list[ord-exp->Base]);
	
	
}


void Load_Import(LPVOID base,PIMAGE_IMPORT_DESCRIPTOR import)
{
	
	ULONGLONG * p;
	LPVOID dll;
	
	PIMAGE_THUNK_DATA pthunk,fthunk;
	PIMAGE_IMPORT_BY_NAME pnm;
	
	
	
	
	while(import->Name!=0)
	{
		dll=LoadLibraryA((LPSTR)(base+import->Name));
		pthunk=(PIMAGE_THUNK_DATA)(base+import->OriginalFirstThunk);
		fthunk=(PIMAGE_THUNK_DATA)(base+import->FirstThunk);
		
		if(pthunk==NULL)
		 pthunk=fthunk;
		
		
		while(pthunk->u1.AddressOfData) 
		
		{
			p=(ULONGLONG *)fthunk;
			if(pthunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				//*p=(ULONGLONG)GetFunc(dll,IMAGE_ORDINAL(pthunk->u1.Ordinal));
				*p=(ULONGLONG)GetProcAddress(dll,(char *)IMAGE_ORDINAL(pthunk->u1.Ordinal));
			}
			else
			{
				pnm=(PIMAGE_IMPORT_BY_NAME)(base+pthunk->u1.AddressOfData);
				*p=(ULONGLONG)GetProcAddress(dll,pnm->Name);
				
				
			}
			
			pthunk++;fthunk++;
		}
		import++;
	}
}

void Call_Tls(LPVOID base,PIMAGE_TLS_DIRECTORY tls)
{
	PIMAGE_TLS_CALLBACK * Callback;
	
	if(tls->AddressOfCallBacks==0)
	return ;
	Callback=(PIMAGE_TLS_CALLBACK *)(tls->AddressOfCallBacks);

	while(*Callback)
	{
		
		
		(*Callback)(base,DLL_PROCESS_ATTACH,NULL);
		Callback++;
	}
}

