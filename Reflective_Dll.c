#include<stdio.h>
#include<Windows.h>
#include<TlHelp32.h>
#include<DbgHelp.h>
//NtCurrentTeb() for get current TEB

typedef struct _PE_INFO
{
	LPVOID base;
	BOOL reloc;
	LPVOID Load_Dll;
	LPVOID Get_Proc;
} PE_INFO, *LPE_INFO;

BOOL Get_Rva(LPVOID base, PIMAGE_NT_HEADERS nt, char * name,PDWORD rva)
{
	PIMAGE_EXPORT_DIRECTORY exp=(PIMAGE_EXPORT_DIRECTORY)ImageRvaToVa(nt,base,nt->OptionalHeader.DataDirectory[0].VirtualAddress,NULL);
	PDWORD Name;
	PDWORD addr;
	PWORD ord;
	int i;
	
	ord=(PWORD)ImageRvaToVa(nt,base,exp->AddressOfNameOrdinals,NULL);
	Name=(PDWORD)ImageRvaToVa(nt,base,exp->AddressOfNames,NULL);
	addr=(PDWORD)ImageRvaToVa(nt,base,exp->AddressOfFunctions,NULL);
	
	for(i=0;i<exp->NumberOfNames;i++)
	{
		LPSTR Func=(LPSTR)ImageRvaToVa(nt,base,Name[i],NULL);
		if(!strcmp(Func,name))
		{
			*rva=addr[ord[i]];
			return 1;
		}
	}

	return 0;
}

void Adjust_PE(LPE_INFO pe)
{
	LPVOID base;
	ULONG64 delta;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_IMPORT_DESCRIPTOR import;
	PIMAGE_THUNK_DATA Othunk,Fthunk;
	PIMAGE_BASE_RELOCATION reloc;
	PIMAGE_TLS_DIRECTORY tls;
	PIMAGE_TLS_CALLBACK * tls_callback;
	LPVOID (*Get_Dll)(LPSTR );
	LPVOID (*Get_Proc)(LPVOID ,LPSTR );
	BOOL (*Entry)(LPVOID , DWORD , LPVOID);
	int i;
	
	//Initialize
	
	base=pe->base;
	Get_Dll=pe->Load_Dll;
	Get_Proc=pe->Get_Proc;
	nt=(PIMAGE_NT_HEADERS)(base+((PIMAGE_DOS_HEADER)base)->e_lfanew);
	
	
	if(!pe->reloc)
	goto Load_Export;
	
	
	Base_Reloc:
		if(nt->OptionalHeader.DataDirectory[5].VirtualAddress==0)
		goto Load_Export;
		
		delta=(ULONG64)base-nt->OptionalHeader.ImageBase;
		reloc=(PIMAGE_BASE_RELOCATION)(base+nt->OptionalHeader.DataDirectory[5].VirtualAddress);
		while(reloc->VirtualAddress)
		{
			LPVOID des=base+reloc->VirtualAddress;
			int entry=(reloc->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/2;
			
			PWORD data=((LPVOID)reloc+sizeof(IMAGE_BASE_RELOCATION));
			for(i=0;i<entry;i++,data++)
			{
				if((*data)>>12==10)
				{
					ULONG64 *p=(ULONG64 *)(des+((*data)&0xfff));
					*p+=delta;
				}
			}
			reloc=((LPVOID)reloc+reloc->SizeOfBlock);
			
		}
		
		
	
	
	Load_Export:
		if(nt->OptionalHeader.DataDirectory[1].VirtualAddress==0)
		goto Call_TLS;
		import=(PIMAGE_IMPORT_DESCRIPTOR)(base+nt->OptionalHeader.DataDirectory[1].VirtualAddress);
		while(import->Name)
		{
			LPVOID dll=(LPVOID)(*Get_Dll)(base+import->Name);
			Fthunk=(PIMAGE_THUNK_DATA)(base+import->FirstThunk);
			Othunk=(PIMAGE_THUNK_DATA)(base+import->OriginalFirstThunk);
			if(!import->OriginalFirstThunk)
			Othunk=Fthunk;
			
			while(Othunk->u1.AddressOfData)
			{
				if(Othunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					*(ULONG64 *)Fthunk=(ULONG64)(*Get_Proc)(dll,(LPSTR)IMAGE_ORDINAL(Othunk->u1.Ordinal));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME nm=(PIMAGE_IMPORT_BY_NAME)(base+Othunk->u1.AddressOfData);
					*(ULONG64 *)Fthunk=(ULONG64)(*Get_Proc)(dll,nm->Name);
				}
				Othunk++;
				Fthunk++;
			}
			import++;
		}
		
	
	Call_TLS:
		if(nt->OptionalHeader.DataDirectory[9].VirtualAddress==0)
		goto Execute_Entry;
		tls=(PIMAGE_TLS_DIRECTORY)(base+nt->OptionalHeader.DataDirectory[9].VirtualAddress);
		if(tls->AddressOfCallBacks==0)
		goto Execute_Entry;
		tls_callback=(PIMAGE_TLS_CALLBACK *)(tls->AddressOfCallBacks);
		while(*tls_callback)
		{
			(*tls_callback)(base,1,NULL);tls_callback++;
		}
		
		
	Execute_Entry:
		Entry=base+nt->OptionalHeader.AddressOfEntryPoint;
		(*Entry)(base,1,NULL);
		
	
}

HANDLE Find_Process(char * Process_Name)
{
	PROCESSENTRY32 ps;
	HANDLE proc;
	
	ps.dwSize=sizeof(ps);
	if((proc=CreateToolhelp32Snapshot(2,0))==INVALID_HANDLE_VALUE)
	{
		return INVALID_HANDLE_VALUE;
	}
	
	if(!Process32First(proc,&ps))
	return INVALID_HANDLE_VALUE;
	
	do
	{
		if(!strcmp(Process_Name,ps.szExeFile))
		{
			CloseHandle(proc);
			proc=OpenProcess(PROCESS_ALL_ACCESS,0,ps.th32ProcessID);
			if(proc==NULL)
			{
				return INVALID_HANDLE_VALUE;
			}
			else
			return proc;
		}
	}while(Process32Next(proc,&ps));
	
	return INVALID_HANDLE_VALUE;
}

int main(int i, char *arg[])
{
	LPVOID Mem,base;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_SECTION_HEADER sec;
	HANDLE proc, file;
	DWORD File_len;
	PE_INFO pe;

	if (i != 3)
	{
		printf("[*]Usage %s <DLL> <Process Name>\n", arg[0]);
		return 0;
	}

	printf("[*]Opening And Reading File\n");
	if ((file = CreateFileA(arg[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
	{
		printf("[-]Failed To Open File");
		return -1;
	}

	File_len = GetFileSize(file, NULL);
	printf("[+]Allocating Memory....\n");
	if ((Mem = VirtualAlloc(NULL, File_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) == NULL)
	{
		printf("[-]Failed To Allocate Memory..");
		CloseHandle(file);
		return - 1;
	}

	
	ReadFile(file, Mem, File_len, NULL, NULL);
	CloseHandle(file);
	
	dos = (PIMAGE_DOS_HEADER)Mem;
	if (dos->e_magic != 23117)
	{
		printf("[-]Invalid Pe");
		VirtualFree(Mem, 0, MEM_RELEASE);
		return -1;
	}
	
	
	nt = (PIMAGE_NT_HEADERS)(Mem + dos->e_lfanew );

	if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		printf("[-]This is not x64 PE");
		VirtualFree(Mem, 0, MEM_RELEASE);
		return -1;
	}
	sec = (PIMAGE_SECTION_HEADER)((ULONGLONG)nt + sizeof(IMAGE_NT_HEADERS));
	pe.reloc=0;



	printf("[*]Openning Process.....\n");


	if ((proc = Find_Process(arg[2])) == INVALID_HANDLE_VALUE)
	{
		printf("[-]\'%s\' Is not Found Or Failed To Open\n", arg[2]);
		VirtualFree(Mem, 0, MEM_RELEASE);
		return -1;
	}

	printf("[*]Allocating Memory Into Remote Process....\n");
	if ((base = VirtualAllocEx(proc, (LPVOID)nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL)
	{
		pe.reloc = 1;
		
		if ((base = VirtualAllocEx(proc, NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL)
		{
			printf("[-]Failed TO Allocate Memory Into Remote Process");
			VirtualFree(Mem, 0, MEM_RELEASE);
			return -1;
		}
		printf("[!]Failed To Allocate Memory At %#p \n[+]Memory Allocated At %#p\n",nt->OptionalHeader.ImageBase,base);
	}
	
	

	printf("[*]Copying Headers....");
	WriteProcessMemory(proc, base, Mem, nt->OptionalHeader.SizeOfHeaders, NULL);
	printf("\n[*]Copying Section Headers.....\n");
	for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		WriteProcessMemory(proc, sec->VirtualAddress + base, sec->PointerToRawData + Mem, sec->SizeOfRawData, NULL);
		printf("\t[+]Copying Section : %s\n",sec->Name);
		sec++;
	}
	
	pe.base = base;
	pe.Get_Proc = GetProcAddress;
	pe.Load_Dll = LoadLibraryA;

	if (!Get_Rva(Mem, nt, "Adjust_PE", &File_len))
	{
		printf("[!]I Have not Found Any Inline PE Configurator.Using Basic Configurator...");
		ULONG64 len = (ULONG64)Find_Process - (ULONG64)Adjust_PE;
		LPVOID data = VirtualAllocEx(proc, NULL, sizeof(pe) + len, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (data == NULL)
		{
			printf("[-]Failed TO allocate Memory For cache");
			VirtualFree(Mem, 0, MEM_RELEASE);
			VirtualFreeEx(proc, base, 0, MEM_RELEASE);
			return -1;
		}

		WriteProcessMemory(proc, data, &pe, sizeof(pe), NULL);
		WriteProcessMemory(proc, data + sizeof(pe), Adjust_PE, len, NULL);
		CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)data + sizeof(pe), data, 0, NULL);
	}
	else
	{
		
		LPVOID data = VirtualAllocEx(proc, NULL, sizeof(pe) , MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (data == NULL)
		{
			printf("[-]Failed TO allocate Memory For cache");
			VirtualFree(Mem, 0, MEM_RELEASE);
			VirtualFreeEx(proc, base, 0, MEM_RELEASE);
			return -1;
		}

		WriteProcessMemory(proc, data, &pe, sizeof(pe), NULL);
		
		CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)(base + File_len), data, 0, NULL);
	}

	
	VirtualFree(Mem, 0, MEM_RELEASE);
	printf("\n[*]Adjusting PE And Executing.....");
	CloseHandle(proc);
	return 0;


}
