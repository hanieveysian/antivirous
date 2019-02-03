#include<windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#define MAX 100
int checker =0 ;
struct exe_files * make_exe_list(char directory[],struct exe_files *head,char dll_name[]);
void print_files2(struct exe_files *filehead);
void delete_exe(struct exe_files * exe_head);
void delete_all1(struct exe_files * exe_head);

struct exe_files{

    int check;
    char file_name[MAX];
    char only_name[MAX];
    struct exe_files * next;

};

void delete_exe(struct exe_files * exe_head){
    struct exe_files * temp_exe = exe_head;
    while(temp_exe != NULL){
        if(temp_exe->check == 1){
            if(checker == 0){
                int choice;
                printf("How do you want to delete your files?\n\t1.delete all\n\t2.delete one by one\n");
                scanf("%d",&choice);
                checker++;
                if(choice == 1){
                    delete_all1(exe_head);
                    break;
                }
                else if(choice == 2){
                    continue;
                }
            }
            else{
                int status;
                int input;
                printf("This file seem to have the dll you mentioned to be malware: \n\tDO YOU WANT TO DELETE IT?\n1)YES  2)NO?\n\n(%s)",temp_exe->only_name);
                scanf("%d",&input);
                if(input==1){
                    status=remove(temp_exe->file_name);

                    if(status==0){
                        printf("%s deleted successfully\n",temp_exe->only_name);
                    }
                    else{
                        printf("unable to delete this file -> %s\n",temp_exe->only_name);
                        perror("following error occurred\n");
                    }
                }
                else if(input==2){
                    temp_exe=temp_exe->next;
                    continue;
                }
                else{
                    printf("You entered a wrong entry.please try again.\n");
                    delete_exe(exe_head);
                }
                    }

                }

        temp_exe =temp_exe->next;
    }
    if(checker==0){
        printf("None of your PE files had the dll you entered so none of them are malware.be safe :)");
    }

}
void delete_all1(struct exe_files * exe_head){
    struct exe_files * temp_exe=(struct exe_files *)malloc(sizeof(struct exe_files));
    temp_exe=exe_head;
    while(temp_exe!=NULL){
        int status;
        status=remove(temp_exe->file_name);
        if(status==0){
            printf("%s deleted successfully\n",temp_exe->only_name);
        }
        else{
            printf("unable to delete this file-> %s\n",temp_exe->only_name);
            perror("following error occurred\n");
        }
    temp_exe=temp_exe->next;
    }

}

struct exe_files * make_exe_list(char directory[],struct exe_files *head,char dll_name[]){
    struct exe_files *temp = head;
    DIR *d;
    struct dirent *dir;
    d = opendir(directory);
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if(temp == NULL){
                if(strcmp(dir->d_name,".")!=0 && strcmp(dir->d_name,"..")!=0 ){
                    head = (struct files *)malloc(sizeof(struct exe_files));
                    temp = head;
                    char dirplusname[200];
                    strcpy(dirplusname,directory);
                    strcat(dirplusname,"\\");
                    strcat(dirplusname,dir->d_name);
                    strcpy(temp->only_name,dir->d_name);
                    strcpy(temp->file_name,dirplusname);
                    if(checking(temp->file_name,dll_name) == 1){
                        temp->check =1;
                    }
                    else{
                        temp->check =0;
                    }
                    temp->next = NULL;
                }
            }
            else {

                temp ->next =(struct files *)malloc(sizeof(struct exe_files));
                temp = temp->next;
                char dirplusname[200];
                strcpy(dirplusname,directory);
                strcat(dirplusname,"\\");
                strcat(dirplusname,dir->d_name);
                strcpy(temp->only_name,dir->d_name);
                strcpy(temp->file_name,dirplusname);
                if(checking(temp->file_name,dll_name) == 1){
                    temp->check =1;
                }
                else{
                    temp->check =0;
                }
                temp->next = NULL;

            }
    }
    temp->next=NULL;
    closedir(d);
    return head;
  }
  return head;
}

int checking(char exe_name[],char dll_name[]){

    int res=0;
        printf("**************   %s   ***************\n",exe_name);
         HANDLE hFile,hFileMap;
         DWORD dwImportDirectoryVA,dwSectionCount,dwSection=0,dwRawOffset;
         LPVOID lpFile;
         PIMAGE_DOS_HEADER pDosHeader;
         PIMAGE_NT_HEADERS pNtHeaders;
         PIMAGE_SECTION_HEADER pSectionHeader;
         PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
         PIMAGE_THUNK_DATA pThunkData;
         hFile = CreateFile(exe_name,GENERIC_READ,0,0,OPEN_EXISTING,0,0);//vorodi
         if(hFile==INVALID_HANDLE_VALUE)
            ExitProcess(1);
         hFileMap = CreateFileMapping(hFile,0,PAGE_READONLY,0,0,0);
         lpFile = MapViewOfFile(hFileMap,FILE_MAP_READ,0,0,0);
         pDosHeader = (PIMAGE_DOS_HEADER)lpFile;
         pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)lpFile+pDosHeader->e_lfanew);
         dwSectionCount = pNtHeaders->FileHeader.NumberOfSections;
         dwImportDirectoryVA = pNtHeaders->OptionalHeader.DataDirectory[1].VirtualAddress;
         pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders+sizeof(IMAGE_NT_HEADERS));
         for(; pSectionHeader->VirtualAddress <= dwImportDirectoryVA;pSectionHeader++);

         pSectionHeader--;
         dwRawOffset = (DWORD)lpFile+pSectionHeader->PointerToRawData;
         pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dwRawOffset+(dwImportDirectoryVA-pSectionHeader->VirtualAddress));
         printf("\tDLL Names used by this particular PE file are:\n");

         for(;pImportDescriptor->Name!=0;pImportDescriptor++){
             printf("\t\t%s\n",dwRawOffset+(pImportDescriptor->Name-pSectionHeader->VirtualAddress));

             pThunkData = (PIMAGE_THUNK_DATA)(dwRawOffset+(pImportDescriptor->FirstThunk-pSectionHeader->VirtualAddress));
             printf("\t\t\tFunctions used in this particular DLL are: \n");
             for(;pThunkData->u1.AddressOfData != 0;pThunkData++){

                 printf("\t\t\t\t%s\n",(dwRawOffset+(pThunkData->u1.AddressOfData-pSectionHeader->VirtualAddress+2)));
             }
            if(strcmp(dwRawOffset+(pImportDescriptor->Name-pSectionHeader->VirtualAddress),dll_name)==0){
                    res = 1;

            }
         }
         UnmapViewOfFile(lpFile);
         CloseHandle(hFileMap);
         CloseHandle(hFile);
         return res;
}
void print_files2(struct exe_files *filehead){
    struct exe_files * temp=filehead;

    if(filehead==NULL){
        return ;
    }
    while(temp!=NULL){
        if(temp->check == 1){
            printf("file name is :%s\n",temp->only_name);
        }
        temp=temp->next;
    }
}

void PHASE2()
{
    char arr[MAX];
    printf("Please Enter Full address of your directory: \n");
    scanf("%s",arr);
    char dll_name[100];
    printf("please Enter dll name:\n");
     scanf("%s",dll_name);
    struct exe_files *exe_head = NULL;
    exe_head = make_exe_list(arr,exe_head,dll_name);
    print_files2(exe_head);
    delete_exe(exe_head);

}
