#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include "md5.c"
#define MAX 1000


//=============STRUCTURES===============
struct malware{
    char malware_name[MAX];
    struct malware* next;
    char only_name[MAX];

};
struct files{
    char filename[MAX];
    char file_md5[MAX];
    char only_name[MAX];
    struct files *next;
};

//=========Functions Prototypes=============
char *MD5_file (char *path);
void printmalware(struct malware * mal_head);
void print_files(struct files *filehead);
struct malware* findmalware(char textfile_name[],struct files* file_head,struct malware* mal_head);
struct files * make_linklist(char directory[],struct files *head);
void delete_file(struct malware * mal_head);
void delete_all(struct malware * mal_head);
//============================================
struct malware* findmalware(char textfile_name[],struct files* file_head,struct malware* mal_head){

    //mal_head is NULL for the first time

   struct malware * mal_temp = mal_head;
    struct files* file_temp = file_head;

    while(file_temp != NULL){
        char arr[33];
        FILE *malware_file;
        malware_file = fopen(textfile_name,"r");
        while(fgets(arr,33,malware_file)){
            strlwr(arr);
            int result;
            result = strcmp(file_temp->file_md5,arr);
            if(result == 0){
                if(mal_temp == NULL){
                    mal_head = (struct malware *) malloc(sizeof(struct malware));
                    mal_temp = mal_head;
                    strcpy(mal_temp->only_name,file_temp->only_name);
                    strcpy(mal_temp->malware_name,file_temp->filename);
                    mal_temp->next = NULL;
                }
                else{
                    mal_temp ->next = (struct malware *) malloc(sizeof(struct malware));
                    mal_temp = mal_temp->next;
                    strcpy(mal_temp->only_name,file_temp->only_name);
                    strcpy(mal_temp->malware_name,file_temp->filename);
                    mal_temp->next = NULL;
                }
            }
        }
        fclose(malware_file);
        file_temp = file_temp->next;
    }

    return mal_head;
}
//===========================================
struct files * make_linklist(char directory[],struct files *head){
    struct files *temp = head;
    DIR *d;
    struct dirent *dir;
    d = opendir(directory);
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if(temp == NULL){
                if(strcmp(dir->d_name,".")!=0 && strcmp(dir->d_name,"..")!=0 ){
                    head = (struct files *)malloc(sizeof(struct files));
                    temp = head;
                    char dirplusname[MAX];
                    strcpy(temp->only_name,dir->d_name);
                    strcpy(dirplusname,directory);
                    strcat(dirplusname,"\\");
                    strcat(dirplusname,dir->d_name);
                    strcpy(temp->filename,dirplusname);
                    char *md5 = MD5_file(dirplusname);
                    strcpy(temp->file_md5,md5);
                    temp->next = NULL;
                }
            }
            else {

                temp ->next =(struct files *)malloc(sizeof(struct files));
                temp = temp->next;
                char dirplusname[MAX];
                strcpy(temp->only_name,dir->d_name);
                strcpy(dirplusname,directory);
                strcat(dirplusname,"\\");
                strcat(dirplusname,dir->d_name);
                strcpy(temp->filename,dirplusname);
                char *md5 = MD5_file(dirplusname);
                strcpy(temp->file_md5,md5);
                temp->next = NULL;

            }
    }
    temp->next=NULL;
    closedir(d);
    return head;
  }
  return head;
}
//=======================================
void delete_file(struct malware * mal_head){
    struct malware * mal_temp=(struct malware *)malloc(sizeof(struct malware));
    mal_temp=mal_head;
    while(mal_temp!=NULL){
        int status;
        int input=0;
        printf("THIS FILE  <%s> SEEMS TO BE A MALWARE.DO YOU WANT TO DELETE IT?\n1)YES  2)NO?\n",mal_temp->only_name);
        scanf("%d",&input);
        if(input==1){
            status=remove(mal_temp->malware_name);
            if(status==0){
                printf("%s deleted successfully\n",mal_temp->only_name);
            }
            else{
                printf("unable to delete the file\n");
                perror("following error occurred\n");
            }
        }
        else if(input==2){
            mal_temp=mal_temp->next;
            continue;
        }
        else{
            printf("You entered a wrong entry.please try again.\n");
            delete_file(mal_head);
        }
    mal_temp=mal_temp->next;
    }
}
//=======================================
void delete_all(struct malware * mal_head){
    struct malware * mal_temp=(struct malware *)malloc(sizeof(struct malware));
    mal_temp=mal_head;
    while(mal_temp!=NULL){
        int status;
        status=remove(mal_temp->malware_name);
        if(status==0){
            printf("%s deleted successfully\n",mal_temp->only_name);
        }
        else{
            printf("unable to delete the file\n");
            perror("following error occurred\n");
        }
    mal_temp=mal_temp->next;
    }

}
//=======================================

char *MD5_file (char *path){

  FILE *fp = fopen (path, "rb");
  MD5_CTX mdContext;
  int bytes;
  unsigned char data[1024];
  char *file_md5;
  int i;

  if (fp == NULL) {
    fprintf (stderr, "fopen %s failed\n", path);
    perror(path);
    exit(EXIT_FAILURE);
    return NULL;
  }

  MD5Init (&mdContext);

  while ((bytes = fread (data, 1, 1024, fp)) != 0){
    MD5Update (&mdContext, data, bytes);
  }
  MD5Final (&mdContext);

  file_md5 = (char *)malloc((33) * sizeof(char));
  if(file_md5 == NULL){
    fprintf(stderr, "malloc failed.\n");
    return NULL;
  }
  memset(file_md5, 0, 33);

    for(i=0; i<16; i++){
      sprintf(&file_md5[i*2], "%02x", mdContext.digest[i]);
    }

  fclose (fp);

  return file_md5;
}


//=======================================
void printmalware(struct malware * mal_head){
    struct malware * temp=mal_head;

    if(mal_head==NULL){
        printf("\t\t\t\t  no malware found\n");
        return ;
    }
    while(temp!=NULL){
        printf("malware directory is:%s\n",temp->malware_name);
        printf("malware name is:%s\n",temp->only_name);
        temp=temp->next;
    }
}
//=======================================
void print_files(struct files *filehead){
    struct files * temp=filehead;

    if(filehead==NULL){
        return ;
    }
    while(temp!=NULL){
        printf("file name is :%s\n",temp->only_name);
        printf("md5 hash of the file is:%s\n",temp->file_md5);
        temp=temp->next;
    }
}
//=======================================

void PHASE1(){

    struct files * filehead=NULL;
    printf("\t\t\tENTER THE DIRECTORY :\n\n\t\t\t");
    char arr[MAX];
    scanf ("%s",arr);
    filehead=make_linklist(arr,filehead);
   // print_files(filehead);

    struct malware * mal_head=NULL;
    printf("\n\t\t\tENTER FULL TEXT FILE ADDRESS AND NAME:\n\n\t\t\t");
    char textfile_name[100];
    scanf("%s",textfile_name);
    mal_head=findmalware(textfile_name,filehead,mal_head);
    printf("\n-----------------------------------------------------------------------------\n\t\t\tHERE IS THE LIST OF MALWARES:\n\n");
    printmalware(mal_head);
    printf("-----------------------------------------------------------------------------\n");
    if(mal_head!=NULL){
        printf("\n\t\t\thow do you want to delete them?\n\t\t");
        printf("      1.One by One      2.DELETE THEM ALL\n");
        int in;
        scanf("%d",&in);
        if(in==1){
            delete_file(mal_head);
        }
        else if(in==2){
            delete_all(mal_head);
        }
    }
}

