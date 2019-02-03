#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include "phase1.c"
#include "phase2.c"
#define MAX 1000
int count = 0;

int main(){
    while(count >= 0){
        int choice;
        if(count == 0){
           printf("            WELLCOME to our ANTIVIRUS\n========================================================\n");
           count++;
        }
        else{
            printf("            WELLCOME AGAIN to our ANTIVIRUS\n========================================================\n");
        }

        printf(" Choose With Phase you want to try the antivirus with or Exit(:/):\n");
        printf(" 1.PHASE1\n 2.PHASE2\n 3.Exit\n");
        scanf("%d",&choice);
        if(choice == 1){
            PHASE1();
        }
        else if(choice == 2){
            PHASE2();
        }
        else if(choice == 3){
            break;
        }
    }
    printf("you exited successfuly :)");

return 0;
}



