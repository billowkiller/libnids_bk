#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define MAXWORD 30


typedef struct GSList{
   struct GSList* next;
   char* data;
}GSList;

GSList *g_kw_list = NULL;

GSList* current_kw=NULL;

GSList* g_list_append(GSList* kw_list,char* word)
{
    if(kw_list==NULL)
    {
        kw_list=(GSList*)malloc(sizeof(GSList));
        kw_list->data=word;
        current_kw=kw_list;
    }
    else{
        GSList* pre=current_kw;
        current_kw=(GSList*)malloc(sizeof(GSList));
        current_kw->data=word;
        pre->next=current_kw;
    }
    current_kw->next=NULL;
    return kw_list;
}

void read_kw_file(char *filename)
{
	FILE *file = fopen(filename, "r");
	while(1)
	{
		char *word = (char *)malloc(MAXWORD);
		//int n = fscanf(file, "%s", word);
        fgets(word,MAXWORD,file);
        word[strlen(word)-1]='\0';
        int n=strlen(word);
		//printf("%s\n",word);
		if(n > 0)
			g_kw_list = g_list_append(g_kw_list, word);
		else
			break;
	}
}

char* fileRead(char *filename)
{
	long file_length;
	FILE* file = fopen(filename, "r");
	if (file == NULL) {
	  perror("fopen");
	}

	fseek(file, 0, SEEK_END);
	file_length = ftell(file);
	if (file_length == -1) {
	  perror("ftell");
	}
	fseek(file, 0, SEEK_SET);
	char* data = malloc(file_length);
	if (fread(data, 1, file_length, file) != (size_t)file_length) {
	  fprintf(stderr, "couldn't read entire file\n");
	  free(data);
	}
	return data;
}

int kw_match(char *str, GSList *list)
{
	GSList *iterator = NULL;
	for (iterator = list; iterator; iterator = iterator->next)
	{
		 if(strstr(str, (char*)iterator->data))
		 {
		     //printf("%s\n",iterator->data);
			 return 1;
		 }
	}
	return 0;
}

