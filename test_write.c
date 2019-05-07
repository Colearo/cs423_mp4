#include <stdio.h>
#include <stdlib.h>  
int main(int argc , char *argv[])
{
   FILE *fptr;

   fptr = fopen(argv[1], "w");
   if(fptr == NULL)
   {
      printf("Error!");
      exit(1);
   }

   fprintf(fptr,"Hello Write Test\n");
   fclose(fptr);

   return 0;
}
