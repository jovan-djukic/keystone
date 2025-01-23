#include <stdio.h>

int main()
{
  FILE *file = fopen ( "/root/hello.txt", "r" );
  
  if ( file != NULL ) {
    
    while ( !feof ( file ) ) {
      char c = fgetc ( file );
      putchar ( c );
    }

  } else {
    printf ( "Couldn't open file!\n" );
  }

  fclose ( file );
  
  return 0;
}
