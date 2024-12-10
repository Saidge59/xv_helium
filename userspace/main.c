#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "hpt.h"


struct hpt *hpt = NULL;

void on_hpt_packet(void *handle, uint8_t *msg_content, size_t length);


int main() 
{
  int res = hpt_init();
  if(res != 0)
  {
    perror("Fatal Error: Could not find HPT, is the kernel module loaded?\n");
  }

  char name[HPT_NAMESIZE] = "hpt";
  hpt = hpt_alloc(name, 8192, on_hpt_packet, NULL, 1000000);
  
  uint8_t data[32] = "TEST";
  hpt_write(hpt, data, sizeof(data));  
  hpt_drain(hpt);

  hpt_close(hpt);
  /*
  char getChar = 0;
  while (true) 
  {
    getChar = getchar();
    if(getChar == 'q') 
    {
      hpt_close(hpt);
      break;
    }
    else if(getChar == 's')
    {
      hpt_write(hpt, data, 6);
    }
    getChar = 0;
  }
*/
  return 0;
}

void on_hpt_packet(void *handle, uint8_t *msg_content, size_t length) 
{
  printf("on_hpt_packet\n");
  for(size_t i = 0; i < length; i++)
  {
    printf("i: %ld, %c", i, msg_content[i]);
  }
}
