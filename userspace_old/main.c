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

  char name[HPT_NAMESIZE] = HPT_DEVICE;
  hpt = hpt_alloc(name, 8192, on_hpt_packet, NULL, 100);

  uint8_t *data = malloc(2048);

  if(!hpt)
  {
    perror("Fatal Error: hpt_alloc\n");
    hpt_close(hpt);
    return 0;
  }

  while (true) 
  {
    switch(getchar())
    {
      case 'q': 
        hpt_close(hpt); 
        free(data);
        return 0;
      case 'w': 
        hpt_write(hpt, data, 2048); 
        break;
      case 'd': 
        hpt_drain(hpt); 
        break;
    }
  }

  return 0;
}

void on_hpt_packet(void *handle, uint8_t *msg_content, size_t length) 
{
  printf("Received packet of size %zu\n", length);
  for(uint8_t i=0; i < length; i++)
  {
    printf("%c", msg_content[i]);
  }

}
