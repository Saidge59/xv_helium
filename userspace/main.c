#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "hpt.h"


struct hpt *hpt = NULL;

void on_hpt_packet(void *handle, uint8_t *msg_content, size_t length);
void hpt_send(unsigned char *packet, size_t packet_size);

int main() 
{
  int res = hpt_init();
  if(res != 0)
  {
    perror("Fatal Error: Could not find HPT, is the kernel module loaded?\n");
  }

  char name[HPT_NAMESIZE] = HPT_DEVICE;
  hpt = hpt_alloc(name, 8192, on_hpt_packet, NULL, 100);

  const char *test_data = "Test hpt";


unsigned char ip_header[] = {
        0x45, 0x00, 0x00, 0x00, 
        0x1C, 0x46, 0x40, 0x00, 
        0x40, 0x11, 0x00, 0x00, 
        0xC0, 0xA8, 0x1F, 0xC8, // 192.168.31.200
        0xC0, 0xA8, 0x1F, 0xC9  // 192.168.31.201
    };

    unsigned char udp_header[] = {
        0x48, 0x1D, 0x6C, 0x5C,
        0x00, 0x00, 0x00, 0x00
    };

    //const char *payload = "Hello, hpt!";
    const size_t len = 1500;
    char payload[len];
    memset(payload, 'a', len);
    size_t payload_len = strlen(payload);

    size_t udp_len = sizeof(udp_header) + payload_len;
    size_t ip_len = sizeof(ip_header) + udp_len;

    ip_header[2] = (ip_len >> 8) & 0xFF;
    ip_header[3] = ip_len & 0xFF;

    udp_header[4] = (udp_len >> 8) & 0xFF;
    udp_header[5] = udp_len & 0xFF;

    unsigned char packet[ip_len];
    memcpy(packet, ip_header, sizeof(ip_header));
    memcpy(packet + sizeof(ip_header), udp_header, sizeof(udp_header));
    memcpy(packet + sizeof(ip_header) + sizeof(udp_header), payload, payload_len);



  while (true) 
  {
    switch(getchar())
    {
      case 'q': hpt_close(hpt); return 0;
      case 'w': hpt_send(packet, sizeof(packet)); break;
      case 'd': hpt_drain(hpt); break;
    }
  }

  return 0;
}

void hpt_send(unsigned char *packet, size_t packet_size)
{
  uint8_t i = 10;
  while(i > 0)
  {
    hpt_write(hpt, (uint8_t *)packet, packet_size);
    i--;
  }
}

void on_hpt_packet(void *handle, uint8_t *msg_content, size_t length) 
{
  printf("Received packet of size %zu\n", length);
  for(uint8_t i=0; i < length; i++)
  {
    printf("%c", msg_content[i]);
  }

}
