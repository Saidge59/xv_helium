#include "hpt_lib.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

int main() 
{
    hpt_init();

    const char name[HPT_NAMESIZE] = HPT_DEVICE;
    struct hpt *hpt = hpt_alloc(name, 8192);
    if (!hpt) {
        return -1;
    }
    
    hpt_buffer_t rx_buf;
    memset(&rx_buf, 0, sizeof(rx_buf));

    rx_buf.base = malloc(sizeof(hpt_buffer_t));

    while (true) 
    {
        switch(getchar())
        {
            case 'q': 
                hpt_close(hpt); 
                free(rx_buf.base); 
                return 0;
            case 'w': 
                hpt_write(hpt, NULL); 
                break;
            case 'r': 
                hpt_read(hpt, &rx_buf); 
                break;
        }
    }    

    return 0;
}