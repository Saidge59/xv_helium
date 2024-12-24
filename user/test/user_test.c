#include "hpt_lib.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

int main() 
{
    hpt_init();

    const char name[HPT_NAMESIZE] = HPT_DEVICE;
    struct hpt *hpt = hpt_alloc(name, 10);
    if (!hpt) {
        return -1;
    }
    
    hpt_buffer_t *tx_buf = NULL;
    hpt_buffer_t *rx_buf = NULL;

    while (true) 
    {
        switch(getchar())
        {
            case 'q': 
                hpt_close(hpt); 
                //free(tx_buf); 
                //free(rx_buf); 
                return 0;
            case 'w': 
                hpt_write(hpt, tx_buf); 
                break;
            case 'r': 
                hpt_read(hpt, rx_buf); 
                break;
        }
    }    

    return 0;
}