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

    while (true) 
    {
        switch(getchar())
        {
            case 'q': 
                hpt_close(hpt); 
                return 0;
            case 'w': 
                hpt_write(hpt, NULL); 
                break;
            case 'r': 
                hpt_read(hpt, NULL); 
                break;
        }
    }    

    return 0;
}