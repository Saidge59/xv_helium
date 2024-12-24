#include "hpt_lib.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

int main() {
    hpt_handle_t *handle = hpt_open();
    if (!handle) {
        return 1;
    }

    char read_buf[HPT_BUFFER_SIZE];

    while (true) 
    {
        switch(getchar())
        {
        case 'q': hpt_close(handle); return 0;
        case 's': hpt_send(handle); break;
        case 'w': hpt_write(handle); break;
        case 'r': hpt_read(handle, read_buf, sizeof(read_buf)); break;
        }
    }

    return 0;
}