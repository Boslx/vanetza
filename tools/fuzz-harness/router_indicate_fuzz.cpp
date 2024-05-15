#include <stdio.h>
#include <unistd.h>
#include "RouterIndicate.h"


#ifndef __AFL_FUZZ_TESTCASE_LEN
ssize_t fuzz_len;
#define __AFL_FUZZ_TESTCASE_LEN fuzz_len
unsigned char fuzz_buf[1024000];
#define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
#define __AFL_FUZZ_INIT() void sync(void);
#define __AFL_LOOP(x) ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
#define __AFL_INIT() sync()
#endif

__AFL_FUZZ_INIT();

int main() {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    RouterIndicate routerIndicate;
    routerIndicate.SetUp();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;

        ByteBuffer buffer = ByteBuffer(buf, buf + len);

        routerIndicate.router.indicate(routerIndicate.get_up_packet(buffer),
                                       routerIndicate.mac_address_sender,
                                       routerIndicate.mac_address_destination);
    }

    return 0;
}
