#define ABCD

#include <stdio.h>
#include <unistd.h>
#include "RouterIndicate.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <stdio.h>
#ifdef ABCD
#include <papi.h>
#include "Base64.h"
#endif



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


#ifdef ABCD
void handle_error (int retval)
{
    printf("PAPI error %d: %s\n", retval, PAPI_strerror(retval));
    exit(1);
}

void setupPAPI(int &retval, int &eventSet) {
    /* Initialize the PAPI library */
    retval = PAPI_library_init(PAPI_VER_CURRENT);
    if (retval != PAPI_VER_CURRENT)
        handle_error(retval);

    /* Create the Event Set */
    retval = PAPI_create_eventset(&eventSet);
    if (retval != PAPI_OK)
        handle_error(retval);

    /* Add Total Instructions Executed to our Event Set */
    retval = PAPI_add_event(eventSet, PAPI_TOT_INS);
    if (retval != PAPI_OK)
        handle_error(retval);

    /* Start counting events in the Event Set */
    retval = PAPI_start(eventSet);
    if (retval != PAPI_OK)
        handle_error(retval);
}
#endif

int main() {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

#ifdef ABCD
    int retval;
    int eventSet = PAPI_NULL;
    long_long values[1];

    setupPAPI(retval, eventSet);
#endif
    RouterIndicate routerIndicate;
    routerIndicate.SetUp();

    std::ofstream outfile;
    outfile.open("fuzzStat.csv", std::ios_base::app);

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;

        ByteBuffer buffer = ByteBuffer(buf, buf + len);

#ifdef ABCD
        retval = PAPI_reset(eventSet);
        if (retval != PAPI_OK)
            handle_error(retval);
#endif

        routerIndicate.router.indicate(routerIndicate.get_up_packet(buffer),
                                       routerIndicate.mac_address_sender,
                                       routerIndicate.mac_address_destination);
#ifdef ABCD
        retval = PAPI_read(eventSet, values);
        if (retval != PAPI_OK)
            handle_error(retval);

        if(values[0]>39700000) {
            outfile << "\n" << values[0] << ", " <<  len << ", " << base64::encode(buffer);
        }
#endif
    }
#ifdef ABCD
    /* Stop the counting of events in the Event Set */
    retval = PAPI_stop(eventSet, values);
    if (retval != PAPI_OK)
        handle_error(retval);
#endif
    return 0;
}
