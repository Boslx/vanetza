#include "RouterIndicate.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <papi.h>
#include <stdio.h>
#include <stdlib.h>

void handle_error (int retval)
{
    printf("PAPI error %d: %s\n", retval, PAPI_strerror(retval));
    exit(1);
}

ByteBuffer readFileToByteArray(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return {};
    }

    const std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    ByteBuffer buffer(size);
    if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
        std::cerr << "Error reading file: " << filename << std::endl;
        return {};
    }

    return buffer;
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

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <filepath>" << std::endl;
        return 1;
    }

    const std::string filename = argv[1];
    const ByteBuffer byteArray = readFileToByteArray(filename);

    if (byteArray.empty()) {
        return 1;
    }

    int retval;
    int eventSet = PAPI_NULL;
    long_long values[1];

    setupPAPI(retval, eventSet);

    RouterIndicate routerIndicate;
    routerIndicate.SetUp();

    std::ofstream outfile;
    outfile.open("test.txt", std::ios_base::app);

    for(int i = 0; i < 100; i++) {
        retval = PAPI_reset(eventSet);
        if (retval != PAPI_OK)
            handle_error(retval);

        routerIndicate.router.indicate(routerIndicate.get_up_packet(byteArray),
                                   routerIndicate.mac_address_sender,
                                   routerIndicate.mac_address_destination);

        retval = PAPI_read(eventSet, values);
        if (retval != PAPI_OK)
            handle_error(retval);

        outfile << "\n" << values[0] << ", " <<  byteArray.size();
    }

    /* Stop the counting of events in the Event Set */
    retval = PAPI_stop(eventSet, values);
    if (retval != PAPI_OK)
        handle_error(retval);

    return 0;
}
