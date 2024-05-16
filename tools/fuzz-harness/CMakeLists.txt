find_package(Threads REQUIRED)
find_package(PAPI REQUIRED)

include_directories(${PAPI_INCLUDE_DIRS})

add_executable(routerIndicatePersistentFuzz
        router_indicate_fuzz.cpp
        RouterIndicate.h
)
target_link_libraries(routerIndicatePersistentFuzz PUBLIC Boost::system Boost::program_options vanetza ${PAPI_LIBRARIES})
install(TARGETS routerIndicatePersistentFuzz EXPORT ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

add_executable(routerIndicateTest
        router_indicate_test.cpp
        RouterIndicate.h
)
target_compile_definitions(routerIndicateTest PUBLIC NDEBUG)
target_compile_options(routerIndicateTest PUBLIC -Wall)
# target_compile_options(routerIndicateTest PRIVATE -fsanitize=address)
target_link_libraries(routerIndicateTest PUBLIC Boost::system Boost::program_options vanetza ${PAPI_LIBRARIES})
install(TARGETS routerIndicateTest EXPORT ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})