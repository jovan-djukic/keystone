set(eapp_bin relay)
# QTEE_ROOT is passed in by overlays/keystone/package/keystone-examples.
# (Not derived from CMAKE_CURRENT_SOURCE_DIR: Buildroot builds a staged copy
# of this tree, from which ../../../.. is not the project root.)
if(NOT DEFINED QTEE_ROOT)
  message(FATAL_ERROR "QTEE_ROOT (QTEE-V project root) must be set")
endif()

# The enclave builds the project's own relay.c (no copy in this tree), so the
# enclave relay can never drift from the native one.
set(eapp_src ${QTEE_ROOT}/relay.c)
set(host_bin relay-runner)
set(host_src host/host.cpp)
set(package_name "relay.ke")

set(package_script "./relay-runner relay eyrie-rt loader.bin")
# set(eyrie_plugins "io_syscall linux_syscall net_syscall env_setup internal_strace debug")
set(eyrie_plugins "io_syscall linux_syscall net_syscall env_setup")

# eapp

# Absolute path, not relative: Buildroot's "local" site method physically
# copies this source tree into an isolated build directory before compiling
# (build-generic64/buildroot.build/build/keystone-examples-<hash>/), and
# external/wolfssl and relay.c live outside external/keystone entirely, so
# they're never part of that copy. A relative path resolves fine from the
# original source location but silently breaks once staged there.
set(WOLFSSL_RISCV_DIR "${QTEE_ROOT}/external/wolfssl/_install_riscv"
    CACHE PATH "Path to the RISC-V WolfSSL install (see build_wolfssl_variants.sh)")

add_executable(${eapp_bin} ${eapp_src})
target_link_libraries(${eapp_bin} PRIVATE "-static" ${WOLFSSL_RISCV_DIR}/lib/libwolfssl.a)
target_link_libraries(${eapp_bin} PRIVATE m)
target_include_directories(${eapp_bin} PRIVATE ${WOLFSSL_RISCV_DIR}/include)

# Enables the real Keystone enclave attestation path in relay.c (raw RISC-V
# ecall to the security monitor via attest_enclave()) instead of the SHA256
# dev-fallback report used when building/running outside an enclave.
target_compile_definitions(${eapp_bin} PRIVATE RISC_V_ATTESTATION)

# host

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE})

# add target for Eyrie runtime (see keystone.cmake)

set(eyrie_files_to_copy .options_log eyrie-rt loader.bin)
add_eyrie_runtime(${eapp_bin}-eyrie
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

# add target for packaging (see keystone.cmake)

add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} ${eapp_bin} ${host_bin})

add_dependencies(${eapp_bin}-package ${eapp_bin}-eyrie)

# add package to the top-level target
add_dependencies(examples ${eapp_bin}-package)