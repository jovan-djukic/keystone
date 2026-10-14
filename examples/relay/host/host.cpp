//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------

#include <cstdio>
#include <cstring>

#include "edge/edge_call.h"
#include "host/keystone.h"

using namespace Keystone;

// Usage: relay-runner <eapp> <runtime> <loader> [--measure]
//
// --measure prints the SHA3-512 measurement the Security Monitor will put in
// this enclave's attestation report, computed from the binaries on disk
// (same Enclave::measure() the attestation example's verifier uses), and
// exits without launching. That is the value to pin in the controller with
// --enclave-measurement.
int
main(int argc, char** argv) {
  if (argc < 4) {
    fprintf(stderr, "Usage: %s <eapp> <runtime> <loader> [--measure]\n", argv[0]);
    return 1;
  }

  if (argc > 4 && strcmp(argv[4], "--measure") == 0) {
    unsigned char hash[MDSIZE];
    if (Enclave::measure((char*)hash, argv[1], argv[2], argv[3]) != Error::Success) {
      fprintf(stderr, "measure failed\n");
      return 1;
    }
    for (int i = 0; i < MDSIZE; i++) printf("%02x", hash[i]);
    printf("\n");
    return 0;
  }

  Enclave enclave;
  Params params;

  params.setFreeMemSize(200 * 1024 * 1024);
  params.setUntrustedSize(1024 * 1024);

  enclave.init(argv[1], argv[2], argv[3], params);

  enclave.registerOcallDispatch(incoming_call_dispatch);
  edge_call_init_internals(
      (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

  enclave.run();

  return 0;
}
