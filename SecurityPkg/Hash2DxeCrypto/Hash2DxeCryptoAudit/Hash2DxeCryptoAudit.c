//
// Uefi Shell based Application that Unit Tests and Audits the Hash2Protoco
//
// Copyright (C) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent
//

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/UnitTestLib.h>
#include <Library/DebugLib.h>
#include <Protocol/Hash2.h>
#include <Protocol/ServiceBinding.h>

#define UNIT_TEST_APP_NAME     "Hash 2 Dxe Crypto Audit Tests"
#define UNIT_TEST_APP_VERSION  "1.0"
//
// This is the handle for the Hash2ServiceBinding Protocol instance this driver produces
// if the platform does not provide one.
//
EFI_HANDLE  mHash2ServiceHandle = NULL;

STATIC
UNIT_TEST_STATUS
EFIAPI
TestLocateHash2Protocol (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS                    Status;
  EFI_SERVICE_BINDING_PROTOCOL  *Hash2ServiceBinding;
  EFI_HASH2_PROTOCOL            *Hash2Protocol;

  Status = gBS->LocateProtocol (&gEfiHash2ProtocolGuid, NULL, (VOID **)&Hash2Protocol);
  if (EFI_ERROR (Status)) {
    //
    // If we can't find the Hashing protocol, then we need to create one.
    //

    //
    // Platform is expected to publish the hash service binding protocol to support TCP.
    //
    Status = gBS->LocateProtocol (
                    &gEfiHash2ServiceBindingProtocolGuid,
                    NULL,
                    (VOID **)&Hash2ServiceBinding
                    );
    if (EFI_ERROR (Status) || (Hash2ServiceBinding == NULL) || (Hash2ServiceBinding->CreateChild == NULL)) {
      UT_ASSERT_NOT_EFI_ERROR (Status);
    }

    //
    // Create an instance of the hash protocol for this controller.
    //
    Status = Hash2ServiceBinding->CreateChild (Hash2ServiceBinding, &mHash2ServiceHandle);
    if (EFI_ERROR (Status)) {
      UT_ASSERT_NOT_EFI_ERROR (Status);
    }

    //
    // Now that an instance is binded - should be able to locate the protocol
    //
    Status = gBS->LocateProtocol (&gEfiHash2ProtocolGuid, NULL, (VOID **)&Hash2Protocol);
  }

  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_NOT_NULL (Hash2Protocol);

  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestHash2Md5 (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS          Status;
  EFI_HASH2_PROTOCOL  *Hash2;
  EFI_HASH2_OUTPUT    Hash;
  UINT8               Data[]   = "Test Data";
  UINTN               DataSize = sizeof (Data) - 1;

  Status = gBS->LocateProtocol (&gEfiHash2ProtocolGuid, NULL, (VOID **)&Hash2);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_NOT_NULL (Hash2);

  //
  // MD5Sum is no longer supported and should return EFI_UNSUPPORTED
  // *some* implementations have been known to crash when called
  //
  Status = Hash2->Hash (Hash2, &gEfiHashAlgorithmMD5Guid, Data, DataSize, &Hash);
  UT_ASSERT_EQUAL (Status, EFI_UNSUPPORTED);

  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestHash2Sha1 (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS          Status;
  EFI_HASH2_PROTOCOL  *Hash2;
  EFI_HASH2_OUTPUT    Hash;
  UINT8               Data[]   = "Test Data";
  UINTN               DataSize = sizeof (Data) - 1;

  Status = gBS->LocateProtocol (&gEfiHash2ProtocolGuid, NULL, (VOID **)&Hash2);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_NOT_NULL (Hash2);

  //
  // Sha1 is no longer supported and should return EFI_UNSUPPORTED
  // *some* implementations have been known to crash when called
  //
  Status = Hash2->Hash (Hash2, &gEfiHashAlgorithmSha1Guid, Data, DataSize, &Hash);
  UT_ASSERT_EQUAL (Status, EFI_UNSUPPORTED);

  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestHash2SHA256 (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS          Status;
  EFI_HASH2_PROTOCOL  *Hash2;
  EFI_HASH2_OUTPUT    Hash;
  UINT8               Data[]         = "Test Data";
  UINTN               DataSize       = sizeof (Data) - 1;
  UINT8               ExpectedHash[] = {
    0xBC, 0xFE, 0x67, 0x17, 0x2A, 0x6F, 0x40, 0x79,
    0xD6, 0x9F, 0xE2, 0xF2, 0x7A, 0x99, 0x60, 0xF9,
    0xD6, 0x2E, 0xDA, 0xE2, 0xFC, 0xD4, 0xBB, 0x5A,
    0x60, 0x6C, 0x2E, 0xBB, 0x74, 0xB3, 0xBA, 0x65
  };

  Status = gBS->LocateProtocol (&gEfiHash2ProtocolGuid, NULL, (VOID **)&Hash2);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_NOT_NULL (Hash2);

  //
  // Test SHA256
  //
  Status = Hash2->Hash (Hash2, &gEfiHashAlgorithmSha256Guid, Data, DataSize, &Hash);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_MEM_EQUAL (Hash.Sha256Hash, ExpectedHash, sizeof (ExpectedHash));

  //
  // Test SHA256 INIT/UPDATE/FINAL
  //
  Status = Hash2->HashInit (Hash2, &gEfiHashAlgorithmSha256Guid);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  Status = Hash2->HashUpdate (Hash2, Data, DataSize);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  Status = Hash2->HashFinal (Hash2, &Hash);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_MEM_EQUAL (Hash.Sha256Hash, ExpectedHash, sizeof (ExpectedHash));

  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestHash2SHA384 (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS          Status;
  EFI_HASH2_PROTOCOL  *Hash2;
  EFI_HASH2_OUTPUT    Hash;
  UINT8               Data[]         = "Test Data";
  UINTN               DataSize       = sizeof (Data) - 1;
  UINT8               ExpectedHash[] = {
    0x18, 0x50, 0x0E, 0x64, 0x2F, 0xAA, 0x93, 0x32,
    0x3D, 0x8B, 0x94, 0xE2, 0x88, 0xAB, 0x0F, 0xBE,
    0x83, 0x5A, 0x40, 0x3F, 0x0D, 0xDF, 0x2E, 0xA0,
    0xAF, 0x04, 0x53, 0x78, 0x6D, 0x3F, 0x26, 0x16,
    0x23, 0x7D, 0x85, 0xD7, 0x42, 0x14, 0xEB, 0x20,
    0x7C, 0xAD, 0x29, 0xA7, 0x0B, 0xD9, 0xD4, 0xEB
  };

  Status = gBS->LocateProtocol (&gEfiHash2ProtocolGuid, NULL, (VOID **)&Hash2);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_NOT_NULL (Hash2);

  //
  // Test SHA384
  //
  Status = Hash2->Hash (Hash2, &gEfiHashAlgorithmSha384Guid, Data, DataSize, &Hash);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_MEM_EQUAL (Hash.Sha384Hash, ExpectedHash, sizeof (ExpectedHash));

  //
  // Test SHA384 INIT/UPDATE/FINAL
  //
  Status = Hash2->HashInit (Hash2, &gEfiHashAlgorithmSha384Guid);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  Status = Hash2->HashUpdate (Hash2, Data, DataSize);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  Status = Hash2->HashFinal (Hash2, &Hash);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_MEM_EQUAL (Hash.Sha384Hash, ExpectedHash, sizeof (ExpectedHash));

  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestHash2SHA512 (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS          Status;
  EFI_HASH2_PROTOCOL  *Hash2;
  EFI_HASH2_OUTPUT    Hash;
  UINT8               Data[]         = "Test Data";
  UINTN               DataSize       = sizeof (Data) - 1;
  UINT8               ExpectedHash[] = {
    0x43, 0x9E, 0x4C, 0xEE, 0xD9, 0x31, 0x2F, 0xEF,
    0x2E, 0x55, 0x40, 0x42, 0xC3, 0xD2, 0x7D, 0x6A,
    0xC3, 0x1D, 0xA9, 0xCF, 0x72, 0xBA, 0x86, 0x6B,
    0xA9, 0xB0, 0xE0, 0x03, 0x28, 0xD0, 0x62, 0x80,
    0x79, 0x74, 0x82, 0xBF, 0x2C, 0xD0, 0x07, 0xE0,
    0x80, 0x82, 0x96, 0xDB, 0x0B, 0x98, 0x7B, 0x73,
    0xFE, 0x1F, 0x95, 0x3E, 0x97, 0xE2, 0x58, 0x83,
    0x26, 0x3B, 0x97, 0x83, 0x51, 0x3C, 0x29, 0x49
  };

  Status = gBS->LocateProtocol (&gEfiHash2ProtocolGuid, NULL, (VOID **)&Hash2);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_NOT_NULL (Hash2);

  //
  // Test SHA512
  //
  Status = Hash2->Hash (Hash2, &gEfiHashAlgorithmSha512Guid, Data, DataSize, &Hash);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_MEM_EQUAL (Hash.Sha384Hash, ExpectedHash, sizeof (ExpectedHash));

  //
  // Test SHA512 INIT/UPDATE/FINAL
  //
  Status = Hash2->HashInit (Hash2, &gEfiHashAlgorithmSha512Guid);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  Status = Hash2->HashUpdate (Hash2, Data, DataSize);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  Status = Hash2->HashFinal (Hash2, &Hash);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_MEM_EQUAL (Hash.Sha512Hash, ExpectedHash, sizeof (ExpectedHash));

  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestDestroyHash2ServiceBindingChild (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS                    Status;
  EFI_SERVICE_BINDING_PROTOCOL  *Hash2ServiceBinding;

  // Locate the Hash2 Service Binding Protocol
  Status = gBS->LocateProtocol (&gEfiHash2ServiceBindingProtocolGuid, NULL, (VOID **)&Hash2ServiceBinding);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_NOT_NULL (Hash2ServiceBinding);

  if (mHash2ServiceHandle != NULL) {
    // Destroy the child instance of the Hash2 Service Binding Protocol
    Status = Hash2ServiceBinding->DestroyChild (Hash2ServiceBinding, mHash2ServiceHandle);
    UT_ASSERT_NOT_EFI_ERROR (Status);
  }

  return UNIT_TEST_PASSED;
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                  Status;
  UNIT_TEST_FRAMEWORK_HANDLE  Framework = NULL;
  UNIT_TEST_SUITE_HANDLE      Hash2AuditTests;

  DEBUG ((DEBUG_INFO, "%a v%a\n", UNIT_TEST_APP_NAME, UNIT_TEST_APP_VERSION));

  Status = InitUnitTestFramework (&Framework, UNIT_TEST_APP_NAME, gEfiCallerBaseName, UNIT_TEST_APP_VERSION);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = CreateUnitTestSuite (&Hash2AuditTests, Framework, "Hash2AuditTests", "Hash2.Audit", NULL, NULL);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // -----------Suite------------Description-------Class---------Test Function-Pre---Clean-Context
  AddTestCase (Hash2AuditTests, "Test Locate Hash2 Protocol", "Hash2.Audit.TestLocateHash2Protocol", TestLocateHash2Protocol, NULL, NULL, NULL);
  AddTestCase (Hash2AuditTests, "Test Hash2 MD5", "Hash2.Audit.TestHash2Md5", TestHash2Md5, NULL, NULL, NULL);
  AddTestCase (Hash2AuditTests, "Test Hash2 SHA1", "Hash2.Audit.TestHash2Sha1", TestHash2Sha1, NULL, NULL, NULL);
  AddTestCase (Hash2AuditTests, "Test Hash2 SHA256", "Hash2.Audit.TestHash2SHA256", TestHash2SHA256, NULL, NULL, NULL);
  AddTestCase (Hash2AuditTests, "Test Hash2 SHA384", "Hash2.Audit.TestHash2SHA384", TestHash2SHA384, NULL, NULL, NULL);
  AddTestCase (Hash2AuditTests, "Test Hash2 SHA512", "Hash2.Audit.TestHash2SHA512", TestHash2SHA512, NULL, NULL, NULL);
  AddTestCase (Hash2AuditTests, "Test Destroy Hash2 Service Binding Child", "Hash2.Audit.TestDestroyHash2ServiceBindingChild", TestDestroyHash2ServiceBindingChild, NULL, NULL, NULL);

  Status = RunAllTestSuites (Framework);

  if (Framework) {
    FreeUnitTestFramework (Framework);
  }

  return Status;
}
