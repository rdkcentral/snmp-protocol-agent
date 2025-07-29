/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2024 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include "snmp_mock.h"

extern "C" {
    #include "ccsp_mib_helper.h"
    #include "ccsp_scalar_helper.h"
    #include "ccsp_table_helper.h"
    #include "ccsp_mib_utilities.h"
    #include "cosa_api.h"
    #include "print_uptime.h"
}

using namespace testing;

extern SafecLibMock* g_safecLibMock;
extern AnscMemoryMock * g_anscMemoryMock;
extern BaseAPIMock * g_baseapiMock;
extern AnscWrapperApiMock * g_anscWrapperApiMock;
extern netsnmpMock *g_netsnmpMock;
extern SlapMock * g_slapMock;

/************************Internal Functions**************************/
//Test for CcspUtilCleanMibValueQueueAsnOctetStr - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilCleanMibValueQueueAsnOctetStrSuccess)
{
    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    pMibValue->uType = ASN_OCTET_STR; 
    pMibValue->Linkage.Next =  NULL;
    pMibValue->Value.pBuffer = strdup("SampleValue");
    pMibValue->BackValue.pBuffer = strdup("SampleBackValue");

    // Initialize the queue header
    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMibValue;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    CcspUtilCleanMibValueQueue(pQueueHeader);
    // Clean up
    free(pMibValue->Value.pBuffer);
    free(pMibValue->BackValue.pBuffer);
    free(pMibValue);
    free(pQueueHeader);
}

//Test for CcspUtilCleanMibValueQueueAsnBitStr - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilCleanMibValueQueueAsnBitStrSuccess)
{
    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    pMibValue->uType = ASN_BIT_STR; 
    pMibValue->Linkage.Next =  NULL;
    pMibValue->Value.pBuffer = strdup("SampleValue");
    pMibValue->BackValue.pBuffer = strdup("SampleBackValue");

    // Initialize the queue header
    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMibValue;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    CcspUtilCleanMibValueQueue(pQueueHeader);
    // Clean up
    free(pMibValue->Value.pBuffer);
    free(pMibValue->BackValue.pBuffer);
    free(pMibValue);
    free(pQueueHeader);
}

//Test for CcspUtilCleanMibObjQueue - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilCleanMibObjQueueSuccess)
{
    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    PCCSP_MIB_MAPPING pMibMap = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMibMap, 0, sizeof(CCSP_MIB_MAPPING));

    pMibMap->MibInfo.uType = ASN_OCTET_STR;
    pMibMap->MibInfo.uLastOid = 1002;
    strcpy(pMibMap->MibInfo.pType, "MacAddress");

    // Initialize the queue header
    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMibMap;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    CcspUtilCleanMibObjQueue(pQueueHeader);
    // Clean up
    free(pMibMap);
    free(pQueueHeader);
}
//Test for CcspUtilCleanIndexMapQueue - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilCleanIndexMapQueueSuccess)
{
    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));


    PCCSP_INDEX_MAPPING pMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pMapping->Linkage.Next = NULL;
    pMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    // Initialize the queue header
    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMapping;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    CcspUtilCleanIndexMapQueue(pQueueHeader);
    // Clean up
    free(pInsNumberMap);
    free(pMapping);
    free(pQueueHeader);

}

//Test for CcspUtilCleanMibMapping - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilCleanMibMappingSuccess)
{
    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));

    pIntStringMap->Linkage.Next = NULL;
    pIntStringMap->pString = strdup("SampleString");
    pIntStringMap->EnumCode = 2;
    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    CcspUtilCleanMibMapping(pMapping);
    // Clean up
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
}

//Test for CcspUtilCleanIndexMappingInsNumber - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilCleanIndexMappingInsNumberSuccess)
{
    PCCSP_INDEX_MAPPING pMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pMapping->Linkage.Next = NULL;
    pMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    CcspUtilCleanIndexMapping(pMapping);
    // Clean up
    free(pInsNumberMap);
    free(pMapping);
}

//Test for CcspUtilCleanIndexMappingMapToDm - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilCleanIndexMappingMapToDmSuccess)
{
    PCCSP_INDEX_MAPPING pMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->Linkage.Next = NULL;
    pIntStringMap->pString = strdup("SampleString");
    pIntStringMap->EnumCode = 2;

    pMapping->Linkage.Next = NULL;
    pMapping->uMapType = CCSP_MIB_MAP_TO_DM;
    pMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    CcspUtilCleanIndexMapping(pMapping);
    // Clean up
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
}

//Test for CcspUtilParseOidValueString - Failure
TEST_F(CcspSnmpPaTestFixture, CcspUtilParseOidValueStringFailure)
{
    char* oidString = "1,3,6,1,4491";
    oid oidArray[MAX_OID_LEN];
    ULONG size = 0;

    // Create a fake token chain (dummy content, not used directly)
    PANSC_TOKEN_CHAIN pTokenChain = NULL;
    
    EXPECT_CALL(*g_anscWrapperApiMock, AnscTcAllocate(_,_))
                .Times(1)
                .WillOnce(Return(pTokenChain));
    /*EXPECT_CALL(*g_anscWrapperApiMock, AnscTcPopToken(_))
                .Times(1)
                .WillOnce(Return(static_cast<ANSC_HANDLE>(nullptr)));*/
    
    // Call the actual function
    BOOL result = CcspUtilParseOidValueString(oidString, oidArray, &size);
    EXPECT_EQ(result, FALSE);
    free(pTokenChain);
}

//Test for CcspUtilMIBStringToDataType - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBStringToDataTypeSuccess)
{
    char* mibString = "ASN_INTEGER";

    ULONG dataType = CcspUtilMIBStringToDataType(mibString);
    EXPECT_EQ(dataType, 0);
}

//Test for CcspUtilTR69StringToDataType - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilTR69StringToDataTypeSuccess)
{
    char* tr69String = "int";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    ULONG dataType = CcspUtilTR69StringToDataType(tr69String);
    EXPECT_EQ(dataType, CCSP_TR69_DataType_int);
}

//Test for CcspUtilTR69StringToDataType - Failure
TEST_F(CcspSnmpPaTestFixture, CcspUtilTR69StringToDataTypeFailure)
{
    char* tr69String = "int";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(6)
                .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(1)));

    ULONG dataType = CcspUtilTR69StringToDataType(tr69String);
    EXPECT_EQ(dataType, CCSP_TR69_DataType_string);
}

//Test for CcspUtilTR69DataTypeToString - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilTR69DataTypeToStringSuccess)
{
    ULONG dataType = CCSP_TR69_DataType_int;
    char buffer[256];

    CcspUtilTR69DataTypeToString(dataType, buffer);
}

//Test for CcspUtilLoadMibInfo - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilLoadMibInfoSuccess)
{
    extern ANSC_HANDLE g_pMyChildNode;
    MyCreateFunction();

    if(g_pMyChildNode != NULL)
    {
        PCCSP_MIB_INFO pInfo = (PCCSP_MIB_INFO)malloc(sizeof(CCSP_MIB_INFO));
        PQUEUE_HEADER pQueue = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
        PANSC_XML_DOM_NODE_OBJECT pNode = (PANSC_XML_DOM_NODE_OBJECT)g_pMyChildNode;

        EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                    .Times(1)
                    .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));
        EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                    .Times(3)
                    .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
        EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                    .Times(1)
                    .WillOnce(Return(0));

        CcspUtilLoadMibInfo(pInfo, pQueue, pNode);

        free(g_pMyChildNode);
        g_pMyChildNode = NULL;
    
        free(pInfo);
        free(pQueue);
    }
}

//Test for CcspUtilLoadDMMappingInfo - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilLoadDMMappingInfoSuccess)
{
    extern ANSC_HANDLE g_pMyChildNode;
    MyCreateFunction();

    if(g_pMyChildNode != NULL)
    {
        PCCSP_DM_MAPPING_INFO pInfo = (PCCSP_DM_MAPPING_INFO)malloc(sizeof(CCSP_DM_MAPPING_INFO));
        PQUEUE_HEADER pQueue = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
        PANSC_XML_DOM_NODE_OBJECT pNode = (PANSC_XML_DOM_NODE_OBJECT)g_pMyChildNode;
        
        PANSC_TOKEN_CHAIN pTokenChain = NULL;

        PANSC_TOKEN_CHAIN pTokenChain = NULL;
        //memset(pTokenChain, 0, sizeof(ANSC_TOKEN_CHAIN));
        //pTokenChain->TokensQueue.Depth = 1;

        EXPECT_CALL(*g_anscWrapperApiMock, AnscTcAllocate(_,_))
                    .Times(1)
                    .WillOnce(Return(pTokenChain));

        EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                    .Times(1)
                    .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

        CcspUtilLoadDMMappingInfo(pInfo, pQueue, pNode);

        free(g_pMyChildNode);
        g_pMyChildNode = NULL;
        
        free(pTokenChain);
        free(pInfo);
        free(pQueue);
    }
}

//Test for CcspUtilLoadIndexMappingInfo - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilLoadIndexMappingInfoSuccess)
{
    extern ANSC_HANDLE g_pMyChildNode;
    MyCreateFunction();

    if(g_pMyChildNode != NULL)
    {
        PCCSP_INDEX_MAPPING_INFO pInfo = (PCCSP_INDEX_MAPPING_INFO)malloc(sizeof(CCSP_INDEX_MAPPING_INFO));
        PQUEUE_HEADER pQueue = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
        PANSC_XML_DOM_NODE_OBJECT pNode = (PANSC_XML_DOM_NODE_OBJECT)g_pMyChildNode;

        pQueue->Next.Next = NULL;
        pQueue->Depth     = 0;
        pQueue->Last.Next = NULL;

        CcspUtilLoadIndexMappingInfo(pInfo, pQueue, pNode);

        free(g_pMyChildNode);
        g_pMyChildNode = NULL;
    
        free(pInfo);
        free(pQueue);
    }
}

//Test for CcspUtilLoadMibMappingInfo - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilLoadMibMappingInfoSuccess)
{
    extern ANSC_HANDLE g_pMyChildNode;
    MyCreateFunction();

    if(g_pMyChildNode != NULL)
    {
        PANSC_XML_DOM_NODE_OBJECT pNode = (PANSC_XML_DOM_NODE_OBJECT)g_pMyChildNode;
    
        PANSC_TOKEN_CHAIN pTokenChain = NULL;
        //memset(pTokenChain, 0, sizeof(ANSC_TOKEN_CHAIN));
        //pTokenChain->TokensQueue.Depth = 1;

        EXPECT_CALL(*g_anscWrapperApiMock, AnscTcAllocate(_,_))
                    .Times(1)
                    .WillOnce(Return(pTokenChain));
        EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                    .Times(2)
                    .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
        EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                    .Times(3)
                    .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
        EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                    .Times(1)
                    .WillOnce(Return(0));

        CcspUtilLoadMibMappingInfo(pNode);

        free(g_pMyChildNode);
        g_pMyChildNode = NULL;

        free(pTokenChain);
    }
}

//Test for CcspUtilLoadIndexMapping - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilLoadIndexMappingSuccess)
{
    extern ANSC_HANDLE g_pMyChildNode;
    MyCreateFunction();

    if(g_pMyChildNode != NULL)
    {
        PANSC_XML_DOM_NODE_OBJECT pNode = (PANSC_XML_DOM_NODE_OBJECT)g_pMyChildNode;

        EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                    .Times(1)
                    .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));
        EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                    .Times(3)
                    .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
        EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                    .Times(1)
                    .WillOnce(Return(0));

        CcspUtilLoadIndexMapping(pNode);

        free(g_pMyChildNode);
        g_pMyChildNode = NULL;
    }
}

//Test for CcspUtilTraceOid - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilTraceOidSuccess)
{
    oid oidArray[] = {1, 3, 6, 1, 4, 1, 4491};
    ULONG size = sizeof(oidArray) / sizeof(oidArray[0]);

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .Times(1)
                .WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .Times(8)
                .WillRepeatedly(Return(0));

    CcspUtilTraceOid(oidArray, size);
}

//Test for CcspUtilInitMibValueArray - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilInitMibValueArraySuccess)
{
    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    PCCSP_MIB_MAPPING pMibMap = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMibMap, 0, sizeof(CCSP_MIB_MAPPING));

    pMibMap->MibInfo.uType = ASN_OCTET_STR;
    pMibMap->MibInfo.uLastOid = 1002;
    strcpy(pMibMap->MibInfo.pType, "MacAddress");

    // Initialize the queue header
    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMibMap;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PQUEUE_HEADER pQueueHeaderOut = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeaderOut, 0, sizeof(QUEUE_HEADER));

    pQueueHeaderOut->Next.Next = NULL;
    pQueueHeaderOut->Last.Next = NULL;
    pQueueHeaderOut->Depth = 0;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    CcspUtilInitMibValueArray(pQueueHeader, pQueueHeaderOut);

    free(pMibMap);
    free(pQueueHeader);
    free(pQueueHeaderOut);
}

//Test for CcspUtilLookforMibValueObjWithOid - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilLookforMibValueObjWithOidSuccess)
{
    oid uLastOid = 1002;
    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    pMibValue->uLastOid = 1002;
    pMibValue->uType = ASN_OCTET_STR; 
    pMibValue->Linkage.Next =  NULL;
    pMibValue->Value.pBuffer = strdup("SampleValue");
    pMibValue->BackValue.pBuffer = strdup("SampleBackValue");

    // Initialize the queue header
    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMibValue;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PCCSP_MIB_VALUE pMibValueOut = CcspUtilLookforMibValueObjWithOid(pQueueHeader, uLastOid);
    EXPECT_EQ(pMibValueOut->uLastOid, pMibValue->uLastOid);

    free(pMibValue->Value.pBuffer);
    free(pMibValue->BackValue.pBuffer);
    free(pMibValue);
    free(pQueueHeader);
}

//Test for CcspUtilLookforMibMapWithOid - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilLookforMibMapWithOidSuccess)
{
    oid uLastOid = 1002;
    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_MIB_MAPPING pMibMap = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    pMibMap->MibInfo.uLastOid = 1002;
    pMibMap->MibInfo.uType = ASN_OCTET_STR; 
    strcpy(pMibMap->MibInfo.pType, "MacAddress");

    // Initialize the queue header
    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMibMap;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PCCSP_MIB_MAPPING pMibMapOut = CcspUtilLookforMibMapWithOid(pQueueHeader, uLastOid);
    EXPECT_EQ(pMibMapOut->MibInfo.uLastOid, pMibMap->MibInfo.uLastOid);

    free(pMibMap);
    free(pQueueHeader);
}

//Test for CcspUtilLookforEnumMapping - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilLookforEnumMappingSuccess)
{
    ULONG uEnumCode = 2;
    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    // Initialize the queue header
    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PCCSP_INT_STRING_MAP pIntStringMapOut = CcspUtilLookforEnumMapping(pQueueHeader, uEnumCode);
    EXPECT_EQ(pIntStringMapOut->EnumCode, pIntStringMap->EnumCode);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pQueueHeader);
}

//Test for CcspUtilLookforEnumStrInMapping - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilLookforEnumStrInMappingSuccess)
{
    char* pString = "SampleString";
    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    // Initialize the queue header
    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    ULONG EnumCode = CcspUtilLookforEnumStrInMapping(pQueueHeader, pString);
    EXPECT_EQ(EnumCode, pIntStringMap->EnumCode);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pQueueHeader);
}

//Test for CcspUtilLookforInsNumMapping - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilLookforInsNumMappingSuccess)
{
    ULONG uMibValue = 1;
    ULONG uDMValue = 2;
    int value = 0;
    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->Linkage.Next =  NULL;
    pInsNumberMap->uDMValue = 2;

    // Initialize the queue header
    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    value = CcspUtilLookforInsNumMapping(pQueueHeader, uMibValue, TRUE);
    EXPECT_EQ(value, pInsNumberMap->uDMValue);

    value = CcspUtilLookforInsNumMapping(pQueueHeader, uDMValue, FALSE);
    EXPECT_EQ(value, pInsNumberMap->uMibValue);

    free(pInsNumberMap);
    free(pQueueHeader);
}

//Test for CcspUtilDMFilterToNamespace - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilDMFilterToNamespaceSuccess)
{
    unsigned int* value = (unsigned int*)malloc(sizeof(unsigned int));
    value[0] = 1;
    char * temp = "testvalue";
    char* pFilter = "Device.myTable.%d.test.myType = 1";
    char* pDestName = (char*)malloc(sizeof(char) * 256);
    memset(pDestName, 0, sizeof(char) * 256);
    char* pPathName = (char*)malloc(sizeof(char) * 256);
    memset(pPathName, 0, sizeof(char) * 256);

    componentStruct_t *componentStruct = (componentStruct_t *)malloc(sizeof(componentStruct_t));
    memset(componentStruct, 0, sizeof(componentStruct_t));

    componentStruct->componentName = strdup("testComponent");
    componentStruct->dbusPath = strdup("/test/dbus/path");
    componentStruct->type = static_cast<dataType_e>(ASN_INTEGER);
    componentStruct->remoteCR_name = strdup("testRemoteCR");
    componentStruct->remoteCR_dbus_path = strdup("/test/remote/cr/dbus/path");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = static_cast<dataType_e>(ASN_INTEGER);

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<4>(&componentStruct), SetArgPointee<5>(1), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .Times(3)
                .WillOnce(Return(componentStruct->componentName))
                .WillOnce(Return(componentStruct->dbusPath))
                .WillOnce(Return(temp));
    EXPECT_CALL(*g_baseapiMock, free_componentStruct_t(_,_,_));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_GetNextLevelInstances(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<4>(1), SetArgPointee<5>(value), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                    .Times(1)
                    .WillOnce(Return(0));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_,_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<5>(1), SetArgPointee<6>(&paramValStruct), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .Times(1)
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                    .Times(1)
                    .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_,_,_));

    CcspUtilDMFilterToNamespace(pFilter, &pDestName, &pPathName);

    free(pDestName);
    free(pPathName);
    free(componentStruct->remoteCR_name);
    free(componentStruct->remoteCR_dbus_path);
    free(componentStruct);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
}

//Test for CcspUtilDMValueToMIBBool - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilDMValueToMIBBoolSuccess)
{
    char* pValue = "12";
    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.bIsRowStatus = TRUE;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValue, 0, sizeof(CCSP_MIB_VALUE));

    pMibValue->uType = ASN_OCTET_STR;
    pMibValue->uLastOid = 1002;
    pMibValue->Value.pBuffer = strdup("SampleValue");
    pMibValue->BackValue.pBuffer = strdup("SampleBackValue");
    pMibValue->uSize = 1;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(1)
                .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));

    CcspUtilDMValueToMIB(pMapping, pMibValue, ccsp_boolean, pValue);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pMibValue);
}

//Test for CcspUtilDMValueToMIBBool - failure
TEST_F(CcspSnmpPaTestFixture, CcspUtilDMValueToMIBBoolFailure)
{
    char* pValue = "12";
    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.bIsRowStatus = TRUE;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValue, 0, sizeof(CCSP_MIB_VALUE));

    pMibValue->uType = ASN_OCTET_STR;
    pMibValue->uLastOid = 1002;
    pMibValue->Value.pBuffer = strdup("SampleValue");
    pMibValue->BackValue.pBuffer = strdup("SampleBackValue");
    pMibValue->uSize = 1;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(2)
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    CcspUtilDMValueToMIB(pMapping, pMibValue, ccsp_boolean, pValue);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pMibValue);
}

//Test for CcspUtilDMValueToMIBSTR - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilDMValueToMIBSTRSuccess)
{
    char* pValue = "12";
    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValue, 0, sizeof(CCSP_MIB_VALUE));

    pMibValue->uType = ASN_OCTET_STR;
    pMibValue->uLastOid = 1002;
    pMibValue->Value.pBuffer = strdup("SampleValue");
    pMibValue->BackValue.pBuffer = strdup("SampleBackValue");
    pMibValue->uSize = 1;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    CcspUtilDMValueToMIB(pMapping, pMibValue, ccsp_string, pValue);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pMibValue);
}

//Test for CcspUtilDMValueToMIBSTR - Failure
TEST_F(CcspSnmpPaTestFixture, CcspUtilDMValueToMIBSTRFailure)
{
    char* pValue = "12";
    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValue, 0, sizeof(CCSP_MIB_VALUE));

    pMibValue->uType = ASN_OCTET_STR;
    pMibValue->uLastOid = 1002;
    pMibValue->Value.pBuffer = strdup("SampleValue");
    pMibValue->BackValue.pBuffer = strdup("SampleBackValue");
    pMibValue->uSize = 1;

    PANSC_UNIVERSAL_TIME pTime = (PANSC_UNIVERSAL_TIME)malloc(sizeof(ANSC_UNIVERSAL_TIME));
    memset(pTime, 0, sizeof(ANSC_UNIVERSAL_TIME));
    pTime->Year = 2021;
    pTime->Month = 10;
    pTime->DayOfMonth = 10;
    pTime->Hour = 10;
    pTime->Minute = 10;
    pTime->Second = 10;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(3)
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_slapMock, SlapVcoStringToCalendarTime(_,_))
                .Times(1)
                .WillOnce(Return(pTime));

    CcspUtilDMValueToMIB(pMapping, pMibValue, ccsp_string, pValue);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pMibValue);
}

//Test for CcspUtilDMValueToMIBIPV - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilDMValueToMIBIPVSuccess)
{
    char* pValue = "12";
    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValue, 0, sizeof(CCSP_MIB_VALUE));

    pMibValue->uType = ASN_OCTET_STR;
    pMibValue->uLastOid = 1002;
    pMibValue->Value.pBuffer = strdup("SampleValue");
    pMibValue->BackValue.pBuffer = strdup("SampleBackValue");
    pMibValue->uSize = 1;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(4)
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    CcspUtilDMValueToMIB(pMapping, pMibValue, ccsp_string, pValue);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pMibValue);
}

//Test for CcspUtilDMValueToMIBBitStr - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilDMValueToMIBBitStrSuccess)
{
    char* pValue = "12";
    char pTemp[256] = "12";
    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValue, 0, sizeof(CCSP_MIB_VALUE));

    pMibValue->uType = ASN_BIT_STR;
    pMibValue->uLastOid = 1002;
    pMibValue->Value.pBuffer = strdup("SampleValue");
    pMibValue->BackValue.pBuffer = strdup("SampleBackValue");
    pMibValue->uSize = 1;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArrayArgument<0>(pTemp, pTemp+256), Return(0)));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    CcspUtilDMValueToMIB(pMapping, pMibValue, ccsp_string, pValue);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pMibValue);
}

//Test for CcspUtilDMValueToMIBStrInt - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilDMValueToMIBStrIntSuccess)
{
    char* pValue = "12";
    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValue, 0, sizeof(CCSP_MIB_VALUE));

    pMibValue->uType = ASN_INTEGER;
    pMibValue->uLastOid = 1002;
    pMibValue->Value.pBuffer = strdup("SampleValue");
    pMibValue->BackValue.pBuffer = strdup("SampleBackValue");
    pMibValue->uSize = 1;

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    CcspUtilDMValueToMIB(pMapping, pMibValue, ccsp_string, pValue);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pMibValue);
}

//Test for CcspUtilDMValueToMIBCcspInt - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilDMValueToMIBCcspIntSuccess)
{
    char* pValue = "12";
    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValue, 0, sizeof(CCSP_MIB_VALUE));

    pMibValue->uType = ASN_INTEGER;
    pMibValue->uLastOid = 1002;
    pMibValue->Value.pBuffer = strdup("SampleValue");
    pMibValue->BackValue.pBuffer = strdup("SampleBackValue");
    pMibValue->uSize = 1;

    CcspUtilDMValueToMIB(pMapping, pMibValue, ccsp_int, pValue);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pMibValue);
}

//Test for CcspUtilDMValueToMIBCcspIntC64 - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilDMValueToMIBCcspIntC64Success)
{
    char* pValue = "12";
    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValue, 0, sizeof(CCSP_MIB_VALUE));

    pMibValue->uType = ASN_COUNTER64;
    pMibValue->uLastOid = 1002;
    pMibValue->Value.pBuffer = strdup("SampleValue");
    pMibValue->BackValue.pBuffer = strdup("SampleBackValue");
    pMibValue->uSize = 1;

    CcspUtilDMValueToMIB(pMapping, pMibValue, ccsp_int, pValue);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pMibValue);
}

//Test for CcspUtilDMValueToMIBCcspBoolean - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilDMValueToMIBCcspBooleanSuccess)
{
    char* pValue = "12";
    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    strcpy(pMapping->MibInfo.pType, "TruthValue");

    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValue, 0, sizeof(CCSP_MIB_VALUE));

    pMibValue->uType = ASN_COUNTER64;
    pMibValue->uLastOid = 1002;
    pMibValue->Value.pBuffer = strdup("SampleValue");
    pMibValue->BackValue.pBuffer = strdup("SampleBackValue");
    pMibValue->uSize = 1;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(2)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    CcspUtilDMValueToMIB(pMapping, pMibValue, ccsp_boolean, pValue);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pMibValue);
}

//Test for CcspUtilDMValueToMIBCcspBoolean - Failure
TEST_F(CcspSnmpPaTestFixture, CcspUtilDMValueToMIBCcspBooleanFailure)
{
    char* pValue = "12";
    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    strcpy(pMapping->MibInfo.pType, "TruthValue");

    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValue, 0, sizeof(CCSP_MIB_VALUE));

    pMibValue->uType = ASN_COUNTER64;
    pMibValue->uLastOid = 1002;
    pMibValue->Value.pBuffer = strdup("SampleValue");
    pMibValue->BackValue.pBuffer = strdup("SampleBackValue");
    pMibValue->uSize = 1;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(2)
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    CcspUtilDMValueToMIB(pMapping, pMibValue, ccsp_boolean, pValue);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pMibValue);
}

//Test for CcspUtilDMValueToMIBCcspDateTime - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilDMValueToMIBCcspDateTimeSuccess)
{
    char* pValue = "12";
    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    strcpy(pMapping->MibInfo.pType, "TruthValue");

    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValue, 0, sizeof(CCSP_MIB_VALUE));

    pMibValue->uType = ASN_COUNTER64;
    pMibValue->uLastOid = 1002;
    pMibValue->Value.pBuffer = strdup("SampleValue");
    pMibValue->BackValue.pBuffer = strdup("SampleBackValue");
    pMibValue->uSize = 1;

    PANSC_UNIVERSAL_TIME pTime = (PANSC_UNIVERSAL_TIME)malloc(sizeof(ANSC_UNIVERSAL_TIME));
    memset(pTime, 0, sizeof(ANSC_UNIVERSAL_TIME));
    pTime->Year = 2021;
    pTime->Month = 10;
    pTime->DayOfMonth = 10;
    pTime->Hour = 10;
    pTime->Minute = 10;
    pTime->Second = 10;

    EXPECT_CALL(*g_slapMock, SlapVcoStringToCalendarTime(_,_))
                .Times(1)
                .WillOnce(Return(pTime));

    CcspUtilDMValueToMIB(pMapping, pMibValue, ccsp_dateTime, pValue);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pMibValue);
}

//Test for CcspUtilDMValueToMIBBitStrHex - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilDMValueToMIBBitStrHexSuccess)
{
    char* pValue = "12";
    ULONG ulTmpValue = 1232;
    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValue, 0, sizeof(CCSP_MIB_VALUE));

    pMibValue->uType = ASN_BIT_STR;
    pMibValue->uLastOid = 1002;
    pMibValue->Value.pBuffer = strdup("SampleValue");
    pMibValue->BackValue.pBuffer = strdup("SampleBackValue");
    pMibValue->uSize = 1;

    EXPECT_CALL(*g_anscWrapperApiMock, AnscGetStringUlongHex(_))
                .Times(1)
                .WillOnce(Return(ulTmpValue));

    CcspUtilDMValueToMIB(pMapping, pMibValue, ccsp_string, pValue);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pMibValue);
}

//Test for CcspUtilMIBValueToDMbIsRowStatusBool - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBValueToDMbIsRowStatusBoolSuccess)
{
    long value = RS_ACTIVE;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->MibInfo.bIsRowStatus = TRUE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = ccsp_boolean;

    netsnmp_variable_list *var = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(var, 0, sizeof(netsnmp_variable_list));

    var->val.integer = &value;

    CcspUtilMIBValueToDM(pMapping, paramValStruct, var);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(var);
}

//Test for CcspUtilMIBValueToDMbIsRowStatusBool - Failure
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBValueToDMbIsRowStatusBoolFailure)
{
    long value = RS_ACTIVE;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->MibInfo.bIsRowStatus = TRUE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = ccsp_none;

    netsnmp_variable_list *var = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(var, 0, sizeof(netsnmp_variable_list));

    var->val.integer = &value;

    CcspUtilMIBValueToDM(pMapping, paramValStruct, var);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(var);
}

//Test for CcspUtilMIBValueToDMCcspBool - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBValueToDMCcspBoolSuccess)
{
    long value = 1;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = ccsp_boolean;

    netsnmp_variable_list *var = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(var, 0, sizeof(netsnmp_variable_list));

    var->val.integer = &value;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    CcspUtilMIBValueToDM(pMapping, paramValStruct, var);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(var);
}

//Test for CcspUtilMIBValueToDMCcspInt - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBValueToDMCcspIntSuccess)
{
    long value = 1;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = ccsp_int;

    netsnmp_variable_list *var = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(var, 0, sizeof(netsnmp_variable_list));

    var->val.integer = &value;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    CcspUtilMIBValueToDM(pMapping, paramValStruct, var);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(var);
}

//Test for CcspUtilMIBValueToDMCcspString - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBValueToDMCcspStringSuccess)
{
    long value = 1;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = ccsp_string;

    netsnmp_variable_list *var = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(var, 0, sizeof(netsnmp_variable_list));

    var->val.integer = &value;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    CcspUtilMIBValueToDM(pMapping, paramValStruct, var);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(var);
}

//Test for CcspUtilMIBValueToDMOctetStr - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBValueToDMOctetStrSuccess)
{
    long value = 1;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = ccsp_string;

    netsnmp_variable_list *var = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(var, 0, sizeof(netsnmp_variable_list));

    var->val.integer = &value;
    var->val.bitstring = (u_char *)malloc(sizeof(u_char) * 5);
    var->val.bitstring[0] = 1;
    var->val.bitstring[1] = 2;
    var->val.bitstring[2] = 3;
    var->val.bitstring[3] = 4;
    var->val.bitstring[4] = 5;


    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(3)
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    CcspUtilMIBValueToDM(pMapping, paramValStruct, var);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(var->val.bitstring);
    free(var);
}

//Test for CcspUtilMIBValueToDMOctetIpv6 - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBValueToDMOctetIpv6Success)
{
    long value = 1;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = ccsp_string;

    netsnmp_variable_list *var = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(var, 0, sizeof(netsnmp_variable_list));

    var->val.integer = &value;
    var->val.bitstring = (u_char *)malloc(sizeof(u_char) * 16);
    var->val.bitstring[0] = 1;
    var->val.bitstring[1] = 2;
    var->val.bitstring[2] = 3;
    var->val.bitstring[3] = 4;
    var->val.bitstring[4] = 5;
    var->val.bitstring[5] = 6;
    var->val.bitstring[6] = 7;
    var->val.bitstring[7] = 8;
    var->val.bitstring[8] = 9;
    var->val.bitstring[9] = 10;
    var->val.bitstring[10] = 11;
    var->val.bitstring[11] = 12;
    var->val.bitstring[12] = 13;
    var->val.bitstring[13] = 14;
    var->val.bitstring[14] = 15;
    var->val.bitstring[15] = 16;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(4)
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(1)))
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    CcspUtilMIBValueToDM(pMapping, paramValStruct, var);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(var->val.bitstring);
    free(var);
}

//Test for CcspUtilMIBValueToDMOctetIpv6 - Failure
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBValueToDMOctetIpv6Failure)
{
    long value = 1;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = ccsp_string;

    netsnmp_variable_list *var = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(var, 0, sizeof(netsnmp_variable_list));

    var->val.integer = &value;
    var->val.bitstring = (u_char *)malloc(sizeof(u_char) * 16);
    var->val.bitstring[0] = 1;
    var->val.bitstring[1] = 2;
    var->val.bitstring[2] = 3;
    var->val.bitstring[3] = 4;
    var->val.bitstring[4] = 5;
    var->val.bitstring[5] = 6;
    var->val.bitstring[6] = 7;
    var->val.bitstring[7] = 8;
    var->val.bitstring[8] = 9;
    var->val.bitstring[9] = 10;
    var->val.bitstring[10] = 11;
    var->val.bitstring[11] = 12;
    var->val.bitstring[12] = 13;
    var->val.bitstring[13] = 14;
    var->val.bitstring[14] = 15;
    var->val.bitstring[15] = 16;
    var->val_len = 16;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(4)
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(1)))
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)));

    CcspUtilMIBValueToDM(pMapping, paramValStruct, var);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(var->val.bitstring);
    free(var);
}

//Test for CcspUtilMIBValueToDMIntegerCcspString - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBValueToDMIntegerCcspStringSuccess)
{
    long value = 1;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    pMapping->MibInfo.uType = ASN_INTEGER;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = ccsp_string;

    netsnmp_variable_list *var = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(var, 0, sizeof(netsnmp_variable_list));

    var->val.integer = &value;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)));

    CcspUtilMIBValueToDM(pMapping, paramValStruct, var);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(var);
}

//Test for CcspUtilMIBValueToDMIntegerCcspBoolean - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBValueToDMIntegerCcspBooleanSuccess)
{
    long value = 1;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    pMapping->MibInfo.uType = ASN_INTEGER;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = ccsp_boolean;

    netsnmp_variable_list *var = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(var, 0, sizeof(netsnmp_variable_list));

    var->val.integer = &value;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)));

    CcspUtilMIBValueToDM(pMapping, paramValStruct, var);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(var);
}

//Test for CcspUtilMIBValueToDMInteger - Failure
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBValueToDMIntegerFailure)
{
    long value = 1;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    pMapping->MibInfo.uType = ASN_INTEGER;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = ccsp_none;

    netsnmp_variable_list *var = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(var, 0, sizeof(netsnmp_variable_list));

    var->val.integer = &value;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)));

    CcspUtilMIBValueToDM(pMapping, paramValStruct, var);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(var);
}

//Test for CcspUtilMIBValueToDMAsnIpAddress - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBValueToDMAsnIpAddressSuccess)
{
    long value = 1;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    pMapping->MibInfo.uType = ASN_IPADDRESS;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = ccsp_none;

    netsnmp_variable_list *var = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(var, 0, sizeof(netsnmp_variable_list));

    var->val.integer = &value;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)));

    CcspUtilMIBValueToDM(pMapping, paramValStruct, var);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(var);
}

//Test for CcspUtilMIBValueToDMAsnIpAddressCcspString - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBValueToDMAsnIpAddressCcspStringSuccess)
{
    long value = 1;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    pMapping->MibInfo.uType = ASN_COUNTER;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = ccsp_string;

    netsnmp_variable_list *var = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(var, 0, sizeof(netsnmp_variable_list));

    var->val.integer = &value;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)));

    CcspUtilMIBValueToDM(pMapping, paramValStruct, var);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(var);
}

//Test for CcspUtilMIBValueToDMAsnIpAddressCcspString - Failure
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBValueToDMAsnIpAddressCcspStringFailure)
{
    long value = 1;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    pMapping->MibInfo.uType = ASN_COUNTER;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = ccsp_none;

    netsnmp_variable_list *var = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(var, 0, sizeof(netsnmp_variable_list));

    var->val.integer = &value;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)));

    CcspUtilMIBValueToDM(pMapping, paramValStruct, var);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(var);
}

//Test for CcspUtilMIBValueToDMAsnBitStrCcspString - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBValueToDMAsnBitStrCcspStringSuccess)
{
    long value = 1;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    pMapping->MibInfo.uType = ASN_BIT_STR;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = ccsp_string;

    netsnmp_variable_list *var = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(var, 0, sizeof(netsnmp_variable_list));

    var->val.integer = &value;
    var->val.bitstring = (u_char *)malloc(sizeof(u_char) * 8);
    var->val.bitstring[0] = 1;
    var->val.bitstring[1] = 2;
    var->val.bitstring[2] = 3;
    var->val.bitstring[3] = 4;
    var->val.bitstring[4] = 5;
    var->val.bitstring[5] = 6;
    var->val.bitstring[6] = 7;
    var->val.bitstring[7] = 8;
    var->val_len = 8;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .Times(8)
                .WillRepeatedly(Return(0));

    CcspUtilMIBValueToDM(pMapping, paramValStruct, var);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(var->val.bitstring);
    free(var);
}

//Test for CcspUtilMIBValueToDMAsnBitStrDepth1 - Success
TEST_F(CcspSnmpPaTestFixture, CcspUtilMIBValueToDMAsnBitStrDepth1Success)
{
    long value = 1;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.bIsRowStatus = FALSE;
    pMapping->MibInfo.uType = ASN_BIT_STR;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("42");
    paramValStruct->type = ccsp_string;

    netsnmp_variable_list *var = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(var, 0, sizeof(netsnmp_variable_list));

    var->val.integer = &value;
    var->val.bitstring = (u_char *)malloc(sizeof(u_char) * 8);
    var->val.bitstring[0] = 0;
    var->val.bitstring[1] = 2;
    var->val.bitstring[2] = 3;
    var->val.bitstring[3] = 4;
    var->val.bitstring[4] = 5;
    var->val.bitstring[5] = 6;
    var->val.bitstring[6] = 7;
    var->val.bitstring[7] = 8;
    var->val_len = 8;

    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)));
    EXPECT_CALL(*g_safecLibMock, _strcat_s_chk(_,_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    CcspUtilMIBValueToDM(pMapping, paramValStruct, var);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(var->val.bitstring);
    free(var);
}

//Test for CcspUtilCreateMibEntry - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilCreateMibEntrySuccess)
{
    netsnmp_tdata *data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(data, 0, sizeof(netsnmp_tdata));

    PULONG pValue = (PULONG)malloc(sizeof(ULONG) * 8);
    pValue[0] = 1;
    pValue[1] = 2;
    pValue[2] = 3;
    pValue[3] = 4;
    pValue[4] = 5;
    pValue[5] = 6;
    pValue[6] = 7;
    pValue[7] = 8;

    netsnmp_tdata_row *row = (netsnmp_tdata_row *)malloc(sizeof(netsnmp_tdata_row));
    memset(row, 0, sizeof(netsnmp_tdata_row));

    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_create_row())
                .Times(1)
                .WillOnce(Return(row));
    EXPECT_CALL(*g_netsnmpMock, snmp_varlist_add_variable(_,_,_,_,_,_))
                .Times(8)
                .WillRepeatedly(Return(static_cast<variable_list*>(nullptr)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_add_row(_,_))
                .Times(1)
                .WillOnce(Return(NULL));

    CcspUtilCreateMibEntry(data, pValue, 8, TRUE);

    free(data);
    free(pValue);
    free(row);
}

//Test for CcspUtilRemoveMibEntry - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilRemoveMibEntrySuccess)
{
    PCCSP_TABLE_ENTRY pValue = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pValue, 0, sizeof(CCSP_TABLE_ENTRY));
    pValue->IndexCount = 1;

    netsnmp_tdata *data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(data, 0, sizeof(netsnmp_tdata));

    netsnmp_tdata_row *row = (netsnmp_tdata_row *)malloc(sizeof(netsnmp_tdata_row));
    memset(row, 0, sizeof(netsnmp_tdata_row));

    row->data = (void *)pValue;

    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_remove_and_delete_row(_,_));

    CcspUtilRemoveMibEntry(data, row);

    free(data);
    free(pValue);
    free(row);
}

//Test for CcspUtilDeleteCosaEntry - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilDeleteCosaEntrySuccess)
{
    PULONG value = (PULONG)malloc(sizeof(ULONG));

    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    PCCSP_INDEX_MAPPING pMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pMapping->Linkage.Next = NULL;
    pMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    // Initialize the queue header
    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMapping;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PCCSP_TABLE_HELPER_OBJECT pValue = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pValue, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pValue->IndexMapQueue = *pQueueHeader;

    EXPECT_CALL(*g_anscWrapperApiMock, AnscQueueSearchEntryByIndex(_,_))
                .WillRepeatedly(Return((PSINGLE_LINK_ENTRY)pMapping));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_DeleteTblRow(_,_,_,_,_))
                .WillRepeatedly(Return(ANSC_STATUS_SUCCESS));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));

    CcspUtilDeleteCosaEntry(pValue, value, 0);
    // CcspUtilDeleteCosaEntry(pValue, value, 2);
    // CcspUtilDeleteCosaEntry(pValue, value, 3);
    // CcspUtilDeleteCosaEntry(pValue, value, 4);

    free(pInsNumberMap);
    free(pMapping);
    free(pQueueHeader);
    free(pValue);
    free(value);
}

//Test for CcspUtilCreateCosaEntry - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilCreateCosaEntrySuccess)
{
    PULONG value = (PULONG)malloc(sizeof(ULONG));

    unsigned int *insArray = (unsigned int *)malloc(sizeof(unsigned int)*1);
    insArray[0] = 5;

    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    PCCSP_INDEX_MAPPING pMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pMapping->Linkage.Next = NULL;
    pMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    // Initialize the queue header
    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMapping;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PCCSP_TABLE_HELPER_OBJECT pValue = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pValue, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pValue->IndexMapQueue = *pQueueHeader;

    EXPECT_CALL(*g_anscWrapperApiMock, AnscQueueSearchEntryByIndex(_,_))
                .WillRepeatedly(Return((PSINGLE_LINK_ENTRY)pMapping));
    /*EXPECT_CALL(*g_baseapiMock, CcspBaseIf_GetNextLevelInstances(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<4>(1), SetArgPointee<5>(insArray), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_AddTblRow(_,_,_,_,_,_))
                .WillRepeatedly(Return(CCSP_SUCCESS));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));*/

    CcspUtilCreateCosaEntry(pValue, value, 0);

    free(pInsNumberMap);
    free(pMapping);
    free(pQueueHeader);
    free(pValue);
    free(value);
}

//Test for CcspUtilGetDMParamName - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilGetDMParamNameSuccess)
{
    char pTemp[256] = "parameter";
    char * tempName = "1";
    PULONG value = (PULONG)malloc(sizeof(ULONG));

    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    PCCSP_INDEX_MAPPING pMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pMapping->Linkage.Next = NULL;
    pMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    // Initialize the queue header
    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMapping;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    EXPECT_CALL(*g_anscWrapperApiMock, AnscQueueSearchEntryByIndex(_,_))
                .WillRepeatedly(Return((PSINGLE_LINK_ENTRY)pMapping));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .WillRepeatedly(Return(pTemp));

    EXPECT_STREQ(CcspUtilGetDMParamName(pQueueHeader, value, 0, tempName), "parameter");
    // EXPECT_STREQ(CcspUtilGetDMParamName(pQueueHeader, value, 2, tempName), "parameter");
    // EXPECT_STREQ(CcspUtilGetDMParamName(pQueueHeader, value, 3, tempName), "parameter");
    // EXPECT_STREQ(CcspUtilGetDMParamName(pQueueHeader, value, 4, tempName), "parameter");

    free(pInsNumberMap);
    free(pMapping);
    free(pQueueHeader);
    free(value);
}

//Test for CcspUtilAddIndexToInsMapping - success
TEST_F(CcspSnmpPaTestFixture, CcspUtilAddIndexToInsMappingSuccess)
{
    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    PCCSP_INDEX_MAPPING pMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pMapping->Linkage.Next = NULL;
    pMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    // Initialize the queue header
    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMapping;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    EXPECT_EQ(CcspUtilAddIndexToInsMapping(pQueueHeader, 1, 1), TRUE);

    free(pInsNumberMap);
    free(pMapping);
    free(pQueueHeader);
}
