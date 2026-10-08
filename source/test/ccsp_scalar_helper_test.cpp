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
    #include "ccsp_scalar_helper_internal.h"
    #include "ccsp_mib_utilities.h"
    #include "cosa_api.h"
    #include "ansc_policy_parser_interface.h"
    #include "ansc_xml_parser_interface.h"

    void MyRegisterMibHandler( ANSC_HANDLE hThisObject )
    {
        UNREFERENCED_PARAMETER(hThisObject);
    }
}

using namespace testing;

extern SafecLibMock* g_safecLibMock;
extern AnscMemoryMock * g_anscMemoryMock;
extern BaseAPIMock * g_baseapiMock;
extern AnscWrapperApiMock * g_anscWrapperApiMock;
extern netsnmpMock *g_netsnmpMock;
extern SlapMock * g_slapMock;
extern AnscTaskMock * g_anscTaskMock;

/************************Internal Functions**************************/
//Test for CcspCreateScalarHelperAndRemove - success
TEST_F(CcspSnmpPaTestFixture, CcspCreateScalarHelperSuccess)
{
    void* pThisObject = CcspCreateScalarHelper();
    PCCSP_SCALAR_HELPER_OBJECT value = (PCCSP_SCALAR_HELPER_OBJECT)pThisObject;
    if(value != NULL)
    {
        value->pCcspComp = strdup("SampleString1");
        value->pCcspPath = strdup("SampleString1Path");
        value->pMibFilter = strdup("Device.myTable.%d.test.myType = 1");
    }
    CcspScalarHelperRemove(pThisObject);
    if(value != NULL)
    {
        free(value->pCcspComp);
        free(value->pCcspPath);
        free(value->pMibFilter);
    }
}

//Test for CcspScalarHelperLoadMibs - success
TEST_F(CcspSnmpPaTestFixture, CcspScalarHelperLoadMibsSuccess)
{
    extern ANSC_HANDLE g_pMyChildNode;
    MyCreateFunction();

    if(g_pMyChildNode != NULL)
    {
        PCCSP_SCALAR_HELPER_OBJECT pThisObject = (PCCSP_SCALAR_HELPER_OBJECT)malloc(sizeof(CCSP_SCALAR_HELPER_OBJECT));
        memset(pThisObject, 0, sizeof(CCSP_SCALAR_HELPER_OBJECT));
    
        strcpy(pThisObject->MibName, "123");
        pThisObject->uCacheTimeout = 1;
        pThisObject->BaseOid[0] = 1;
        pThisObject->uOidLen = 1;
        pThisObject->RegisterMibHandler = CcspScalarHelperRegisterMibHandler;

        PANSC_XML_DOM_NODE_OBJECT pNode = (PANSC_XML_DOM_NODE_OBJECT)g_pMyChildNode;

        PANSC_TOKEN_CHAIN pTokenChain = NULL;
        //memset(pTokenChain, 0, sizeof(ANSC_TOKEN_CHAIN));
        //pTokenChain->TokensQueue.Depth = 1;

        PANSC_STRING_TOKEN pStringToken = (PANSC_STRING_TOKEN)malloc(sizeof(ANSC_STRING_TOKEN));
        memset(pStringToken, 0, sizeof(ANSC_STRING_TOKEN));
        strcpy(pStringToken->Name, "123");

        netsnmp_mib_handler *mibHandler = (netsnmp_mib_handler *)malloc(sizeof(netsnmp_mib_handler));
        memset(mibHandler, 0, sizeof(netsnmp_mib_handler));
        mibHandler->handler_name = strdup("handler_name");
 

        netsnmp_cache *cache = (netsnmp_cache *)malloc(sizeof(netsnmp_cache));
        memset(cache, 0, sizeof(netsnmp_cache));
        cache->timeout = 1;

        netsnmp_handler_registration *reginfo = (netsnmp_handler_registration *)malloc(sizeof(netsnmp_handler_registration));
        memset(reginfo, 0, sizeof(netsnmp_handler_registration));
        reginfo->handlerName = strdup("handlerName");

        EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                    .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
        EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                    .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
        EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                    .WillRepeatedly(Return(0));
        EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                    .WillRepeatedly(Return(0));
        EXPECT_CALL(*g_anscWrapperApiMock, AnscTcAllocate(_,_))
                    .Times(1)
                    .WillRepeatedly(Return(pTokenChain));
        /*EXPECT_CALL(*g_anscWrapperApiMock, AnscTcPopToken(_))
                    .Times(1)
                    .WillOnce(Return(static_cast<ANSC_HANDLE>(pStringToken)));
        EXPECT_CALL(*g_safecLibMock, _memcpy_s_chk(_,_,_,_,_,_))
                    .Times(1)
                    .WillOnce(Return(0));
        EXPECT_CALL(*g_netsnmpMock, netsnmp_cache_handler_get(_))
                    .Times(1)
                    .WillOnce(Return(mibHandler));
        EXPECT_CALL(*g_netsnmpMock, netsnmp_cache_create(_,_,_,_,_))
                    .Times(1)
                    .WillOnce(Return(cache));
        EXPECT_CALL(*g_netsnmpMock, netsnmp_cache_handler_owns_cache(_));
        EXPECT_CALL(*g_netsnmpMock, netsnmp_create_handler_registration(_,_,_,_,_))
                    .Times(1)
                    .WillOnce(Return(reginfo));
        EXPECT_CALL(*g_netsnmpMock, netsnmp_register_scalar(_))
                    .Times(1)
                    .WillOnce(Return(0));
        EXPECT_CALL(*g_netsnmpMock, netsnmp_inject_handler(_, _))
                    .Times(1)
                    .WillOnce(Return(0));*/

        CcspScalarHelperLoadMibs(pThisObject, pNode, NULL);

        free(pTokenChain);
        free(pStringToken);
        free(g_pMyChildNode);
        g_pMyChildNode = NULL;
        free(pThisObject);
    }
}

//Test for CcspScalarHelperGetMibValuesAsnInt - success
TEST_F(CcspSnmpPaTestFixture, CcspScalarHelperGetMibValuesAsnIntSuccess)
{
    oid uLastOid = 1002;

    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    pMibValue->uLastOid = 1002;
    pMibValue->uType = ASN_INTEGER;
    pMibValue->uSize = 1;
    pMibValue->Linkage.Next =  NULL;
    pMibValue->Value.uValue = 1;

    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMibValue;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PCCSP_SCALAR_HELPER_OBJECT pThisObject = (PCCSP_SCALAR_HELPER_OBJECT)malloc(sizeof(CCSP_SCALAR_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_SCALAR_HELPER_OBJECT));
    pThisObject->uOidLen = 1;
    pThisObject->MibValueQueue = *pQueueHeader;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->name = (oid *)malloc(sizeof(oid)*2);
    requests->requestvb->name[0] = 1002;
    requests->requestvb->name[1] = 1002;

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));

    EXPECT_CALL(*g_netsnmpMock, snmp_set_var_typed_value(_,_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(CcspScalarHelperGetMibValues((ANSC_HANDLE)pThisObject, reqinfo, requests), SNMP_ERR_NOERROR);

    free(requests->requestvb->name);
    free(requests->requestvb);
    free(requests);
    free(reqinfo);
    free(pMibValue);
    free(pQueueHeader);
    free(pThisObject);
}

//Test for CcspScalarHelperGetMibValuesBitStr - success
TEST_F(CcspSnmpPaTestFixture, CcspScalarHelperGetMibValuesBitStrSuccess)
{
    oid uLastOid = 1002;

    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    pMibValue->uLastOid = 1002;
    pMibValue->uType = ASN_BIT_STR;
    pMibValue->uSize = 1;
    pMibValue->Linkage.Next =  NULL;
    pMibValue->Value.pBuffer = strdup("SampleValue");

    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMibValue;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PCCSP_SCALAR_HELPER_OBJECT pThisObject = (PCCSP_SCALAR_HELPER_OBJECT)malloc(sizeof(CCSP_SCALAR_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_SCALAR_HELPER_OBJECT));
    pThisObject->uOidLen = 1;
    pThisObject->MibValueQueue = *pQueueHeader;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->name = (oid *)malloc(sizeof(oid)*2);
    requests->requestvb->name[0] = 1002;
    requests->requestvb->name[1] = 1002;

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));

    EXPECT_CALL(*g_netsnmpMock, snmp_set_var_typed_value(_,_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(CcspScalarHelperGetMibValues((ANSC_HANDLE)pThisObject, reqinfo, requests), SNMP_ERR_NOERROR);

    free(requests->requestvb->name);
    free(requests->requestvb);
    free(requests);
    free(reqinfo);
    free(pMibValue->Value.pBuffer);
    free(pMibValue);
    free(pQueueHeader);
    free(pThisObject);
}

//Test for CcspScalarHelperGetMibValuesAsnCounter64 - success
TEST_F(CcspSnmpPaTestFixture, CcspScalarHelperGetMibValuesAsnCounter64Success)
{
    oid uLastOid = 1002;
    U64 val = {1,1};

    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    pMibValue->uLastOid = 1002;
    pMibValue->uType = ASN_COUNTER64;
    pMibValue->uSize = 1;
    pMibValue->Linkage.Next =  NULL;
    pMibValue->Value.u64Value = val;

    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMibValue;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PCCSP_SCALAR_HELPER_OBJECT pThisObject = (PCCSP_SCALAR_HELPER_OBJECT)malloc(sizeof(CCSP_SCALAR_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_SCALAR_HELPER_OBJECT));
    pThisObject->uOidLen = 1;
    pThisObject->MibValueQueue = *pQueueHeader;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->name = (oid *)malloc(sizeof(oid)*2);
    requests->requestvb->name[0] = 1002;
    requests->requestvb->name[1] = 1002;

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));

    EXPECT_CALL(*g_netsnmpMock, snmp_set_var_typed_value(_,_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(CcspScalarHelperGetMibValues((ANSC_HANDLE)pThisObject, reqinfo, requests), SNMP_ERR_NOERROR);

    free(requests->requestvb->name);
    free(requests->requestvb);
    free(requests);
    free(reqinfo);
    free(pMibValue);
    free(pQueueHeader);
    free(pThisObject);
}

//Test for CcspScalarHelperGetMibValuesUnknown - success
TEST_F(CcspSnmpPaTestFixture, CcspScalarHelperGetMibValuesUnknownSuccess)
{
    oid uLastOid = 1002;

    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    pMibValue->uLastOid = 1002;
    pMibValue->uType = ASN_NSAP;
    pMibValue->uSize = 1;
    pMibValue->Linkage.Next =  NULL;

    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMibValue;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PCCSP_SCALAR_HELPER_OBJECT pThisObject = (PCCSP_SCALAR_HELPER_OBJECT)malloc(sizeof(CCSP_SCALAR_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_SCALAR_HELPER_OBJECT));
    pThisObject->uOidLen = 1;
    pThisObject->MibValueQueue = *pQueueHeader;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->name = (oid *)malloc(sizeof(oid)*2);
    requests->requestvb->name[0] = 1002;
    requests->requestvb->name[1] = 1002;

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));

    EXPECT_EQ(CcspScalarHelperGetMibValues((ANSC_HANDLE)pThisObject, reqinfo, requests), SNMP_ERR_NOERROR);

    free(requests->requestvb->name);
    free(requests->requestvb);
    free(requests);
    free(reqinfo);
    free(pMibValue);
    free(pQueueHeader);
    free(pThisObject);
}

//Test for CcspScalarHelperGetMibValues - Failure
TEST_F(CcspSnmpPaTestFixture, CcspScalarHelperGetMibValuesFailure)
{
    oid uLastOid = 1002;

    // Sample data for uType, Linkage, Value.pBuffer, and BackValue.pBuffer
    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    pMibValue->uLastOid = 1002;
    pMibValue->uType = ASN_TIMETICKS;
    pMibValue->uSize = 1;
    pMibValue->Linkage.Next =  NULL;

    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMibValue;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PCCSP_SCALAR_HELPER_OBJECT pThisObject = (PCCSP_SCALAR_HELPER_OBJECT)malloc(sizeof(CCSP_SCALAR_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_SCALAR_HELPER_OBJECT));
    pThisObject->uOidLen = 1;
    pThisObject->MibValueQueue = *pQueueHeader;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->name = (oid *)malloc(sizeof(oid)*2);
    requests->requestvb->name[0] = 1002;
    requests->requestvb->name[1] = 0;

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));

    EXPECT_CALL(*g_netsnmpMock, netsnmp_set_request_error(_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(CcspScalarHelperGetMibValues((ANSC_HANDLE)pThisObject, reqinfo, requests), SNMP_ERR_NOERROR);

    free(requests->requestvb->name);
    free(requests->requestvb);
    free(requests);
    free(reqinfo);
    free(pMibValue);
    free(pQueueHeader);
    free(pThisObject);
}

//Test for CcspScalarHelperSetMibValuesModeReserve1 - success
TEST_F(CcspSnmpPaTestFixture, CcspScalarHelperSetMibValuesModeReserve1Success)
{
    oid uLastOid = 1002;

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

    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMapping;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PCCSP_SCALAR_HELPER_OBJECT pThisObject = (PCCSP_SCALAR_HELPER_OBJECT)malloc(sizeof(CCSP_SCALAR_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_SCALAR_HELPER_OBJECT));
    pThisObject->uOidLen = 1;
    pThisObject->MibValueQueue = *pQueueHeader;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;

    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->name = (oid *)malloc(sizeof(oid)*2);
    requests->requestvb->name[0] = 1002;
    requests->requestvb->name[1] = 1002;

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));
    reqinfo->mode = MODE_SET_RESERVE1;

    EXPECT_CALL(*g_netsnmpMock, netsnmp_set_request_error(_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(CcspScalarHelperSetMibValues((ANSC_HANDLE)pThisObject, reqinfo, requests), SNMP_ERR_NOERROR);

    free(requests->requestvb->name);
    free(requests->requestvb);
    free(requests);
    free(reqinfo);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pQueueHeader);
    free(pThisObject);
}

//Test for CcspScalarHelperSetMibValuesModeReserve2 - success
TEST_F(CcspSnmpPaTestFixture, CcspScalarHelperSetMibValuesModeReserve2Success)
{
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->bHasMapping = TRUE;
    strcpy(pMapping->Mapping.pDMName, "SampleString");
    pMapping->Mapping.backgroundCommit = TRUE;
    pMapping->MibInfo.bIsRowStatus = TRUE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    pMapping->MibInfo.uLastOid = 1002;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMapping;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PCCSP_SCALAR_HELPER_OBJECT pThisObject = (PCCSP_SCALAR_HELPER_OBJECT)malloc(sizeof(CCSP_SCALAR_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_SCALAR_HELPER_OBJECT));
    pThisObject->uOidLen = 1;
    pThisObject->MibValueQueue = *pQueueHeader;
    pThisObject->pCcspComp = strdup("SampleString1");
    pThisObject->pCcspPath = strdup("SampleString1Path");
    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;

    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->name = (oid *)malloc(sizeof(oid) *2);
    requests->requestvb->name[0] = 1002;
    requests->requestvb->name[1] = 1002;

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));
    reqinfo->mode = MODE_SET_RESERVE2;

    EXPECT_EQ(CcspScalarHelperSetMibValues((ANSC_HANDLE)pThisObject, reqinfo, requests), SNMP_ERR_NOERROR);

    free(requests->requestvb->name);
    free(requests->requestvb);
    free(requests);
    free(reqinfo);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pQueueHeader);
    free(pThisObject);
}

//Test for CcspScalarHelperSetMibValuesModeActionBgTrue - success
TEST_F(CcspSnmpPaTestFixture, CcspScalarHelperSetMibValuesModeActionBgTrueSuccess)
{
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->bHasMapping = TRUE;
    strcpy(pMapping->Mapping.pDMName, "SampleString");
    pMapping->Mapping.backgroundCommit = TRUE;
    pMapping->MibInfo.bIsRowStatus = TRUE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    pMapping->MibInfo.uLastOid = 1002;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMapping;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PCCSP_SCALAR_HELPER_OBJECT pThisObject = (PCCSP_SCALAR_HELPER_OBJECT)malloc(sizeof(CCSP_SCALAR_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_SCALAR_HELPER_OBJECT));
    pThisObject->uOidLen = 1;
    pThisObject->MibValueQueue = *pQueueHeader;
    pThisObject->pCcspComp = strdup("SampleString1");
    pThisObject->pCcspPath = strdup("SampleString1Path");
    pThisObject->bBackground = TRUE;
    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;

    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->name = (oid *)malloc(sizeof(oid) *2);
    requests->requestvb->name[0] = 1002;
    requests->requestvb->name[1] = 1002;

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));
    reqinfo->mode = MODE_SET_ACTION;

    EXPECT_CALL(*g_anscTaskMock, UserCreateTask(_,_,_,_,_))
                .WillRepeatedly(Return(static_cast<void *>(nullptr)));

    EXPECT_EQ(CcspScalarHelperSetMibValues((ANSC_HANDLE)pThisObject, reqinfo, requests), SNMP_ERR_NOERROR);

    free(requests->requestvb->name);
    free(requests->requestvb);
    free(requests);
    free(reqinfo);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pQueueHeader);
    free(pThisObject);
}

//Test for CcspScalarHelperSetMibValuesModeActionBgFalse - success
TEST_F(CcspSnmpPaTestFixture, CcspScalarHelperSetMibValuesModeActionBgFalseSuccess)
{
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->bHasMapping = TRUE;
    strcpy(pMapping->Mapping.pDMName, "SampleString");
    pMapping->Mapping.backgroundCommit = TRUE;
    pMapping->MibInfo.bIsRowStatus = TRUE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    pMapping->MibInfo.uLastOid = 1002;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMapping;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PCCSP_SCALAR_HELPER_OBJECT pThisObject = (PCCSP_SCALAR_HELPER_OBJECT)malloc(sizeof(CCSP_SCALAR_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_SCALAR_HELPER_OBJECT));
    pThisObject->uOidLen = 1;
    pThisObject->MibValueQueue = *pQueueHeader;
    pThisObject->pCcspComp = strdup("SampleString1");
    pThisObject->pCcspPath = strdup("SampleString1Path");
    pThisObject->bBackground = FALSE;
    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;

    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->name = (oid *)malloc(sizeof(oid) *2);
    requests->requestvb->name[0] = 1002;
    requests->requestvb->name[1] = 1002;

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));
    reqinfo->mode = MODE_SET_ACTION;

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setCommit(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(Return(CCSP_SUCCESS));

    EXPECT_EQ(CcspScalarHelperSetMibValues((ANSC_HANDLE)pThisObject, reqinfo, requests), SNMP_ERR_NOERROR);

    free(requests->requestvb->name);
    free(requests->requestvb);
    free(requests);
    free(reqinfo);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pQueueHeader);
    free(pThisObject);
}

//Test for CcspScalarHelperSetMibValuesModeFree - success
TEST_F(CcspSnmpPaTestFixture, CcspScalarHelperSetMibValuesModeFreeSuccess)
{
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->bHasMapping = TRUE;
    strcpy(pMapping->Mapping.pDMName, "SampleString");
    pMapping->Mapping.backgroundCommit = TRUE;
    pMapping->MibInfo.bIsRowStatus = TRUE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    pMapping->MibInfo.uLastOid = 1002;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMapping;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PCCSP_SCALAR_HELPER_OBJECT pThisObject = (PCCSP_SCALAR_HELPER_OBJECT)malloc(sizeof(CCSP_SCALAR_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_SCALAR_HELPER_OBJECT));
    pThisObject->uOidLen = 1;
    pThisObject->MibValueQueue = *pQueueHeader;
    pThisObject->pCcspComp = strdup("SampleString1");
    pThisObject->pCcspPath = strdup("SampleString1Path");
    pThisObject->bBackground = TRUE;
    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;

    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->name = (oid *)malloc(sizeof(oid) *2);
    requests->requestvb->name[0] = 1002;
    requests->requestvb->name[1] = 1002;

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));
    reqinfo->mode = MODE_SET_FREE;

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setCommit(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(Return(CCSP_SUCCESS));

    EXPECT_EQ(CcspScalarHelperSetMibValues((ANSC_HANDLE)pThisObject, reqinfo, requests), SNMP_ERR_NOERROR);

    free(requests->requestvb->name);
    free(requests->requestvb);
    free(requests);
    free(reqinfo);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pQueueHeader);
    free(pThisObject);
}

//Test for CcspScalarHelperRefreshCache - success
TEST_F(CcspSnmpPaTestFixture, CcspScalarHelperRefreshCacheSuccess)
{
    unsigned int* value = (unsigned int*)malloc(sizeof(unsigned int));
    value[0] = 1;
    char * temp = "testvalue";
    //char* pFilter = "Device.myTable.%d.test.myType = 1";
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

    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    pMibValue->uLastOid = 1002;
    pMibValue->uType = ASN_INTEGER;
    pMibValue->uSize = 1;
    pMibValue->Linkage.Next =  NULL;
    pMibValue->Value.uValue = 1;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->bHasMapping = TRUE;
    strcpy(pMapping->Mapping.pDMName, "Device.myTable.%d.test.myType");
    pMapping->Mapping.backgroundCommit = TRUE;
    pMapping->MibInfo.bIsRowStatus = TRUE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    pMapping->MibInfo.uLastOid = 1002;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMapping;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PQUEUE_HEADER pQueueHeader1 = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader1, 0, sizeof(QUEUE_HEADER));

    pQueueHeader1->Next.Next = (PSINGLE_LINK_ENTRY)pMibValue;
    pQueueHeader1->Last.Next = NULL;
    pQueueHeader1->Depth = 1;

    PCCSP_SCALAR_HELPER_OBJECT pThisObject = (PCCSP_SCALAR_HELPER_OBJECT)malloc(sizeof(CCSP_SCALAR_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_SCALAR_HELPER_OBJECT));
    pThisObject->uOidLen = 1;
    pThisObject->MibValueQueue = *pQueueHeader1;
    pThisObject->bBackground = TRUE;
    pThisObject->MibObjQueue = *pQueueHeader;
    pThisObject->pMibFilter = "Device.myTable.%d.test.myType = 1";

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
                .Times(2)
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_,_,_,_,_,_,_))
                .WillRepeatedly(DoAll(SetArgPointee<5>(1), SetArgPointee<6>(&paramValStruct), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .Times(2)
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .Times(1)
                .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_,_,_))
                .Times(2);

    EXPECT_EQ(CcspScalarHelperRefreshCache((ANSC_HANDLE)pThisObject), 0);

    //CcspScalarHelperRefreshCache((ANSC_HANDLE)pThisObject);

    free(pDestName);
    free(pPathName);
    free(componentStruct->componentName);
    free(componentStruct->dbusPath);
    free(componentStruct->remoteCR_name);
    free(componentStruct->remoteCR_dbus_path);
    free(componentStruct);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pQueueHeader);
    free(pQueueHeader1);
    free(pThisObject);
}

//Test for CcspScalarHelperRefreshCache - Failure
TEST_F(CcspSnmpPaTestFixture, CcspScalarHelperRefreshCacheFailure)
{
    unsigned int* value = (unsigned int*)malloc(sizeof(unsigned int));
    value[0] = 1;
    //char * temp = "testvalue";
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

    PCCSP_MIB_VALUE pMibValue = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    pMibValue->uLastOid = 1002;
    pMibValue->uType = ASN_INTEGER;
    pMibValue->uSize = 1;
    pMibValue->Linkage.Next =  NULL;
    pMibValue->Value.uValue = 1;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 2;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));

    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;
    pMapping->MapQueue.Last.Next = NULL;
    pMapping->MapQueue.Depth = 0;
    pMapping->bHasMapping = TRUE;
    strcpy(pMapping->Mapping.pDMName, "Device.myTable.test.myType");
    pMapping->Mapping.backgroundCommit = TRUE;
    pMapping->MibInfo.bIsRowStatus = TRUE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    pMapping->MibInfo.uLastOid = 1002;
    strcpy(pMapping->MibInfo.pType, "MacAddress");

    PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

    pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pMapping;
    pQueueHeader->Last.Next = NULL;
    pQueueHeader->Depth = 1;

    PQUEUE_HEADER pQueueHeader1 = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
    memset(pQueueHeader1, 0, sizeof(QUEUE_HEADER));

    pQueueHeader1->Next.Next = (PSINGLE_LINK_ENTRY)pMibValue;
    pQueueHeader1->Last.Next = NULL;
    pQueueHeader1->Depth = 1;

    PCCSP_SCALAR_HELPER_OBJECT pThisObject = (PCCSP_SCALAR_HELPER_OBJECT)malloc(sizeof(CCSP_SCALAR_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_SCALAR_HELPER_OBJECT));
    pThisObject->uOidLen = 1;
    pThisObject->MibValueQueue = *pQueueHeader1;
    pThisObject->bBackground = TRUE;
    pThisObject->MibObjQueue = *pQueueHeader;
    pThisObject->pMibFilter = "Device.myTable.test.myType";

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_,_,_,_,_,_))
                .Times(2)
                .WillRepeatedly(DoAll(SetArgPointee<4>(&componentStruct), SetArgPointee<5>(1), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .Times(4)
                .WillOnce(Return(componentStruct->componentName))
                .WillOnce(Return(componentStruct->dbusPath))
                .WillOnce(Return(componentStruct->componentName))
                .WillOnce(Return(componentStruct->dbusPath));
                //.WillOnce(Return(temp));
    EXPECT_CALL(*g_baseapiMock, free_componentStruct_t(_,_,_))
                .Times(2);
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_,_,_,_,_,_,_))
                .WillRepeatedly(DoAll(SetArgPointee<5>(1), SetArgPointee<6>(&paramValStruct), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_,_,_));

    EXPECT_EQ(CcspScalarHelperRefreshCache((ANSC_HANDLE)pThisObject), 0);

    //CcspScalarHelperRefreshCache((ANSC_HANDLE)pThisObject);

    free(pDestName);
    free(pPathName);
    free(componentStruct->componentName);
    free(componentStruct->dbusPath);
    free(componentStruct->remoteCR_name);
    free(componentStruct->remoteCR_dbus_path);
    free(componentStruct);
    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(paramValStruct);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pQueueHeader);
    free(pQueueHeader1);
    free(pThisObject);
}

//Test for CcspScalarHelperClearCache - success
TEST_F(CcspSnmpPaTestFixture, CcspScalarHelperClearCacheSuccess)
{
    CcspScalarHelperClearCache((ANSC_HANDLE)NULL);
}