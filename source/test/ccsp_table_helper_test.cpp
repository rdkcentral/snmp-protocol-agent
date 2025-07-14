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
    #include "ccsp_table_helper.h"
    #include "ccsp_table_helper_internal.h"
    #include "ccsp_mib_utilities.h"
    #include "cosa_api.h"
    #include "ansc_policy_parser_interface.h"
    #include "ansc_xml_parser_interface.h"

    int * MyRefreshCacheCallback( netsnmp_tdata* table_data)
    {
        UNREFERENCED_PARAMETER(table_data);
        return 0;
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
//Test for CcspCreateTableHelper - success
TEST_F(CcspSnmpPaTestFixture, CcspCreateTableHelperSuccess)
{
    void* pThisObject = CcspCreateTableHelper();
    PCCSP_TABLE_HELPER_OBJECT value = (PCCSP_TABLE_HELPER_OBJECT)pThisObject;
    if(value != NULL)
    {
        value->pCcspComp = strdup("SampleString1");
        value->pCcspPath = strdup("SampleString1Path");
    }

    CcspTableHelperRemove(pThisObject);

    if(value != NULL)
    {
        free(value->pCcspComp);
        free(value->pCcspPath);
    }
}

//Test for CcspTableHelperLoadMibs - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperLoadMibsSuccess)
{
    extern ANSC_HANDLE g_pMyChildNode;
    MyCreateFunction();

    if(g_pMyChildNode != NULL)
    {   
        PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
        memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));
        pIndexMapping->MibInfo.uType = 1;

        PQUEUE_HEADER pQueueHeader = (PQUEUE_HEADER)malloc(sizeof(QUEUE_HEADER));
        memset(pQueueHeader, 0, sizeof(QUEUE_HEADER));

        pQueueHeader->Next.Next = (PSINGLE_LINK_ENTRY)pIndexMapping;
        pQueueHeader->Last.Next = NULL;
        pQueueHeader->Depth = 1;

        PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
        memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    
        strcpy(pThisObject->MibName, "123");
        pThisObject->uCacheTimeout = 1;
        pThisObject->BaseOid[0] = 1;
        pThisObject->uOidLen = 1;
        pThisObject->uMinOid = 1;
        pThisObject->uMaxOid = 1;
        pThisObject->IndexMapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIndexMapping;
        pThisObject->RegisterMibHandler = CcspTableHelperRegisterMibHandler;

        PANSC_XML_DOM_NODE_OBJECT pNode = (PANSC_XML_DOM_NODE_OBJECT)g_pMyChildNode;

        PANSC_TOKEN_CHAIN pTokenChain = (PANSC_TOKEN_CHAIN)malloc(sizeof(ANSC_TOKEN_CHAIN));
        memset(pTokenChain, 0, sizeof(ANSC_TOKEN_CHAIN));
        pTokenChain->TokensQueue.Depth = 1;

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

        netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
        memset(table_data, 0, sizeof(netsnmp_tdata));

        netsnmp_table_data *table_data2 = (netsnmp_table_data *)malloc(sizeof(netsnmp_table_data));
        memset(table_data2, 0, sizeof(netsnmp_table_data));

        netsnmp_table_registration_info *table_info = (netsnmp_table_registration_info *)malloc(sizeof(netsnmp_table_registration_info));
        memset(table_info, 0, sizeof(netsnmp_table_registration_info));

        EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                    .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
        EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                    .WillRepeatedly(Return(0));
        EXPECT_CALL(*g_anscWrapperApiMock, AnscTcAllocate(_,_))
                    .Times(1)
                    .WillOnce(Return(pTokenChain));
        EXPECT_CALL(*g_anscWrapperApiMock, AnscTcPopToken(_))
                    .Times(1)
                    .WillOnce(Return(static_cast<ANSC_HANDLE>(pStringToken)));
        EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                    .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
        EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                    .WillRepeatedly(Return(0));
        EXPECT_CALL(*g_netsnmpMock, netsnmp_create_handler_registration(_,_,_,_,_))
                    .Times(1)
                    .WillOnce(Return(reginfo));
        EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_create_table(_,_))
                    .Times(1)
                    .WillOnce(Return(table_data));
        EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_register(_,_,_))
                    .Times(1)
                    .WillOnce(Return(0));
        EXPECT_CALL(*g_netsnmpMock, netsnmp_cache_handler_get(_))
                    .Times(1)
                    .WillOnce(Return(mibHandler));
        EXPECT_CALL(*g_netsnmpMock, netsnmp_cache_create(_,_,_,_,_))
                    .Times(1)
                    .WillOnce(Return(cache));

        CcspTableHelperLoadMibs(pThisObject, pNode, NULL);

        free(pTokenChain);
        free(pStringToken);
        free(g_pMyChildNode);
        g_pMyChildNode = NULL;
        free(pIndexMapping);
        free(pQueueHeader);
        free(mibHandler->handler_name);
        free(mibHandler);
        free(cache);
        free(reginfo->handlerName);
        free(reginfo);
        free(table_data);
        free(table_data2);
        free(table_info);
        free(pThisObject);
    }
}

//Test for CcspTableHelperGetMibValuesAsnOctStr - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperGetMibValuesAsnOctStrSuccess)
{
    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->uType = ASN_OCTET_STR;
    pMibValueObj->uLastOid = 1002;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;

    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .Times(1)
                .WillOnce(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .Times(1)
                .WillOnce(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, snmp_set_var_typed_value(_,_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(CcspTableHelperGetMibValues(NULL, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pMibValueObj);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(reqInfo);
}

//Test for CcspTableHelperGetMibValuesAsnInt - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperGetMibValuesAsnIntSuccess)
{
    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->uType = ASN_INTEGER;
    pMibValueObj->uLastOid = 1002;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;

    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .Times(1)
                .WillOnce(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .Times(1)
                .WillOnce(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, snmp_set_var_typed_value(_,_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(CcspTableHelperGetMibValues(NULL, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pMibValueObj);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(reqInfo);
}

//Test for CcspTableHelperGetMibValuesAsnCounter64 - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperGetMibValuesAsnCounter64Success)
{
    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->uType = ASN_COUNTER64;
    pMibValueObj->uLastOid = 1002;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;

    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .Times(1)
                .WillOnce(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .Times(1)
                .WillOnce(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, snmp_set_var_typed_value(_,_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(CcspTableHelperGetMibValues(NULL, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pMibValueObj);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(reqInfo);
}

//Test for CcspTableHelperGetMibValues - failure
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperGetMibValuesFailure)
{
    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->uType = ASN_GAUGE;
    pMibValueObj->uLastOid = 0;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;

    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .Times(1)
                .WillOnce(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .Times(1)
                .WillOnce(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_set_request_error(_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(CcspTableHelperGetMibValues(NULL, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pMibValueObj);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(reqInfo);
}

//Test for CcspTableHelperGetMibValuesEmptyTable - failure
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperGetMibValuesEmptyTableFailure)
{
    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;

    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .Times(1)
                .WillOnce(Return(static_cast<void *>(nullptr)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .Times(1)
                .WillOnce(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_set_request_error(_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(CcspTableHelperGetMibValues(NULL, reqInfo, requests), SNMP_ERR_NOERROR);

    free(requests->requestvb);
    free(requests);
    free(table_info);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeReserve1 - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeReserve1Success)
{
    long value = RS_DESTROY;
    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MibInfo.uLastOid = 1002;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_RESERVE1;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;

    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .Times(1)
                .WillOnce(Return(static_cast<void *>(nullptr)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .Times(1)
                .WillOnce(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_check_vb_rowstatus(_,_))
                .Times(1)
                .WillOnce(Return(SNMP_ERR_NOERROR));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_set_request_error(_,_,_))
                .Times(1)
                .WillOnce(Return(0));
    
    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pMapping);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(table_info);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeReserve1 - retFailure
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeReserve1RetFailure)
{
    long value = RS_DESTROY;
    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MibInfo.uLastOid = 1002;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_RESERVE1;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;

    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .Times(1)
                .WillOnce(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .Times(1)
                .WillOnce(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_check_vb_rowstatus(_,_))
                .Times(1)
                .WillOnce(Return(SNMP_ERR_BADVALUE));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_set_request_error(_,_,_))
                .Times(1)
                .WillOnce(Return(0));
    
    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pMapping);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeR1pMapping - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeR1pMappingIntSuccess)
{
    long value = RS_DESTROY;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 6;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_INTEGER;
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 0;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_RESERVE1;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;

    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .Times(1)
                .WillOnce(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .Times(1)
                .WillOnce(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_check_vb_type(_,_))
                .Times(1)
                .WillOnce(Return(SNMP_ERR_NOERROR));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_check_vb_size(_,_))
                .Times(1)
                .WillOnce(Return(SNMP_ERR_NOERROR));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_check_vb_int_range(_,_,_))
                .Times(1)
                .WillOnce(Return(SNMP_ERR_NOERROR));
    
    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeR1pMapping - failure
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeR1pMappingIntFailure)
{
    long value = RS_DESTROY;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_INTEGER;
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 0;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_RESERVE1;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;

    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .Times(1)
                .WillOnce(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .Times(1)
                .WillOnce(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_check_vb_type(_,_))
                .Times(1)
                .WillOnce(Return(SNMP_ERR_NOERROR));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_check_vb_size(_,_))
                .Times(1)
                .WillOnce(Return(SNMP_ERR_NOERROR));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_check_vb_int_range(_,_,_))
                .Times(1)
                .WillOnce(Return(SNMP_ERR_NOERROR));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_set_request_error(_,_,_))
                .Times(1)
                .WillOnce(Return(0));
    
    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeReserve1 - failure
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeReserve1Failure)
{
    long value = RS_DESTROY;
    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 0;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_INTEGER;
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 0;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_RESERVE1;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;

    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .Times(1)
                .WillOnce(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .Times(1)
                .WillOnce(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_set_request_error(_,_,_))
                .Times(1)
                .WillOnce(Return(0));
    
    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeR2AsnInt - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeR2AsnIntSuccess)
{
    char pTemp[256] = ".Security.X_COMCAST-COM_KeyPassphrase";
    long value = RS_CREATEANDGO;

    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->Value.uValue = 1;
    pMibValueObj->uSize = 1;
    pMibValueObj->uLastOid = 1002;

    PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pIndexMapping->Linkage.Next = NULL;
    pIndexMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pIndexMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_INTEGER;
    strcpy(pMapping->MibInfo.pType, "Integer");
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;
    requests->requestvb->val_len = sizeof(long);

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_RESERVE2;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->IndexCount = 1;
    pEntry->IndexValue[0].Value.uValue = 1;
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_variable_list *indexes = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(indexes, 0, sizeof(netsnmp_variable_list));
    indexes->val.integer = &value;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;
    table_info->number_indexes = 1;
    table_info->indexes = indexes;

    netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(table_data, 0, sizeof(netsnmp_tdata));

    netsnmp_tdata_row *row = (netsnmp_tdata_row *)malloc(sizeof(netsnmp_tdata_row));
    memset(row, 0, sizeof(netsnmp_tdata_row));
    row->data = (void *)pEntry;

    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .WillRepeatedly(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .WillRepeatedly(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_table(_))
                .Times(1)
                .WillOnce(Return(table_data));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_create_row())
                .Times(1)
                .WillOnce(Return(row));
    EXPECT_CALL(*g_netsnmpMock, snmp_varlist_add_variable(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(Return(static_cast<variable_list*>(nullptr)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_add_row(_,_))
                .Times(1)
                .WillOnce(Return(NULL));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscQueueSearchEntryByIndex(_,_))
                .Times(2)
                .WillOnce(Return(static_cast<PSINGLE_LINK_ENTRY>(nullptr)))
                .WillOnce(Return((PSINGLE_LINK_ENTRY)pIndexMapping));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .WillRepeatedly(Return(pTemp));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setParameterValues(_,_,_,_,_,_,_,_,_))
                .Times(1)
                .WillOnce(Return(CCSP_SUCCESS));

    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pInsNumberMap);
    free(pIndexMapping);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(indexes);
    free(table_data);
    free(row);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeR2AsnOctStr - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeR2AsnOctStrSuccess)
{
    char pTemp[256] = ".Security.X_COMCAST-COM_KeyPassphrase";
    long value = RS_CREATEANDGO;

    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->Value.uValue = 1;
    pMibValueObj->uSize = 1;
    pMibValueObj->uLastOid = 1002;

    PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pIndexMapping->Linkage.Next = NULL;
    pIndexMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pIndexMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    strcpy(pMapping->MibInfo.pType, "Integer");
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;
    requests->requestvb->val_len = sizeof(long);

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_RESERVE2;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->IndexCount = 1;
    pEntry->IndexValue[0].Value.uValue = 1;
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_variable_list *indexes = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(indexes, 0, sizeof(netsnmp_variable_list));
    indexes->val.integer = &value;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;
    table_info->number_indexes = 1;
    table_info->indexes = indexes;

    netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(table_data, 0, sizeof(netsnmp_tdata));

    netsnmp_tdata_row *row = (netsnmp_tdata_row *)malloc(sizeof(netsnmp_tdata_row));
    memset(row, 0, sizeof(netsnmp_tdata_row));
    row->data = (void *)pEntry;

    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .WillRepeatedly(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .WillRepeatedly(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_table(_))
                .Times(1)
                .WillOnce(Return(table_data));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_create_row())
                .Times(1)
                .WillOnce(Return(row));
    EXPECT_CALL(*g_netsnmpMock, snmp_varlist_add_variable(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(Return(static_cast<variable_list*>(nullptr)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_add_row(_,_))
                .Times(1)
                .WillOnce(Return(NULL));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscQueueSearchEntryByIndex(_,_))
                .Times(2)
                .WillOnce(Return(static_cast<PSINGLE_LINK_ENTRY>(nullptr)))
                .WillOnce(Return((PSINGLE_LINK_ENTRY)pIndexMapping));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .WillRepeatedly(Return(pTemp));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setParameterValues(_,_,_,_,_,_,_,_,_))
                .Times(1)
                .WillOnce(Return(CCSP_SUCCESS));

    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pInsNumberMap);
    free(pIndexMapping);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(indexes);
    free(table_data);
    free(row);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeR2AsnBitStr - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeR2AsnBitStrSuccess)
{
    char pTemp[256] = ".Security.X_COMCAST-COM_KeyPassphrase";
    long value = RS_CREATEANDGO;

    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->Value.uValue = 1;
    pMibValueObj->uSize = 1;
    pMibValueObj->uLastOid = 1002;

    PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pIndexMapping->Linkage.Next = NULL;
    pIndexMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pIndexMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_BIT_STR;
    strcpy(pMapping->MibInfo.pType, "Integer");
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;
    requests->requestvb->val_len = sizeof(long);

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_RESERVE2;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->IndexCount = 1;
    pEntry->IndexValue[0].Value.uValue = 1;
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_variable_list *indexes = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(indexes, 0, sizeof(netsnmp_variable_list));
    indexes->val.integer = &value;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;
    table_info->number_indexes = 1;
    table_info->indexes = indexes;

    netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(table_data, 0, sizeof(netsnmp_tdata));

    netsnmp_tdata_row *row = (netsnmp_tdata_row *)malloc(sizeof(netsnmp_tdata_row));
    memset(row, 0, sizeof(netsnmp_tdata_row));
    row->data = (void *)pEntry;

    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .WillRepeatedly(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .WillRepeatedly(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_table(_))
                .Times(1)
                .WillOnce(Return(table_data));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_create_row())
                .Times(1)
                .WillOnce(Return(row));
    EXPECT_CALL(*g_netsnmpMock, snmp_varlist_add_variable(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(Return(static_cast<variable_list*>(nullptr)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_add_row(_,_))
                .Times(1)
                .WillOnce(Return(NULL));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscQueueSearchEntryByIndex(_,_))
                .Times(2)
                .WillOnce(Return(static_cast<PSINGLE_LINK_ENTRY>(nullptr)))
                .WillOnce(Return((PSINGLE_LINK_ENTRY)pIndexMapping));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .WillRepeatedly(Return(pTemp));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setParameterValues(_,_,_,_,_,_,_,_,_))
                .Times(1)
                .WillOnce(Return(CCSP_SUCCESS));

    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pInsNumberMap);
    free(pIndexMapping);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(indexes);
    free(table_data);
    free(row);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeReserve2 - failure
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeReserve2Failure)
{
    char pTemp[256] = ".Security.X_COMCAST-COM_KeyPassphrase";
    long value = RS_CREATEANDGO;

    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->Value.uValue = 1;
    pMibValueObj->uSize = 1;
    pMibValueObj->uLastOid = 1002;

    PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pIndexMapping->Linkage.Next = NULL;
    pIndexMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pIndexMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_INTEGER;
    strcpy(pMapping->MibInfo.pType, "Integer");
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;
    requests->requestvb->val_len = sizeof(long);

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_RESERVE2;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->IndexCount = 1;
    pEntry->IndexValue[0].Value.uValue = 1;
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_variable_list *indexes = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(indexes, 0, sizeof(netsnmp_variable_list));
    indexes->val.integer = &value;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;
    table_info->number_indexes = 1;
    table_info->indexes = indexes;

    netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(table_data, 0, sizeof(netsnmp_tdata));

    netsnmp_tdata_row *row = (netsnmp_tdata_row *)malloc(sizeof(netsnmp_tdata_row));
    memset(row, 0, sizeof(netsnmp_tdata_row));
    row->data = (void *)pEntry;

    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .WillRepeatedly(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .WillRepeatedly(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_table(_))
                .Times(1)
                .WillOnce(Return(table_data));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_create_row())
                .Times(1)
                .WillOnce(Return(static_cast<netsnmp_tdata_row *>(nullptr)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_set_request_error(_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pInsNumberMap);
    free(pIndexMapping);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(indexes);
    free(table_data);
    free(row);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeSetActionCnG - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeSetActionCnGSuccess)
{
    char pTemp[256] = ".Security.X_COMCAST-COM_KeyPassphrase";
    long value = RS_CREATEANDGO;

    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->Value.uValue = 1;
    pMibValueObj->uSize = 1;
    pMibValueObj->uLastOid = 1002;

    PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pIndexMapping->Linkage.Next = NULL;
    pIndexMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pIndexMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_BIT_STR;
    strcpy(pMapping->MibInfo.pType, "Integer");
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->pCcspPath = strdup("path");
    pThisObject->pCcspComp = strdup("comp");
    pThisObject->bBackground = TRUE;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;
    requests->requestvb->val_len = sizeof(long);

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_ACTION;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->IndexCount = 1;
    pEntry->IndexValue[0].Value.uValue = 1;
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_variable_list *indexes = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(indexes, 0, sizeof(netsnmp_variable_list));
    indexes->val.integer = &value;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;
    table_info->number_indexes = 1;
    table_info->indexes = indexes;

    netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(table_data, 0, sizeof(netsnmp_tdata));

    EXPECT_CALL(*g_anscTaskMock, UserCreateTask(_,_,_,_,_))
                .WillRepeatedly(Return(static_cast<void *>(nullptr)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .WillRepeatedly(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .WillRepeatedly(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_row(_))
                .Times(1)
                .WillOnce(Return(static_cast<netsnmp_tdata_row *>(nullptr)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_table(_))
                .Times(1)
                .WillOnce(Return(table_data));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .WillRepeatedly(Return(pTemp));

    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pInsNumberMap);
    free(pIndexMapping);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(indexes);
    free(table_data);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeSetActionActive - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeSetActionActiveSuccess)
{
    char pTemp[256] = ".Security.X_COMCAST-COM_KeyPassphrase";
    long value = RS_ACTIVE;

    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->Value.uValue = 1;
    pMibValueObj->uSize = 1;
    pMibValueObj->uLastOid = 1002;

    PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pIndexMapping->Linkage.Next = NULL;
    pIndexMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pIndexMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_BIT_STR;
    strcpy(pMapping->MibInfo.pType, "Integer");
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->pCcspPath = strdup("path");
    pThisObject->pCcspComp = strdup("comp");
    pThisObject->bBackground = TRUE;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;
    requests->requestvb->val_len = sizeof(long);

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_ACTION;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->IndexCount = 1;
    pEntry->IndexValue[0].Value.uValue = 1;
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_variable_list *indexes = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(indexes, 0, sizeof(netsnmp_variable_list));
    indexes->val.integer = &value;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;
    table_info->number_indexes = 1;
    table_info->indexes = indexes;

    netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(table_data, 0, sizeof(netsnmp_tdata));

    EXPECT_CALL(*g_anscTaskMock, UserCreateTask(_,_,_,_,_))
                .WillRepeatedly(Return(static_cast<void *>(nullptr)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .WillRepeatedly(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .WillRepeatedly(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_row(_))
                .Times(1)
                .WillOnce(Return(static_cast<netsnmp_tdata_row *>(nullptr)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_table(_))
                .Times(1)
                .WillOnce(Return(table_data));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .WillRepeatedly(Return(pTemp));

    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pInsNumberMap);
    free(pIndexMapping);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(indexes);
    free(table_data);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeSetActionCnW - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeSetActionCnWSuccess)
{
    char pTemp[256] = ".Security.X_COMCAST-COM_KeyPassphrase";
    long value = RS_CREATEANDWAIT;

    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->Value.uValue = 1;
    pMibValueObj->uSize = 1;
    pMibValueObj->uLastOid = 1002;

    PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pIndexMapping->Linkage.Next = NULL;
    pIndexMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pIndexMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_BIT_STR;
    strcpy(pMapping->MibInfo.pType, "Integer");
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->pCcspPath = strdup("path");
    pThisObject->pCcspComp = strdup("comp");
    pThisObject->bBackground = TRUE;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;
    requests->requestvb->val_len = sizeof(long);

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_ACTION;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->IndexCount = 1;
    pEntry->IndexValue[0].Value.uValue = 1;
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_variable_list *indexes = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(indexes, 0, sizeof(netsnmp_variable_list));
    indexes->val.integer = &value;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;
    table_info->number_indexes = 1;
    table_info->indexes = indexes;

    netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(table_data, 0, sizeof(netsnmp_tdata));

    EXPECT_CALL(*g_anscTaskMock, UserCreateTask(_,_,_,_,_))
                .WillRepeatedly(Return(static_cast<void *>(nullptr)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .WillRepeatedly(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .WillRepeatedly(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_row(_))
                .Times(1)
                .WillOnce(Return(static_cast<netsnmp_tdata_row *>(nullptr)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_table(_))
                .Times(1)
                .WillOnce(Return(table_data));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .WillRepeatedly(Return(pTemp));

    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pInsNumberMap);
    free(pIndexMapping);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(indexes);
    free(table_data);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeSetActionNIService - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeSetActionNIServiceSuccess)
{
    char pTemp[256] = ".Security.X_COMCAST-COM_KeyPassphrase";
    long value = RS_NOTINSERVICE;

    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->Value.uValue = 1;
    pMibValueObj->uSize = 1;
    pMibValueObj->uLastOid = 1002;

    PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pIndexMapping->Linkage.Next = NULL;
    pIndexMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pIndexMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_BIT_STR;
    strcpy(pMapping->MibInfo.pType, "Integer");
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->pCcspPath = strdup("path");
    pThisObject->pCcspComp = strdup("comp");
    pThisObject->bBackground = TRUE;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;
    requests->requestvb->val_len = sizeof(long);

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_ACTION;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->IndexCount = 1;
    pEntry->IndexValue[0].Value.uValue = 1;
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_variable_list *indexes = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(indexes, 0, sizeof(netsnmp_variable_list));
    indexes->val.integer = &value;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;
    table_info->number_indexes = 1;
    table_info->indexes = indexes;

    netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(table_data, 0, sizeof(netsnmp_tdata));

    EXPECT_CALL(*g_anscTaskMock, UserCreateTask(_,_,_,_,_))
                .WillRepeatedly(Return(static_cast<void *>(nullptr)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .WillRepeatedly(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .WillRepeatedly(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_row(_))
                .Times(1)
                .WillOnce(Return(static_cast<netsnmp_tdata_row *>(nullptr)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_table(_))
                .Times(1)
                .WillOnce(Return(table_data));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .WillRepeatedly(Return(pTemp));

    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pInsNumberMap);
    free(pIndexMapping);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(indexes);
    free(table_data);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeSetActionDestroy - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeSetActionDestroySuccess)
{
    char pTemp[256] = ".Security.X_COMCAST-COM_KeyPassphrase";
    long value = RS_DESTROY;

    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->Value.uValue = 1;
    pMibValueObj->uSize = 1;
    pMibValueObj->uLastOid = 1002;

    PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pIndexMapping->Linkage.Next = NULL;
    pIndexMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pIndexMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_BIT_STR;
    strcpy(pMapping->MibInfo.pType, "Integer");
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->pCcspPath = strdup("path");
    pThisObject->pCcspComp = strdup("comp");
    pThisObject->bBackground = TRUE;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;
    requests->requestvb->val_len = sizeof(long);

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_ACTION;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->IndexCount = 1;
    pEntry->IndexValue[0].Value.uValue = 1;
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_variable_list *indexes = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(indexes, 0, sizeof(netsnmp_variable_list));
    indexes->val.integer = &value;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;
    table_info->number_indexes = 1;
    table_info->indexes = indexes;

    netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(table_data, 0, sizeof(netsnmp_tdata));

    netsnmp_tdata_row *row = (netsnmp_tdata_row *)malloc(sizeof(netsnmp_tdata_row));
    memset(row, 0, sizeof(netsnmp_tdata_row));
    row->data = (void *)pEntry;

    EXPECT_CALL(*g_anscTaskMock, UserCreateTask(_,_,_,_,_))
                .WillRepeatedly(Return(static_cast<void *>(nullptr)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .WillRepeatedly(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .WillRepeatedly(Return(table_info));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_row(_))
                .Times(1)
                .WillOnce(Return(row));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_table(_))
                .Times(1)
                .WillOnce(Return(table_data));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .WillRepeatedly(Return(pTemp));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_remove_and_delete_row(_,_));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscQueueSearchEntryByIndex(_,_))
                .WillRepeatedly(Return((PSINGLE_LINK_ENTRY)pIndexMapping));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_DeleteTblRow(_,_,_,_,_))
                .WillRepeatedly(Return(ANSC_STATUS_SUCCESS));

    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pInsNumberMap);
    free(pIndexMapping);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject->pCcspPath);
    free(pThisObject->pCcspComp);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(row);
    free(table_info);
    free(indexes);
    free(table_data);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeSetFreeAsnOctStr - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeSetFreeAsnOctStrSuccess)
{
    char pTemp[256] = ".Security.X_COMCAST-COM_KeyPassphrase";
    long value = RS_DESTROY;

    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->Value.uValue = 1;
    pMibValueObj->uSize = 1;
    pMibValueObj->uLastOid = 1002;
    pMibValueObj->uType = ASN_OCTET_STR;

    PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pIndexMapping->Linkage.Next = NULL;
    pIndexMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pIndexMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    strcpy(pMapping->MibInfo.pType, "Integer");
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->pCcspPath = strdup("path");
    pThisObject->pCcspComp = strdup("comp");
    pThisObject->bBackground = TRUE;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;
    requests->requestvb->val_len = sizeof(long);

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_FREE;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->IndexCount = 1;
    pEntry->IndexValue[0].Value.uValue = 1;
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_variable_list *indexes = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(indexes, 0, sizeof(netsnmp_variable_list));
    indexes->val.integer = &value;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;
    table_info->number_indexes = 1;
    table_info->indexes = indexes;

    netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(table_data, 0, sizeof(netsnmp_tdata));


    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .WillRepeatedly(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .WillRepeatedly(Return(table_info));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setCommit(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(Return(CCSP_SUCCESS));

    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pInsNumberMap);
    free(pIndexMapping);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject->pCcspPath);
    free(pThisObject->pCcspComp);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(indexes);
    free(table_data);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeSetFreeAsnBitStr - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeSetFreeAsnBitStrSuccess)
{
    char pTemp[256] = ".Security.X_COMCAST-COM_KeyPassphrase";
    long value = RS_DESTROY;

    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->Value.uValue = 1;
    pMibValueObj->uSize = 1;
    pMibValueObj->uLastOid = 1002;
    pMibValueObj->uType = ASN_BIT_STR;

    PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pIndexMapping->Linkage.Next = NULL;
    pIndexMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pIndexMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_BIT_STR;
    strcpy(pMapping->MibInfo.pType, "Integer");
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->pCcspPath = strdup("path");
    pThisObject->pCcspComp = strdup("comp");
    pThisObject->bBackground = TRUE;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;
    requests->requestvb->val_len = sizeof(long);

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_FREE;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->IndexCount = 1;
    pEntry->IndexValue[0].Value.uValue = 1;
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_variable_list *indexes = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(indexes, 0, sizeof(netsnmp_variable_list));
    indexes->val.integer = &value;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;
    table_info->number_indexes = 1;
    table_info->indexes = indexes;

    netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(table_data, 0, sizeof(netsnmp_tdata));


    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .WillRepeatedly(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .WillRepeatedly(Return(table_info));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setCommit(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(Return(CCSP_SUCCESS));

    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pInsNumberMap);
    free(pIndexMapping);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject->pCcspPath);
    free(pThisObject->pCcspComp);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(indexes);
    free(table_data);
    free(reqInfo);
}

//Test for CcspTableHelperSetMibValuesModeSetFreeNoneType - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperSetMibValuesModeSetFreeNoneTypeSuccess)
{
    char pTemp[256] = ".Security.X_COMCAST-COM_KeyPassphrase";
    long value = RS_DESTROY;

    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->Value.uValue = 1;
    pMibValueObj->uSize = 1;
    pMibValueObj->uLastOid = 1002;

    PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pIndexMapping->Linkage.Next = NULL;
    pIndexMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    pIndexMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_OCTET_STR;
    strcpy(pMapping->MibInfo.pType, "Integer");
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->pCcspPath = strdup("path");
    pThisObject->pCcspComp = strdup("comp");
    pThisObject->bBackground = TRUE;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;
    requests->requestvb->val_len = sizeof(long);

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_FREE;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->IndexCount = 1;
    pEntry->IndexValue[0].Value.uValue = 1;
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_variable_list *indexes = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(indexes, 0, sizeof(netsnmp_variable_list));
    indexes->val.integer = &value;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;
    table_info->number_indexes = 1;
    table_info->indexes = indexes;

    netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(table_data, 0, sizeof(netsnmp_tdata));


    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_extract_entry(_))
                .WillRepeatedly(Return(static_cast<void *>(pEntry)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_extract_table_info(_))
                .WillRepeatedly(Return(table_info));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setCommit(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(Return(CCSP_SUCCESS));

    EXPECT_EQ(CcspTableHelperSetMibValues((ANSC_HANDLE)pThisObject, reqInfo, requests), SNMP_ERR_NOERROR);

    free(pInsNumberMap);
    free(pIndexMapping);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject->pCcspPath);
    free(pThisObject->pCcspComp);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(table_info);
    free(indexes);
    free(table_data);
    free(reqInfo);
}

//Test for CcspTableHelperRefreshCacheInsNumber - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperRefreshCacheInsNumberSuccess)
{
    char pTemp[256] = ".Security.X_COMCAST-COM_KeyPassphrase";
    long value = RS_DESTROY;
    unsigned int* value1 = (unsigned int*)malloc(sizeof(unsigned int));
    value1[0] = 1;
    char * temp = "testvalue";

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

    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->Value.uValue = 1;
    pMibValueObj->uSize = 1;
    pMibValueObj->uLastOid = 1002;

    PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pIndexMapping->Linkage.Next = NULL;
    pIndexMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
    strcpy(pIndexMapping->Mapping.DMMappingInfo.pDMName, "Device.myTable.%d.test.myType");
    pIndexMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_BIT_STR;
    strcpy(pMapping->MibInfo.pType, "Integer");
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->bBackground = TRUE;
    strcpy(pThisObject->pStrSampleDM, "Device.myTable.%d.test.myType");
    pThisObject->IndexMapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIndexMapping;
    pThisObject->IndexMapQueue.Depth = 1;
    pThisObject->RefreshCacheCallback = (void *)MyRefreshCacheCallback;
    pThisObject->MibObjQueue.Depth = 1;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;
    requests->requestvb->val_len = sizeof(long);

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_ACTION;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->IndexCount = 1;
    pEntry->IndexValue[0].Value.uValue = 1;
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_variable_list *indexes = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(indexes, 0, sizeof(netsnmp_variable_list));
    indexes->val.integer = &value;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;
    table_info->number_indexes = 1;
    table_info->indexes = indexes;

    netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(table_data, 0, sizeof(netsnmp_tdata));

    netsnmp_tdata_row *row = (netsnmp_tdata_row *)malloc(sizeof(netsnmp_tdata_row));
    memset(row, 0, sizeof(netsnmp_tdata_row));
    row->data = (void *)pEntry;

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<4>(&componentStruct), SetArgPointee<5>(1), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .Times(3)
                .WillOnce(Return(componentStruct->componentName))
                .WillOnce(Return(componentStruct->dbusPath))
                .WillOnce(Return(temp));
    EXPECT_CALL(*g_baseapiMock, free_componentStruct_t(_,_,_));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_GetNextLevelInstances(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<4>(1), SetArgPointee<5>(value1), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_create_row())
                .Times(1)
                .WillOnce(Return(row));
    EXPECT_CALL(*g_netsnmpMock, snmp_varlist_add_variable(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(Return(static_cast<variable_list*>(nullptr)));
    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_,_,_,_,_,_,_))
                .WillRepeatedly(DoAll(SetArgPointee<5>(1), SetArgPointee<6>(&paramValStruct), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_,_,_));

    EXPECT_EQ(CcspTableHelperRefreshCache((ANSC_HANDLE)pThisObject), 0);

    free(pInsNumberMap);
    free(pIndexMapping);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject->pCcspPath);
    free(pThisObject->pCcspComp);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(row);
    free(table_info);
    free(indexes);
    free(table_data);
    free(reqInfo);
}

//Test for CcspTableHelperRefreshCacheSubDm - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperRefreshCacheSubDmSuccess)
{
    char pTemp[256] = ".Security.X_COMCAST-COM_KeyPassphrase";
    long value = RS_DESTROY;
    unsigned int* value1 = (unsigned int*)malloc(sizeof(unsigned int));
    value1[0] = 1;
    char * temp = "testvalue";

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

    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->Value.uValue = 1;
    pMibValueObj->uSize = 1;
    pMibValueObj->uLastOid = 1002;

    PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pIndexMapping->Linkage.Next = NULL;
    pIndexMapping->uMapType = CCSP_MIB_MAP_TO_SUBDM;
    strcpy(pIndexMapping->Mapping.DMMappingInfo.pDMName, "Device.myTable.%d.test.myType");
    pIndexMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_BIT_STR;
    strcpy(pMapping->MibInfo.pType, "Integer");
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->bBackground = TRUE;
    strcpy(pThisObject->pStrSampleDM, "Device.myTable.%d.test.myType");
    pThisObject->IndexMapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIndexMapping;
    pThisObject->IndexMapQueue.Depth = 1;
    pThisObject->RefreshCacheCallback = (void *)MyRefreshCacheCallback;
    pThisObject->MibObjQueue.Depth = 1;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;
    requests->requestvb->val_len = sizeof(long);

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_ACTION;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY));
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->IndexCount = 1;
    pEntry->IndexValue[0].Value.uValue = 1;
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_variable_list *indexes = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(indexes, 0, sizeof(netsnmp_variable_list));
    indexes->val.integer = &value;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;
    table_info->number_indexes = 1;
    table_info->indexes = indexes;

    netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(table_data, 0, sizeof(netsnmp_tdata));

    netsnmp_tdata_row *row = (netsnmp_tdata_row *)malloc(sizeof(netsnmp_tdata_row));
    memset(row, 0, sizeof(netsnmp_tdata_row));
    row->data = (void *)pEntry;

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<4>(&componentStruct), SetArgPointee<5>(1), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .Times(3)
                .WillOnce(Return(componentStruct->componentName))
                .WillOnce(Return(componentStruct->dbusPath))
                .WillOnce(Return(temp));
    EXPECT_CALL(*g_baseapiMock, free_componentStruct_t(_,_,_));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_GetNextLevelInstances(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<4>(1), SetArgPointee<5>(value1), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_create_row())
                .Times(1)
                .WillOnce(Return(row));
    EXPECT_CALL(*g_netsnmpMock, snmp_varlist_add_variable(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(Return(static_cast<variable_list*>(nullptr)));
    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_,_,_,_,_,_,_))
                .WillRepeatedly(DoAll(SetArgPointee<5>(1), SetArgPointee<6>(&paramValStruct), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_,_,_))
                .Times(2);

    EXPECT_EQ(CcspTableHelperRefreshCache((ANSC_HANDLE)pThisObject), 0);

    free(pInsNumberMap);
    free(pIndexMapping);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject->pCcspPath);
    free(pThisObject->pCcspComp);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(row);
    free(table_info);
    free(indexes);
    free(table_data);
    free(reqInfo);
}

//Test for CcspTableHelperRefreshCacheDepth2 - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperRefreshCacheDepth2success)
{
    char pTemp[256] = ".Security.X_COMCAST-COM_KeyPassphrase";
    long value = RS_DESTROY;
    unsigned int* value1 = (unsigned int*)malloc(sizeof(unsigned int));
    value1[0] = 1;
    unsigned int* value2 = (unsigned int*)malloc(sizeof(unsigned int));
    value2[0] = 1;
    char * temp = "testvalue";

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

    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->Value.uValue = 1;
    pMibValueObj->uSize = 1;
    pMibValueObj->uLastOid = 1002;

    PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pIndexMapping->Linkage.Next = NULL;
    pIndexMapping->uMapType = CCSP_MIB_MAP_TO_SUBDM;
    strcpy(pIndexMapping->Mapping.DMMappingInfo.pDMName, "Device.myTable.%d.test.myType");
    pIndexMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_BIT_STR;
    strcpy(pMapping->MibInfo.pType, "Integer");
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->bBackground = TRUE;
    strcpy(pThisObject->pStrSampleDM, "Device.myTable.%d.test.myType");
    pThisObject->IndexMapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIndexMapping;
    pThisObject->IndexMapQueue.Depth = 2;
    pThisObject->RefreshCacheCallback = (void *)MyRefreshCacheCallback;
    pThisObject->MibObjQueue.Depth = 1;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;
    requests->requestvb->val_len = sizeof(long);

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_ACTION;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY)*2);
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->IndexCount = 1;
    pEntry->IndexValue[0].Value.uValue = 1;
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_variable_list *indexes = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(indexes, 0, sizeof(netsnmp_variable_list));
    indexes->val.integer = &value;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;
    table_info->number_indexes = 1;
    table_info->indexes = indexes;

    netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(table_data, 0, sizeof(netsnmp_tdata));

    netsnmp_tdata_row *row = (netsnmp_tdata_row *)malloc(sizeof(netsnmp_tdata_row));
    memset(row, 0, sizeof(netsnmp_tdata_row));
    row->data = (void *)pEntry;

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<4>(&componentStruct), SetArgPointee<5>(1), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .Times(3)
                .WillOnce(Return(componentStruct->componentName))
                .WillOnce(Return(componentStruct->dbusPath))
                .WillOnce(Return(temp));
    EXPECT_CALL(*g_baseapiMock, free_componentStruct_t(_,_,_));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_GetNextLevelInstances(_,_,_,_,_,_))
                .Times(2)
                .WillOnce(DoAll(SetArgPointee<4>(1), SetArgPointee<5>(value1), Return(CCSP_SUCCESS)))
                .WillOnce(DoAll(SetArgPointee<4>(1), SetArgPointee<5>(value2), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_create_row())
                .Times(1)
                .WillOnce(Return(row));
    EXPECT_CALL(*g_netsnmpMock, snmp_varlist_add_variable(_,_,_,_,_,_))
                .WillRepeatedly(Return(static_cast<variable_list*>(nullptr)));
    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_,_,_,_,_,_,_))
                .WillRepeatedly(DoAll(SetArgPointee<5>(1), SetArgPointee<6>(&paramValStruct), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscQueueSearchEntryByIndex(_,_))
                .Times(1)
                .WillOnce(Return((PSINGLE_LINK_ENTRY)pIndexMapping));
    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_,_,_))
                .Times(1);

    EXPECT_EQ(CcspTableHelperRefreshCache((ANSC_HANDLE)pThisObject), 0);

    free(pInsNumberMap);
    free(pIndexMapping);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject->pCcspPath);
    free(pThisObject->pCcspComp);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(row);
    free(table_info);
    free(indexes);
    free(table_data);
    free(reqInfo);
}

//Test for CcspTableHelperRefreshCacheDepth3 - success
TEST_F(CcspSnmpPaTestFixture, CcspTableHelperRefreshCacheDepth3success)
{
    char pTemp[256] = ".Security.X_COMCAST-COM_KeyPassphrase";
    long value = RS_DESTROY;
    unsigned int* value1 = (unsigned int*)malloc(sizeof(unsigned int));
    value1[0] = 1;
    unsigned int* value2 = (unsigned int*)malloc(sizeof(unsigned int));
    value2[0] = 1;
    unsigned int* value3 = (unsigned int*)malloc(sizeof(unsigned int));
    value3[0] = 1;
    char * temp = "testvalue";

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

    PCCSP_MIB_VALUE pMibValueObj = (PCCSP_MIB_VALUE)malloc(sizeof(CCSP_MIB_VALUE));
    memset(pMibValueObj, 0, sizeof(CCSP_MIB_VALUE));
    pMibValueObj->Value.uValue = 1;
    pMibValueObj->uSize = 1;
    pMibValueObj->uLastOid = 1002;

    PCCSP_INDEX_MAPPING pIndexMapping = (PCCSP_INDEX_MAPPING)malloc(sizeof(CCSP_INDEX_MAPPING));
    memset(pIndexMapping, 0, sizeof(CCSP_INDEX_MAPPING));

    PCCSP_INS_NUMBER_MAP pInsNumberMap = (PCCSP_INS_NUMBER_MAP)malloc(sizeof(CCSP_INS_NUMBER_MAP));
    memset(pInsNumberMap, 0, sizeof(CCSP_INS_NUMBER_MAP));
    pInsNumberMap->Linkage.Next = NULL;
    pInsNumberMap->uMibValue = 1;
    pInsNumberMap->uDMValue = 2;

    pIndexMapping->Linkage.Next = NULL;
    pIndexMapping->uMapType = CCSP_MIB_MAP_TO_SUBDM;
    strcpy(pIndexMapping->Mapping.DMMappingInfo.pDMName, "Device.myTable.%d.test.myType");
    pIndexMapping->IndexQueue.Next.Next = (PSINGLE_LINK_ENTRY)pInsNumberMap;

    PCCSP_INT_STRING_MAP pIntStringMap = (PCCSP_INT_STRING_MAP)malloc(sizeof(CCSP_INT_STRING_MAP));
    memset(pIntStringMap, 0, sizeof(CCSP_INT_STRING_MAP));
    pIntStringMap->EnumCode = 0;
    pIntStringMap->Linkage.Next =  NULL;
    pIntStringMap->pString = strdup("SampleString");

    PCCSP_MIB_MAPPING pMapping = (PCCSP_MIB_MAPPING)malloc(sizeof(CCSP_MIB_MAPPING));
    memset(pMapping, 0, sizeof(CCSP_MIB_MAPPING));
    pMapping->MapQueue.Depth = 1;
    pMapping->MibInfo.uLastOid = 1002;
    pMapping->MibInfo.bWritable = TRUE;
    pMapping->MibInfo.uType = ASN_BIT_STR;
    strcpy(pMapping->MibInfo.pType, "Integer");
    pMapping->MibInfo.uMaskLimit = CCSP_MIB_LIMIT_BOTH;
    pMapping->MibInfo.nMin= 1;
    pMapping->MibInfo.nMax = 10;
    pMapping->bHasMapping = TRUE;
    pMapping->MapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIntStringMap;

    PCCSP_TABLE_HELPER_OBJECT pThisObject = (PCCSP_TABLE_HELPER_OBJECT)malloc(sizeof(CCSP_TABLE_HELPER_OBJECT));
    memset(pThisObject, 0, sizeof(CCSP_TABLE_HELPER_OBJECT));
    pThisObject->uRowStatus = 1002;
    pThisObject->bBackground = TRUE;
    strcpy(pThisObject->pStrSampleDM, "Device.myTable.%d.test.myType");
    pThisObject->IndexMapQueue.Next.Next = (PSINGLE_LINK_ENTRY)pIndexMapping;
    pThisObject->IndexMapQueue.Depth = 3;
    pThisObject->RefreshCacheCallback = (void *)MyRefreshCacheCallback;
    pThisObject->MibObjQueue.Depth = 1;
    pThisObject->MibObjQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMapping;

    netsnmp_request_info *requests = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(requests, 0, sizeof(netsnmp_request_info));
    requests->processed = 0;
    requests->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(requests->requestvb, 0, sizeof(netsnmp_variable_list));
    requests->requestvb->val.integer = &value;
    requests->requestvb->val_len = sizeof(long);

    netsnmp_agent_request_info *reqInfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqInfo, 0, sizeof(netsnmp_agent_request_info));
    reqInfo->mode = MODE_SET_ACTION;

    PCCSP_TABLE_ENTRY pEntry = (PCCSP_TABLE_ENTRY)malloc(sizeof(CCSP_TABLE_ENTRY)*2);
    memset(pEntry, 0, sizeof(CCSP_TABLE_ENTRY));
    pEntry->IndexCount = 1;
    pEntry->IndexValue[0].Value.uValue = 1;
    pEntry->MibValueQueue.Next.Next = (PSINGLE_LINK_ENTRY)pMibValueObj;

    netsnmp_variable_list *indexes = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(indexes, 0, sizeof(netsnmp_variable_list));
    indexes->val.integer = &value;

    netsnmp_table_request_info *table_info = (netsnmp_table_request_info *)malloc(sizeof(netsnmp_table_request_info));
    memset(table_info, 0, sizeof(netsnmp_table_request_info));
    table_info->colnum = 1002;
    table_info->number_indexes = 1;
    table_info->indexes = indexes;

    netsnmp_tdata *table_data = (netsnmp_tdata *)malloc(sizeof(netsnmp_tdata));
    memset(table_data, 0, sizeof(netsnmp_tdata));

    netsnmp_tdata_row *row = (netsnmp_tdata_row *)malloc(sizeof(netsnmp_tdata_row));
    memset(row, 0, sizeof(netsnmp_tdata_row));
    row->data = (void *)pEntry;

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<4>(&componentStruct), SetArgPointee<5>(1), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .Times(3)
                .WillOnce(Return(componentStruct->componentName))
                .WillOnce(Return(componentStruct->dbusPath))
                .WillOnce(Return(temp));
    EXPECT_CALL(*g_baseapiMock, free_componentStruct_t(_,_,_));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_GetNextLevelInstances(_,_,_,_,_,_))
                .Times(3)
                .WillOnce(DoAll(SetArgPointee<4>(1), SetArgPointee<5>(value1), Return(CCSP_SUCCESS)))
                .WillOnce(DoAll(SetArgPointee<4>(1), SetArgPointee<5>(value2), Return(CCSP_SUCCESS)))
                .WillOnce(DoAll(SetArgPointee<4>(1), SetArgPointee<5>(value3), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_tdata_create_row())
                .Times(1)
                .WillOnce(Return(row));
    EXPECT_CALL(*g_netsnmpMock, snmp_varlist_add_variable(_,_,_,_,_,_))
                .WillRepeatedly(Return(static_cast<variable_list*>(nullptr)));
    EXPECT_CALL(*g_safecLibMock, _strcasecmp_s_chk(_,_,_,_,_))
                .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_,_,_,_,_,_,_))
                .WillRepeatedly(DoAll(SetArgPointee<5>(1), SetArgPointee<6>(&paramValStruct), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscQueueSearchEntryByIndex(_,_))
                .Times(3)
                .WillRepeatedly(Return((PSINGLE_LINK_ENTRY)pIndexMapping));
    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_,_,_))
                .Times(1);

    EXPECT_EQ(CcspTableHelperRefreshCache((ANSC_HANDLE)pThisObject), 0);

    free(pInsNumberMap);
    free(pIndexMapping);
    free(pIntStringMap->pString);
    free(pIntStringMap);
    free(pMapping);
    free(pThisObject->pCcspPath);
    free(pThisObject->pCcspComp);
    free(pThisObject);
    free(requests->requestvb);
    free(requests);
    free(pEntry);
    free(row);
    free(table_info);
    free(indexes);
    free(table_data);
    free(reqInfo);
}