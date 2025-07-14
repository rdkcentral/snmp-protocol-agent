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

extern "C"
{
    #include "rg_devmgmt_handler.h"

    #ifdef SIZE_OF_OID_MAP_TABLE
    #undef SIZE_OF_OID_MAP_TABLE
    #endif
    #define SIZE_OF_OID_MAP_TABLE 1

    int consoleDebugEnable;
    FILE* debugLogFile = nullptr;
    char g_Subsystem[32] = {0};
}

using namespace testing;

extern SafecLibMock* g_safecLibMock;
extern AnscMemoryMock * g_anscMemoryMock;
extern BaseAPIMock * g_baseapiMock;
extern AnscWrapperApiMock * g_anscWrapperApiMock;
extern netsnmpMock *g_netsnmpMock;

//Test for getOid - success
TEST_F(CcspSnmpPaTestFixture, getOidSuccess)
{
    netsnmp_request_info *request = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(request, 0, sizeof(netsnmp_request_info));
    request->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(request->requestvb, 0, sizeof(netsnmp_variable_list));

    request->requestvb->name = (oid *)malloc(sizeof(oid) * MAX_OID_LEN);
    memset(request->requestvb->name, 0, sizeof(oid) * MAX_OID_LEN);
    request->requestvb->name_length = 5;
    request->requestvb->name[0] = 1;
    request->requestvb->name[1] = 3;
    request->requestvb->name[2] = 6;
    request->requestvb->name[3] = 1;
    request->requestvb->name[4] = 4;

    char retOidBuf[MAX_PARAM_NAME_LENGTH] = {'\0'};
    size_t retBufSize = 5;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(getOid(request, retOidBuf, retBufSize), 0);

    free(request->requestvb->name);
    free(request->requestvb);
    free(request);
}

//Test for getOid - failure
TEST_F(CcspSnmpPaTestFixture, getOidFailure)
{
    netsnmp_request_info *request = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(request, 0, sizeof(netsnmp_request_info));
    request->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(request->requestvb, 0, sizeof(netsnmp_variable_list));

    request->requestvb->name = (oid *)malloc(sizeof(oid) * MAX_OID_LEN);
    memset(request->requestvb->name, 0, sizeof(oid) * MAX_OID_LEN);
    request->requestvb->name_length = 5;
    request->requestvb->name[0] = 1;
    request->requestvb->name[1] = 3;
    request->requestvb->name[2] = 6;
    request->requestvb->name[3] = 1;
    request->requestvb->name[4] = 4;

    char retOidBuf[MAX_PARAM_NAME_LENGTH] = {'\0'};
    size_t retBufSize = 5;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .Times(1)
                .WillOnce(Return(1));

    EXPECT_EQ(getOid(request, retOidBuf, retBufSize), -1);

    free(request->requestvb->name);
    free(request->requestvb);
    free(request);
}

//Test for getParamNameFromMapTable - success
TEST_F(CcspSnmpPaTestFixture, getParamNameFromMapTableSuccess)
{
    char oid[MAX_PARAM_NAME_LENGTH] = "1.3.6.1.4";
    char paramName[MAX_PARAM_NAME_LENGTH] = {'\0'};
    size_t retBufSize = 5;

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(getParamNameFromMapTable(oid, paramName, retBufSize), 0);
}

//Test for getParamNameFromMapTable - strcmp failure
TEST_F(CcspSnmpPaTestFixture, getParamNameFromMapTableStrcmpFailure)
{
    char oid[MAX_PARAM_NAME_LENGTH] = "1.3.6.1.4";
    char paramName[MAX_PARAM_NAME_LENGTH] = {'\0'};
    size_t retBufSize = 5;

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(5)
                .WillRepeatedly(DoAll(SetArgPointee<3>(1), Return(1)));

    EXPECT_EQ(getParamNameFromMapTable(oid, paramName, retBufSize), -1);
}

//Test for getParamNameFromMapTable - strcpy failure
TEST_F(CcspSnmpPaTestFixture, getParamNameFromMapTableStrcpyFailure)
{
    char oid[MAX_PARAM_NAME_LENGTH] = "1.3.6.1.4";
    char paramName[MAX_PARAM_NAME_LENGTH] = {'\0'};
    size_t retBufSize = 5;

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .Times(1)
                .WillOnce(Return(1));

    EXPECT_EQ(getParamNameFromMapTable(oid, paramName, retBufSize), -1);
}

//Test for getParamTypeFromMapTable - success
TEST_F(CcspSnmpPaTestFixture, getParamTypeFromMapTableSuccess)
{
    char oid[MAX_PARAM_NAME_LENGTH] = "1.3.6.1.4";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    EXPECT_EQ(getParamTypeFromMapTable(oid), ASN_INTEGER);
}

//Test for getParamTypeFromMapTable - failure
TEST_F(CcspSnmpPaTestFixture, getParamTypeFromMapTableFailure)
{
    char oid[MAX_PARAM_NAME_LENGTH] = "1.3.6.1.4";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(5)
                .WillRepeatedly(DoAll(SetArgPointee<3>(1), Return(1)));

    EXPECT_EQ(getParamTypeFromMapTable(oid), ASN_NULL);
}

//Test for doSnmpGet - ASN_INTEGER success
TEST_F(CcspSnmpPaTestFixture, doSnmpGetAsnIntegerSuccess)
{
    netsnmp_request_info *request = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(request, 0, sizeof(netsnmp_request_info));
    request->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(request->requestvb, 0, sizeof(netsnmp_variable_list));

    request->requestvb->name = (oid *)malloc(sizeof(oid) * MAX_OID_LEN);
    memset(request->requestvb->name, 0, sizeof(oid) * MAX_OID_LEN);
    request->requestvb->name_length = 13;
    request->requestvb->name[0] = 1;
    request->requestvb->name[1] = 3;
    request->requestvb->name[2] = 6;
    request->requestvb->name[3] = 1;
    request->requestvb->name[4] = 4;
    request->requestvb->name[5] = 1;
    request->requestvb->name[6] = 17270;
    request->requestvb->name[7] = 50;
    request->requestvb->name[8] = 2;
    request->requestvb->name[9] = 1;
    request->requestvb->name[10] = 4;
    request->requestvb->name[11] = 2;
    request->requestvb->name[12] = 0;

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));

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

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .Times(2)
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(2)
                .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<4>(&componentStruct), SetArgPointee<5>(1), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .Times(2)
                .WillOnce(Return(componentStruct->componentName))
                .WillOnce(Return(componentStruct->dbusPath));
    EXPECT_CALL(*g_baseapiMock, free_componentStruct_t(_,_,_));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_,_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<5>(1), SetArgPointee<6>(&paramValStruct), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_,_,_));
    EXPECT_CALL(*g_anscMemoryMock, AnscFreeMemoryOrig(_))
                .Times(2);
    EXPECT_CALL(*g_netsnmpMock, snmp_set_var_typed_value(_,_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(doSnmpGet(request, reqinfo), 0);

    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(componentStruct->componentName);
    free(componentStruct->dbusPath);
    free(componentStruct->remoteCR_name);
    free(componentStruct->remoteCR_dbus_path);
    free(request->requestvb->name);
    free(request->requestvb);
    free(request);
    free(reqinfo);
}

//Test for doSnmpGet - ASN_OCTET_STR success
TEST_F(CcspSnmpPaTestFixture, doSnmpGetAsnOctetStrSuccess)
{
    netsnmp_request_info *request = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(request, 0, sizeof(netsnmp_request_info));
    request->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(request->requestvb, 0, sizeof(netsnmp_variable_list));

    request->requestvb->name = (oid *)malloc(sizeof(oid) * MAX_OID_LEN);
    memset(request->requestvb->name, 0, sizeof(oid) * MAX_OID_LEN);
    request->requestvb->name_length = 13;
    request->requestvb->name[0] = 1;
    request->requestvb->name[1] = 3;
    request->requestvb->name[2] = 6;
    request->requestvb->name[3] = 1;
    request->requestvb->name[4] = 4;
    request->requestvb->name[5] = 1;
    request->requestvb->name[6] = 17270;
    request->requestvb->name[7] = 50;
    request->requestvb->name[8] = 2;
    request->requestvb->name[9] = 1;
    request->requestvb->name[10] = 4;
    request->requestvb->name[11] = 2;
    request->requestvb->name[12] = 0;

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));

    componentStruct_t *componentStruct = (componentStruct_t *)malloc(sizeof(componentStruct_t));
    memset(componentStruct, 0, sizeof(componentStruct_t));

    componentStruct->componentName = strdup("testComponent");
    componentStruct->dbusPath = strdup("/test/dbus/path");
    componentStruct->type = static_cast<dataType_e>(ASN_OCTET_STR);
    componentStruct->remoteCR_name = strdup("testRemoteCR");
    componentStruct->remoteCR_dbus_path = strdup("/test/remote/cr/dbus/path");

    parameterValStruct_t *paramValStruct = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    memset(paramValStruct, 0, sizeof(parameterValStruct_t));
    paramValStruct->parameterName = strdup("testParameter");
    paramValStruct->parameterValue = strdup("testValue");
    paramValStruct->type = static_cast<dataType_e>(ASN_OCTET_STR);

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .Times(2)
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(3)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<4>(&componentStruct), SetArgPointee<5>(1), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .Times(2)
                .WillOnce(Return(componentStruct->componentName))
                .WillOnce(Return(componentStruct->dbusPath));
    EXPECT_CALL(*g_baseapiMock, free_componentStruct_t(_,_,_));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_,_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<5>(1), SetArgPointee<6>(&paramValStruct), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_,_,_));
    EXPECT_CALL(*g_anscMemoryMock, AnscFreeMemoryOrig(_))
                .Times(2);
    EXPECT_CALL(*g_netsnmpMock, snmp_set_var_typed_value(_,_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(doSnmpGet(request, reqinfo), 0);

    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(componentStruct->componentName);
    free(componentStruct->dbusPath);
    free(componentStruct->remoteCR_name);
    free(componentStruct->remoteCR_dbus_path);
    free(request->requestvb->name);
    free(request->requestvb);
    free(request);
    free(reqinfo);
}

//Test for doSnmpGet - Failure
TEST_F(CcspSnmpPaTestFixture, doSnmpGetFailure)
{
    netsnmp_request_info *request = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(request, 0, sizeof(netsnmp_request_info));
    request->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(request->requestvb, 0, sizeof(netsnmp_variable_list));

    request->requestvb->name = (oid *)malloc(sizeof(oid) * MAX_OID_LEN);
    memset(request->requestvb->name, 0, sizeof(oid) * MAX_OID_LEN);
    request->requestvb->name_length = 13;
    request->requestvb->name[0] = 1;
    request->requestvb->name[1] = 3;
    request->requestvb->name[2] = 6;
    request->requestvb->name[3] = 1;
    request->requestvb->name[4] = 4;
    request->requestvb->name[5] = 1;
    request->requestvb->name[6] = 17270;
    request->requestvb->name[7] = 50;
    request->requestvb->name[8] = 2;
    request->requestvb->name[9] = 1;
    request->requestvb->name[10] = 4;
    request->requestvb->name[11] = 2;
    request->requestvb->name[12] = 0;

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .Times(2)
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(6)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
                .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)));

    EXPECT_EQ(doSnmpGet(request, reqinfo), 1);

    free(request->requestvb->name);
    free(request->requestvb);
    free(request);
    free(reqinfo);
}

//Test for doSnmpTypeCheck - success
TEST_F(CcspSnmpPaTestFixture, doSnmpTypeCheckSuccess)
{
    netsnmp_request_info *request = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(request, 0, sizeof(netsnmp_request_info));
    request->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(request->requestvb, 0, sizeof(netsnmp_variable_list));

    request->requestvb->name = (oid *)malloc(sizeof(oid) * MAX_OID_LEN);
    memset(request->requestvb->name, 0, sizeof(oid) * MAX_OID_LEN);
    request->requestvb->name_length = 5;
    request->requestvb->name[0] = 1;
    request->requestvb->name[1] = 3;
    request->requestvb->name[2] = 6;
    request->requestvb->name[3] = 1;
    request->requestvb->name[4] = 4;

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .Times(1)
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_check_vb_type(_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(doSnmpTypeCheck(request, reqinfo), 0);

    free(request->requestvb->name);
    free(request->requestvb);
    free(request);
    free(reqinfo);
}

//Test for doSnmpTypeCheck - failure
TEST_F(CcspSnmpPaTestFixture, doSnmpTypeCheckFailure)
{
    netsnmp_request_info *request = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(request, 0, sizeof(netsnmp_request_info));
    request->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(request->requestvb, 0, sizeof(netsnmp_variable_list));

    request->requestvb->name = (oid *)malloc(sizeof(oid) * MAX_OID_LEN);
    memset(request->requestvb->name, 0, sizeof(oid) * MAX_OID_LEN);
    request->requestvb->name_length = 5;
    request->requestvb->name[0] = 1;
    request->requestvb->name[1] = 3;
    request->requestvb->name[2] = 6;
    request->requestvb->name[3] = 1;
    request->requestvb->name[4] = 4;

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .Times(1)
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_check_vb_type(_,_))
                .Times(1)
                .WillOnce(Return(1));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_set_request_error(_,_,_))
                .Times(1)
                .WillOnce(Return(0));

    EXPECT_EQ(doSnmpTypeCheck(request, reqinfo), 1);

    free(request->requestvb->name);
    free(request->requestvb);
    free(request);
    free(reqinfo);
}

//Test for doSnmpSet - success
TEST_F(CcspSnmpPaTestFixture, doSnmpSetSuccess)
{
    netsnmp_request_info *request = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(request, 0, sizeof(netsnmp_request_info));
    request->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(request->requestvb, 0, sizeof(netsnmp_variable_list));

    request->requestvb->name = (oid *)malloc(sizeof(oid) * MAX_OID_LEN);
    memset(request->requestvb->name, 0, sizeof(oid) * MAX_OID_LEN);
    request->requestvb->name_length = 13;
    request->requestvb->name[0] = 1;
    request->requestvb->name[1] = 3;
    request->requestvb->name[2] = 6;
    request->requestvb->name[3] = 1;
    request->requestvb->name[4] = 4;
    request->requestvb->name[5] = 1;
    request->requestvb->name[6] = 17270;
    request->requestvb->name[7] = 50;
    request->requestvb->name[8] = 2;
    request->requestvb->name[9] = 1;
    request->requestvb->name[10] = 4;
    request->requestvb->name[11] = 2;
    request->requestvb->name[12] = 0;
    request->requestvb->val.string = (u_char*)"temp";

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));

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
    char *paramValue = "testParameter";

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .Times(2)
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<4>(&componentStruct), SetArgPointee<5>(1), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .Times(2)
                .WillOnce(Return(componentStruct->componentName))
                .WillOnce(Return(componentStruct->dbusPath));
    EXPECT_CALL(*g_baseapiMock, free_componentStruct_t(_,_,_));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_,_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(paramValue), SetArgPointee<5>(1), SetArgPointee<6>(&paramValStruct), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_,_,_));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setParameterValues(_,_,_,_,_,_,_,_,_))
                .Times(1)
                .WillOnce(Return(CCSP_SUCCESS));
    EXPECT_CALL(*g_anscMemoryMock, AnscFreeMemoryOrig(_))
                .Times(2);

    EXPECT_EQ(doSnmpSet(request, reqinfo), 0);

    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(componentStruct->componentName);
    free(componentStruct->dbusPath);
    free(componentStruct->remoteCR_name);
    free(componentStruct->remoteCR_dbus_path);
    free(request->requestvb->name);
    free(request->requestvb);
    free(request);
    free(reqinfo);
}

//Test for doSnmpSet - failure
TEST_F(CcspSnmpPaTestFixture, doSnmpSetFailure)
{
    netsnmp_request_info *request = (netsnmp_request_info *)malloc(sizeof(netsnmp_request_info));
    memset(request, 0, sizeof(netsnmp_request_info));
    request->requestvb = (netsnmp_variable_list *)malloc(sizeof(netsnmp_variable_list));
    memset(request->requestvb, 0, sizeof(netsnmp_variable_list));

    request->requestvb->name = (oid *)malloc(sizeof(oid) * MAX_OID_LEN);
    memset(request->requestvb->name, 0, sizeof(oid) * MAX_OID_LEN);
    request->requestvb->name_length = 13;
    request->requestvb->name[0] = 1;
    request->requestvb->name[1] = 3;
    request->requestvb->name[2] = 6;
    request->requestvb->name[3] = 1;
    request->requestvb->name[4] = 4;
    request->requestvb->name[5] = 1;
    request->requestvb->name[6] = 17270;
    request->requestvb->name[7] = 50;
    request->requestvb->name[8] = 2;
    request->requestvb->name[9] = 1;
    request->requestvb->name[10] = 4;
    request->requestvb->name[11] = 2;
    request->requestvb->name[12] = 0;
    request->requestvb->val.string = (u_char*)"temp";

    netsnmp_agent_request_info *reqinfo = (netsnmp_agent_request_info *)malloc(sizeof(netsnmp_agent_request_info));
    memset(reqinfo, 0, sizeof(netsnmp_agent_request_info));

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
    char *paramValue = "testParameter";

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
                .Times(2)
                .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<4>(&componentStruct), SetArgPointee<5>(1), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(_))
                .Times(2)
                .WillOnce(Return(componentStruct->componentName))
                .WillOnce(Return(componentStruct->dbusPath));
    EXPECT_CALL(*g_baseapiMock, free_componentStruct_t(_,_,_));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_,_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(SetArgPointee<3>(paramValue), SetArgPointee<5>(1), SetArgPointee<6>(&paramValStruct), Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setParameterValues(_,_,_,_,_,_,_,_,_))
                .Times(1)
                .WillOnce(DoAll(Return(CCSP_FAILURE)));
    EXPECT_CALL(*g_netsnmpMock, netsnmp_set_request_error(_,_,_))
                .Times(1)
                .WillOnce(Return(0));
    EXPECT_CALL(*g_anscMemoryMock, AnscFreeMemoryOrig(_))
                .Times(2);

    EXPECT_EQ(doSnmpSet(request, reqinfo), 1);

    free(paramValStruct->parameterName);
    free(paramValStruct->parameterValue);
    free(componentStruct->componentName);
    free(componentStruct->dbusPath);
    free(componentStruct->remoteCR_name);
    free(componentStruct->remoteCR_dbus_path);
    free(request->requestvb->name);
    free(request->requestvb);
    free(request);
    free(reqinfo);
}