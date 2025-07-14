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
    #include "CcspSnmpPlugin.h"
}

using namespace testing;

extern SafecLibMock* g_safecLibMock;
extern AnscMemoryMock * g_anscMemoryMock;
extern BaseAPIMock * g_baseapiMock;
extern AnscWrapperApiMock * g_anscWrapperApiMock;
extern netsnmpMock *g_netsnmpMock;
extern SlapMock * g_slapMock;
extern AnscTaskMock * g_anscTaskMock;
extern UtilMock * g_utilMock;
extern MessageBusMock * g_messagebusMock;
extern AnscFileIOMock* g_anscFileIOMock;
extern AnscDebugMock * g_anscDebugMock;
extern AnscXmlMock * g_anscXmlMock;

/************************Internal Functions**************************/
//Test for init_ccsp_snmp_plugin - success
TEST_F(CcspSnmpPaTestFixture, init_ccsp_snmp_pluginSuccess)
{
    extern ANSC_HANDLE g_pMyChildNode;
    MyCreateFunction();

    if(g_pMyChildNode != NULL)
    {
        char * value = "debug";
        ULONG fileCharSize = 0;

        PANSC_FILE_INFO pFileHandle = (PANSC_FILE_INFO)malloc(sizeof(ANSC_FILE_INFO));
        memset(pFileHandle, 0, sizeof(ANSC_FILE_INFO));

        strcpy(pFileHandle->Name, "temp");
        fileCharSize = (ULONG)strlen(pFileHandle->Name);
        char * pXMLContent = (char *)malloc(15);
        memset(pXMLContent, 0, 15);
        strcpy((char*)pXMLContent, "temp");

        PANSC_XML_DOM_NODE_OBJECT pNode = (PANSC_XML_DOM_NODE_OBJECT)g_pMyChildNode;

        EXPECT_CALL(*g_utilMock, getenv(_))
                    .Times(1)
                    .WillOnce(Return(value));
        EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_,_,_,_,_,_))
                    .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(0)));
        EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_,_,_,_))
                    .Times(1)
                    .WillRepeatedly(Return(0));
        EXPECT_CALL(*g_messagebusMock, CCSP_Message_Bus_Init(_,_,_,_,_))
                    .Times(1)
                    .WillOnce(Return(0));
        EXPECT_CALL(*g_anscFileIOMock, AnscOpenFile(_,_,_))
                    .WillRepeatedly(Return(static_cast<ANSC_HANDLE>(pFileHandle)));
        EXPECT_CALL(*g_anscFileIOMock, AnscGetFileSize(_))
                    .WillRepeatedly(Return(fileCharSize));
        EXPECT_CALL(*g_anscFileIOMock, AnscReadFile(_,_,_))
                    .WillRepeatedly(Return(ANSC_STATUS_SUCCESS));
        EXPECT_CALL(*g_anscFileIOMock, AnscCloseFile(_))
                    .WillRepeatedly(Return(ANSC_STATUS_SUCCESS));
        EXPECT_CALL(*g_anscXmlMock, AnscXmlDomParseString(_,_,_))
                    .WillRepeatedly(Return(static_cast<ANSC_HANDLE>(pNode)));
        init_ccsp_snmp_plugin();
        remove_ccsp_snmp_plugin();
    
        free(pFileHandle);
        free(pXMLContent);
        free(g_pMyChildNode);
        g_pMyChildNode = NULL;
    }
}