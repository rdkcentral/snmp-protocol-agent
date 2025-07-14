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

#include <gmock/gmock.h>
#include "snmp_mock.h"

extern "C" {
    ANSC_HANDLE g_pMyChildNode = NULL;

    ANSC_HANDLE MyGetChildByNameFunction(ANSC_HANDLE hXmlHandle, char* name)
    {
        UNREFERENCED_PARAMETER(hXmlHandle);
        UNREFERENCED_PARAMETER(name);
        return (ANSC_HANDLE)g_pMyChildNode;
    }

    ANSC_STATUS MyGetDataUlongFunction(ANSC_HANDLE hXmlHandle, char* name, PULONG pulUlong)
    {
        UNREFERENCED_PARAMETER(name);
        UNREFERENCED_PARAMETER(hXmlHandle);
        *pulUlong = 16;
        return ANSC_STATUS_SUCCESS;
    }

    ANSC_STATUS MyGetDataLongFunction(ANSC_HANDLE hXmlHandle, char* name, PLONG plTarget)
    {
        UNREFERENCED_PARAMETER(name);
        UNREFERENCED_PARAMETER(hXmlHandle);
        *plTarget = 8;
        return ANSC_STATUS_SUCCESS;
    }

    ANSC_STATUS MyGetDataStringFunction(ANSC_HANDLE hXmlHandle, char* name, char* buffer, PULONG pulSize)
    {
        UNREFERENCED_PARAMETER(name);
        UNREFERENCED_PARAMETER(hXmlHandle);
        strcpy(buffer, "SampleString");
        *pulSize = strlen(buffer);
        return ANSC_STATUS_SUCCESS;
    }

    ANSC_HANDLE MyGetNextChildFunction(ANSC_HANDLE hXmlHandle, ANSC_HANDLE hChildNode)
    {
        UNREFERENCED_PARAMETER(hXmlHandle);
        UNREFERENCED_PARAMETER(hChildNode);
        return (ANSC_HANDLE)NULL;
    }

    ANSC_STATUS MyGetDataBooleanFunction(ANSC_HANDLE hXmlHandle, char* name, BOOL* pbValue)
    {
        UNREFERENCED_PARAMETER(name);
        UNREFERENCED_PARAMETER(hXmlHandle);
        *pbValue = TRUE;
        return ANSC_STATUS_SUCCESS;
    }

    ANSC_HANDLE MyGetHeadChildFunction(ANSC_HANDLE hXmlHandle)
    {
        UNREFERENCED_PARAMETER(hXmlHandle);
        return (ANSC_HANDLE)g_pMyChildNode;
    }

    char* myGetNameFunction(ANSC_HANDLE hXmlHandle)
    {
        UNREFERENCED_PARAMETER(hXmlHandle);
        return "name";
    }

    ANSC_STATUS myRemoveFunction(ANSC_HANDLE hXmlHandle)
    {
        UNREFERENCED_PARAMETER(hXmlHandle);
        return ANSC_STATUS_SUCCESS;
    }

    void MyCreateFunction()
    {
        // Initialize fields
        PANSC_XML_DOM_NODE_OBJECT pNode = (PANSC_XML_DOM_NODE_OBJECT)malloc(sizeof(ANSC_XML_DOM_NODE_OBJECT));
        memset(pNode, 0, sizeof(ANSC_XML_DOM_NODE_OBJECT));
        pNode->hOwnerContext = NULL;
        strcpy(pNode->Name, "name");
        pNode->hParentNode = NULL;
        AnscQueueInitializeHeader(&pNode->ChildNodeQueue);
        pNode->ChildNodeQueueLock = MY_CHILD_NODE_COOKIE;

        // Initialize function pointers
        pNode->GetChildByName = MyGetChildByNameFunction;
        pNode->GetDataUlong = MyGetDataUlongFunction;
        pNode->GetDataLong = MyGetDataLongFunction;
        pNode->GetDataString = MyGetDataStringFunction;
        pNode->GetNextChild = MyGetNextChildFunction;
        pNode->GetDataBoolean = MyGetDataBooleanFunction;
        pNode->GetHeadChild = MyGetHeadChildFunction;
        pNode->GetName = myGetNameFunction;
        pNode->Remove = myRemoveFunction;
        // Initialize other function pointers as needed
        g_pMyChildNode = (ANSC_HANDLE)pNode;
    }
}
PlatformHalMock *g_platformHALMock = NULL;
SecureWrapperMock * g_securewrapperMock = NULL;
SocketMock * g_socketMock = NULL;
SafecLibMock * g_safecLibMock = NULL;
AnscDebugMock * g_anscDebugMock = NULL;
UserTimeMock * g_usertimeMock = NULL;
BaseAPIMock * g_baseapiMock = NULL;
SyscfgMock * g_syscfgMock = NULL;
PsmMock *g_psmMock = NULL;
parodusMock *g_parodusMock = NULL;
utopiaMock *g_utopiaMock = NULL;
AnscMemoryMock * g_anscMemoryMock = NULL;
AnscWrapperApiMock * g_anscWrapperApiMock = NULL;
UserRuntimeMock* g_userRuntimeMock = NULL;
CcspDmApiMock* g_ccspDmApiMock = NULL;
telemetryMock * g_telemetryMock = NULL;
DslhDmagntExportedMock* g_dslhDmagntExportedMock = NULL;
TraceMock * g_traceMock = NULL;
SyseventMock *g_syseventMock = NULL;
MocaHalMock *g_mocaHALMock = NULL;
msgpackMock *g_msgpackMock = NULL;
webconfigFwMock *g_webconfigFwMock = NULL;
base64Mock *g_base64Mock = NULL;
AnscFileIOMock * g_anscFileIOMock = NULL;
MessageBusMock * g_messagebusMock = NULL;
AnscXmlMock * g_anscXmlMock = NULL;
netsnmpMock *g_netsnmpMock = NULL;
SlapMock * g_slapMock = NULL;
AnscTaskMock * g_anscTaskMock = NULL;
UtilMock * g_utilMock = NULL;

CcspSnmpPaTestFixture::CcspSnmpPaTestFixture()
{
    g_platformHALMock = new PlatformHalMock;
    g_securewrapperMock = new SecureWrapperMock;
    g_socketMock = new SocketMock;
    g_safecLibMock = new SafecLibMock;
    g_anscDebugMock = new AnscDebugMock;
    g_usertimeMock = new UserTimeMock;
    g_baseapiMock = new BaseAPIMock;
    g_syscfgMock = new SyscfgMock;
    g_psmMock = new PsmMock;
    g_parodusMock = new parodusMock;
    g_utopiaMock = new utopiaMock;
    g_anscMemoryMock = new AnscMemoryMock;
    g_anscWrapperApiMock = new AnscWrapperApiMock;
    g_userRuntimeMock = new UserRuntimeMock;
    g_ccspDmApiMock = new CcspDmApiMock;
    g_telemetryMock = new telemetryMock;
    g_dslhDmagntExportedMock = new DslhDmagntExportedMock;
    g_traceMock = new TraceMock;
    g_mocaHALMock = new MocaHalMock;
    g_msgpackMock = new msgpackMock;
    g_syseventMock = new SyseventMock;
    g_webconfigFwMock = new webconfigFwMock;
    g_base64Mock = new base64Mock;
    g_anscFileIOMock = new AnscFileIOMock;
    g_messagebusMock = new MessageBusMock;
    g_anscXmlMock = new AnscXmlMock;
    g_netsnmpMock = new netsnmpMock;
    g_slapMock = new SlapMock;
    g_anscTaskMock = new AnscTaskMock;
    g_utilMock = new UtilMock;
}

CcspSnmpPaTestFixture::~CcspSnmpPaTestFixture()
{
    delete g_platformHALMock;
    delete g_securewrapperMock;
    delete g_socketMock;
    delete g_safecLibMock;
    delete g_anscDebugMock;
    delete g_usertimeMock;
    delete g_baseapiMock;
    delete g_syscfgMock;
    delete g_psmMock;
    delete g_parodusMock;
    delete g_utopiaMock;
    delete g_anscMemoryMock;
    delete g_anscWrapperApiMock;
    delete g_userRuntimeMock;
    delete g_ccspDmApiMock;
    delete g_telemetryMock;
    delete g_dslhDmagntExportedMock;
    delete g_traceMock;
    delete g_mocaHALMock;
    delete g_msgpackMock;
    delete g_syseventMock;
    delete g_webconfigFwMock;
    delete g_base64Mock;
    delete g_anscFileIOMock;
    delete g_messagebusMock;
    delete g_anscXmlMock;
    delete g_netsnmpMock;
    delete g_slapMock;
    delete g_anscTaskMock;
    delete g_utilMock;
    g_platformHALMock = nullptr;
    g_securewrapperMock = nullptr;
    g_socketMock = nullptr;
    g_safecLibMock = nullptr;
    g_anscDebugMock = nullptr;
    g_usertimeMock = nullptr;
    g_baseapiMock = nullptr;
    g_syscfgMock = nullptr;
    g_psmMock = nullptr;
    g_parodusMock = nullptr;
    g_utopiaMock = nullptr;
    g_anscMemoryMock = nullptr;
    g_anscWrapperApiMock = nullptr;
    g_userRuntimeMock = nullptr;
    g_ccspDmApiMock = nullptr;
    g_telemetryMock = nullptr;
    g_dslhDmagntExportedMock = nullptr;
    g_traceMock = nullptr;
    g_mocaHALMock = nullptr;
    g_msgpackMock = nullptr;
    g_syseventMock = nullptr;
    g_webconfigFwMock = nullptr;
    g_base64Mock = nullptr;
    g_anscFileIOMock = nullptr;
    g_messagebusMock = nullptr;
    g_anscXmlMock = nullptr;
    g_netsnmpMock = nullptr;
    g_slapMock = nullptr;
    g_anscTaskMock = nullptr;
    g_utilMock = nullptr;
}

void CcspSnmpPaTestFixture::SetUp()
{
}
void CcspSnmpPaTestFixture::TearDown() {}
void CcspSnmpPaTestFixture::TestBody() {}
// end of file
