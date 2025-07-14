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

#ifndef SNMP_MOCK_H
#define SNMP_MOCK_H

#include "gtest/gtest.h"

#include <mocks/mock_securewrapper.h>
#include <mocks/mock_socket.h>
#include <mocks/mock_safec_lib.h>
#include <mocks/mock_ansc_debug.h>
#include <mocks/mock_usertime.h>
#include <mocks/mock_base_api.h>
#include <mocks/mock_syscfg.h>
#include <mocks/mock_psm.h>
#include <mocks/mock_parodus.h>
#include <mocks/mock_utopia.h>
#include <mocks/mock_ansc_memory.h>
#include <mocks/mock_ansc_wrapper_api.h>
#include <mocks/mock_platform_hal.h>
#include <mocks/mock_user_runtime.h>
#include <mocks/mock_ccsp_dmapi.h>
#include <mocks/mock_telemetry.h>
#include <mocks/mock_dslh_dmagnt_exported.h>
#include <mocks/mock_trace.h>
#include <mocks/mock_moca_hal.h>
#include <mocks/mock_msgpack.h>
#include <mocks/mock_sysevent.h>
#include <mocks/mock_webconfigframework.h>
#include <mocks/mock_base64.h>
#include <mocks/mock_ansc_file_io.h>
#include <mocks/mock_messagebus.h>
#include <mocks/mock_ansc_xml.h>
#include <mocks/mock_netsnmp.h>
#include <mocks/mock_slap.h>
#include <mocks/mock_ansc_task.h>
#include <mocks/mock_util.h>

extern "C" {
    #include "ccsp_mib_helper.h"
    #include "ccsp_scalar_helper.h"
    #include "ccsp_scalar_helper_internal.h"
    #include "ccsp_mib_utilities.h"
    #include "cosa_api.h"
    #include "ansc_policy_parser_interface.h"
    #include "ansc_xml_parser_interface.h"

    #define  MY_CHILD_NODE_COOKIE                  0x11223344
    #define  MY_ATTR_NODE_COOKIE                   0x99887766

    typedef
    ANSC_HANDLE
    (*PFN_XML_NODE_OPEN_ATTR)
        (
            ANSC_HANDLE                 hNode,
            PUCHAR                      pAttributeName
        );

    typedef
    ANSC_HANDLE
    (*PFN_XML_NODE_COPY)
        (
            ANSC_HANDLE                 hNode
        );

    typedef
    ANSC_HANDLE
    (*PFN_XML_NODE_GET_FIRST_ATTR)
        (
            ANSC_HANDLE                 hNode
        );

    typedef
    ANSC_HANDLE
    (*PFN_XML_NODE_GET_NEXT_ATTR)
        (
            ANSC_HANDLE                 hNode,
            ANSC_HANDLE                 hAttr
        );

    typedef
    ULONG
    (*PFN_XML_NODE_GET_LEVEL)
        (
            ANSC_HANDLE                 hNode
        );

    typedef
    void
    (*PFN_XML_NODE_SET_LEVEL)
        (
            ANSC_HANDLE                 hNode,
            ULONG                       ulLevel
        );

    typedef
    BOOL
    (*PFN_XML_NODE_ENUM_KID_PROC)
        (
            ANSC_HANDLE                 hNode,
            PVOID                       pData
        );

    typedef
    BOOL
    (*PFN_XML_NODE_ENUM_CHILD)
        (
            ANSC_HANDLE                 hNode,
            PFN_XML_NODE_ENUM_KID_PROC  Proc,
            PVOID                       pData
        );

    typedef  ANSC_STATUS
    (*PFN_PNO_GET_DATA_LONG)
        (
            ANSC_HANDLE                 hThisObject,
            char*                       name,
            PLONG                       plTarget
        );

    #define  ANSC_XML_DOM_NODE_CLASS_CONTENT                                                    \
        /* duplication of the base object class content */                                      \
        SINGLE_LINK_ENTRY               Linkage;                                                \
        ANSC_HANDLE                     hOwnerContext;                                          \
        char                            Name[ANSC_OBJECT_NAME_SIZE];                            \
        ANSC_HANDLE                     hParentNode;                                            \
                                                                                                \
        QUEUE_HEADER                    ChildNodeQueue;                                         \
        ULONG                           ChildNodeQueueLock;                                     \
                                                                                                \
        PFN_PNO_CREATE                  Create;                                                 \
        PFN_PNO_REMOVE                  Remove;                                                 \
        PFN_PNO_RESET                   Reset;                                                  \
                                                                                                \
        PFN_PNO_GET_STATUS              GetStatus;                                              \
        PFN_PNO_GET_ENCODED_SIZE        GetEncodedSize;                                         \
        PFN_PNO_ENCODE                  Encode;                                                 \
        PFN_PNO_DECODE                  Decode;                                                 \
                                                                                                \
        PFN_PNO_GET_NAME                GetName;                                                \
        PFN_PNO_SET_NAME                SetName;                                                \
        PFN_PNO_GET_PARENT_NODE         GetParentNode;                                          \
        PFN_PNO_SET_PARENT_NODE         SetParentNode;                                          \
                                                                                                \
        PFN_PNO_ADD_CHILD               AddChild;                                               \
        PFN_PNO_ADD_CHILD_BYNAME        AddChildByName;                                         \
        PFN_PNO_DEL_CHILD               DelChild;                                               \
        PFN_PNO_DEL_CHILD_BYNAME        DelChildByName;                                         \
        PFN_PNO_INSERT_CHILD            InsertChild;                                            \
        PFN_PNO_REMOVE_CHILD            RemoveChild;                                            \
                                                                                                \
        PFN_PNO_GET_CHILD_BYNAME        GetChildByName;                                         \
        PFN_PNO_GET_HEAD_CHILD          GetHeadChild;                                           \
        PFN_PNO_GET_NEXT_CHILD          GetNextChild;                                           \
        PFN_PNO_GET_TAIL_CHILD          GetTailChild;                                           \
                                                                                                \
        PFN_PNO_GET_ITEM_STRING         GetItemString;                                          \
        PFN_PNO_GET_ITEM_ULONG          GetItemUlong;                                           \
        PFN_PNO_GET_ITEM_BOOLEAN        GetItemBoolean;                                         \
        PFN_PNO_GET_ITEM_BINARY         GetItemBinary;                                          \
        PFN_PNO_GET_ITEM_SIZE           GetItemSize;                                            \
                                                                                                \
        PFN_PNO_GET_ATTR_STRING         GetAttrString;                                          \
        PFN_PNO_GET_ATTR_ULONG          GetAttrUlong;                                           \
        PFN_PNO_GET_ATTR_BOOLEAN        GetAttrBoolean;                                         \
        PFN_PNO_GET_ATTR_BINARY         GetAttrBinary;                                          \
        PFN_PNO_GET_ATTR_SIZE           GetAttrSize;                                            \
                                                                                                \
        PFN_PNO_GET_DATA_STRING         GetDataString;                                          \
        PFN_PNO_GET_DATA_ULONG          GetDataUlong;                                           \
        PFN_PNO_GET_DATA_LONG           GetDataLong;                                            \
        PFN_PNO_GET_DATA_BOOLEAN        GetDataBoolean;                                         \
        PFN_PNO_GET_DATA_BINARY         GetDataBinary;                                          \
        PFN_PNO_GET_DATA_SIZE           GetDataSize;                                            \
                                                                                                \
        PFN_PNO_SET_ATTR_STRING         SetAttrString;                                          \
        PFN_PNO_SET_ATTR_ULONG          SetAttrUlong;                                           \
        PFN_PNO_SET_ATTR_BOOLEAN        SetAttrBoolean;                                         \
        PFN_PNO_SET_ATTR_BINARY         SetAttrBinary;                                          \
                                                                                                \
        PFN_PNO_SET_DATA_STRING         SetDataString;                                          \
        PFN_PNO_SET_DATA_ULONG          SetDataUlong;                                           \
        PFN_PNO_SET_DATA_BOOLEAN        SetDataBoolean;                                         \
        PFN_PNO_SET_DATA_BINARY         SetDataBinary;                                          \
        /* start of object class content */                                                     \
                                                                                                \
        /* XML the name string of the node  */                                                  \
        /* The base class has already defined the variable "Name"  */                           \
        /*    char                    Name[MAXIMUM_NODE_NAME];     */                           \
                                                                                                \
        /* pointer back to the global context */                                                \
        ANSC_HANDLE                     hXMLContext;                                            \
        /* indicate how deep this node is */                                                    \
        ULONG                           Level;                                                  \
        /* The text in this node ( not exists in AL_STORE) */                                   \
        PVOID                           StringData;                                             \
        /* The text size of this node ( not exists in AL_STORE) */                              \
        ULONG                           DataSize;                                               \
        /* maintain a list of the attributes under this node */                                 \
        QUEUE_HEADER                    AttributesList;                                         \
        /* lock for accessing attribute list */                                                 \
        ULONG                           AttributesListLock;                                     \
        /* write XML header or not */                                                           \
        BOOL                            bIgnoreXMLHeader;                                       \
                                                                                                \
        /* end of object class content */                                                       \

    typedef  struct
    _ANSC_XML_DOM_NODE_OBJECT
    {
        ANSC_XML_DOM_NODE_CLASS_CONTENT
    }
    ANSC_XML_DOM_NODE_OBJECT,  *PANSC_XML_DOM_NODE_OBJECT;
  
    void MyCreateFunction();
}

class CcspSnmpPaTestFixture : public ::testing::Test {
  protected:
        PlatformHalMock mockedPlatformHal;
        SecureWrapperMock mockedsecurewrapper;
        SocketMock mockedSocket;
        SafecLibMock mockedSafecLibMock;
        AnscDebugMock mockedAnscDebug;
        UserTimeMock mockedUserTime;
        BaseAPIMock mockedBaseAPI;
        SyscfgMock mockedSyscfg;
        PsmMock mockedPsm;
        parodusMock mockedParodus;
        utopiaMock mockedUtopia;
        AnscMemoryMock mockedAnscMemory;
        AnscWrapperApiMock mockedAnscWrapperApi;
        UserRuntimeMock mockedUserRuntime;
        CcspDmApiMock mockedCcspDmApi;
        telemetryMock mockedTelemetry;
        DslhDmagntExportedMock mockedDslhDmagntExported;
        TraceMock mockedTrace;
        SyseventMock mockedSysevent;
        MocaHalMock mockedMocaHal;
        msgpackMock mockedMsgpack;
        webconfigFwMock mockedWebconfigFw;
        base64Mock mockedBase64;
        AnscFileIOMock mockedAnscFileIOMock;
        MessageBusMock mockedMessageBus;
        AnscXmlMock mockedAnscXml;
        netsnmpMock mockedNetsnmp;
        SlapMock mockedSlap;
        AnscTaskMock mockedTask;
        UtilMock mockedUtil;

        CcspSnmpPaTestFixture();
        virtual ~CcspSnmpPaTestFixture();
        virtual void SetUp() override;
        virtual void TearDown() override;

        void TestBody() override;
};

#endif // SNMP_MOCK_H