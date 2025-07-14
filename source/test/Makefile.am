##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
AM_CFLAGS = -fPIC -fno-exceptions -Os -Wall -Wextra

AM_CXXFLAGS = -std=c++11

ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = snmp_subagent_gtest.bin

snmp_subagent_gtest_bin_CPPFLAGS = -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/gtest \
                                   -I${top_srcdir}/gtest/include \
                                   -I${top_srcdir}/source \
                                   -I${top_srcdir}/source/test \
                                   -I${top_srcdir}/source/test/mocks \
                                   -I${top_srcdir}/source/custom \
                                   -I${top_srcdir}/source/include \
                                   -I${top_srcdir}/source/SnmpPlugin \
                                   -DUNIT_TEST_DOCKER_SUPPORT \
                                   -DFEATURE_RDKB_WAN_MANAGER

snmp_subagent_gtest_bin_SOURCES = gtest_main.cpp \
                                  mocks/print_uptime.c \
                                  ${top_srcdir}/source/custom/ccsp_snmp_common.c \
                                  ${top_srcdir}/source/custom/rg_devmgmt_handler.c \
                                  ${top_srcdir}/source/SnmpPlugin/ccsp_mib_helper.c \
                                  ${top_srcdir}/source/SnmpPlugin/ccsp_mib_utilities.c \
                                  ${top_srcdir}/source/SnmpPlugin/ccsp_scalar_helper_access.c \
                                  ${top_srcdir}/source/SnmpPlugin/ccsp_scalar_helper_control.c \
                                  ${top_srcdir}/source/SnmpPlugin/ccsp_scalar_helper.c \
                                  ${top_srcdir}/source/SnmpPlugin/ccsp_table_helper_access.c \
                                  ${top_srcdir}/source/SnmpPlugin/ccsp_table_helper_control.c \
                                  ${top_srcdir}/source/SnmpPlugin/ccsp_table_helper.c \
                                  ${top_srcdir}/source/SnmpPlugin/cosa_api.c \
                                  ${top_srcdir}/source/SnmpPlugin/CcspSnmpPlugin.c \
                                  snmp_mock.cpp \
                                  snmp_subagentTest.cpp \
                                  rg_devmgmt_handler_test.cpp \
                                  ccsp_misc_utilities_test.cpp \
                                  ccsp_scalar_helper_test.cpp \
                                  ccsp_table_helper_test.cpp \
                                  CcspSnmpPlugin_test.cpp

snmp_subagent_gtest_bin_LDFLAGS = -lgtest -lgmock -lgcov -lpthread -ldl

snmp_subagent_gtest_bin_LDADD = $(HOME)/usr/local/lib/libmock_ccsp_common.la \
                                $(HOME)/usr/local/lib/libmock_platform_hal.la \
                                $(HOME)/usr/local/lib/libmock_secure_wrapper.la \
                                $(HOME)/usr/local/lib/libmock_safec_lib.la \
                                $(HOME)/usr/local/lib/libmock_psm.la \
                                $(HOME)/usr/local/lib/libmock_syscfg.la \
                                $(HOME)/usr/local/lib/libmock_utopia.la \
                                $(HOME)/usr/local/lib/libmock_telemetry.la \
                                $(HOME)/usr/local/lib/libmock_parodus.la \
                                $(HOME)/usr/local/lib/libmock_rbus.la \
                                $(HOME)/usr/local/lib/libmock_moca_hal.la \
                                $(HOME)/usr/local/lib/libmock_msgpack.la \
                                $(HOME)/usr/local/lib/libmock_webconfigframework.la \
                                $(HOME)/usr/local/lib/libmock_sysevent.la \
                                $(HOME)/usr/local/lib/libmock_base64.la \
                                $(HOME)/usr/local/lib/libmock_netsnmp.la \
                                $(HOME)/usr/local/lib/libmock_util.la

# Adding Code Coverage Flags
AM_CFLAGS += -fprofile-arcs -ftest-coverage
AM_CXXFLAGS += -fprofile-arcs -ftest-coverage
snmp_subagent_gtest_bin_LDFLAGS += --coverage
