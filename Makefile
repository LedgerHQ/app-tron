#*******************************************************************************
#   Ledger App
#   (c) 2018 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

APPNAME = Tron

splitVersion=$(word $2, $(subst ., , $1))

APPVERSION = $(file < VERSION)

APPVERSION_M=$(call splitVersion, $(APPVERSION), 1)
APPVERSION_N=$(call splitVersion, $(APPVERSION), 2)
APPVERSION_P=$(call splitVersion, $(APPVERSION), 3)

# - <VARIANT_PARAM> is the name of the parameter which should be set
#   to specify the variant that should be build.
# - <VARIANT_VALUES> a list of variant that can be build using this app code.
#   * It must at least contains one value.
#   * Values can be the app ticker or anything else but should be unique.
VARIANT_PARAM = COIN
VARIANT_VALUES = tron

CURVE_APP_LOAD_PARAMS = secp256k1
PATH_APP_LOAD_PARAMS = "44'/195'"  # purpose=coin(44) / coin_type=Tron(1)

ICON_NANOS = icons/nanos_app_tron.gif
ICON_NANOX = icons/nanox_app_tron.gif
ICON_NANOSP = icons/nanox_app_tron.gif
ICON_STAX = icons/stax_app_tron.gif
ICON_FLEX = icons/flex_app_tron.gif

ENABLE_BLUETOOTH = 1
ENABLE_SWAP = 1
ENABLE_NBGL_QRCODE = 1

# Enabling DEBUG flag will enable PRINTF and disable optimizations
DEBUG ?= 0

APP_SOURCE_PATH  += src

.PHONY: proto
proto:
	$(MAKE) -C proto

cleanall : clean
	$(MAKE) -C proto clean

# nanopb
#include nanopb/extra/nanopb.mk
NANOPB_DIR = nanopb

CFLAGS += "-I$(NANOPB_DIR)" -Iproto
DEFINES   += PB_NO_ERRMSG=1
SOURCE_FILES += $(NANOPB_DIR)/pb_encode.c $(NANOPB_DIR)/pb_decode.c $(NANOPB_DIR)/pb_common.c
APP_SOURCE_PATH += proto

include $(BOLOS_SDK)/Makefile.standard_app
