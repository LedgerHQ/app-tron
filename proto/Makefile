include ../nanopb/extra/nanopb.mk

DEFINES   += PB_NO_ERRMSG=1

C_TARGETS = core/Tron.pb.c core/Tron.pb.h \
	core/Contract.pb.c core/Contract.pb.h \
	misc/TronApp.pb.c misc/TronApp.pb.h \
	google/protobuf/any.pb.c google/protobuf/any.pb.h

PY_TARGETS = core/Tron_pb2.py \
	core/Contract_pb2.py \
	misc/TronApp_pb2.py \
	google/protobuf/any_pb2.py

default: ${C_TARGETS}
	python3 -m grpc_tools.protoc -I. --python_out=. ./google/protobuf/*.proto ./core/*.proto

clean:
	rm -f ${C_TARGETS} ${PY_TARGETS}
