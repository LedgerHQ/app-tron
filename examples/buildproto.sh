#!/bin/sh
mkdir -p protocol/googleapis/google/api
mkdir -p proto
cp -r ../proto/* proto

git clone https://github.com/tronprotocol/protocol.git protocol/tron
curl https://raw.githubusercontent.com/googleapis/googleapis/master/google/api/annotations.proto > protocol/googleapis/google/api/annotations.proto
curl https://raw.githubusercontent.com/googleapis/googleapis/master/google/api/http.proto > protocol/googleapis/google/api/http.proto

python3 -m grpc_tools.protoc -I. --python_out=. ./proto/core/*.proto
python3 -m grpc_tools.protoc -I. --python_out=. ./proto/google/protobuf/*.proto
python3 -m grpc_tools.protoc -I./protocol/googleapis --python_out=./proto ./protocol/googleapis/google/api/*.proto
