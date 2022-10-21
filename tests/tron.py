#!/usr/bin/env python3
import sys
import base58

from contextlib import contextmanager
from pathlib import Path
from time import sleep
from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1
from eth_keys import keys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from ragger.backend.interface import BackendInterface, RAPDU
from ragger.navigator import NavInsID, NavIns
from conftest import MNEMONIC

sys.path.append(f"{Path(__file__).parent.parent.resolve()}/examples")
sys.path.append(f"{Path(__file__).parent.parent.resolve()}/examples/proto")
from base import parse_bip32_path
'''
Tron Protobuf
'''
from core import Tron_pb2 as tron
from google.protobuf.any_pb2 import Any
from google.protobuf.internal.decoder import _DecodeVarint32

class TronClient:
    # default APDU TCP server
    HOST, PORT = ('127.0.0.1', 9999)
    CLA = 0xE0
    def __init__(self, client: BackendInterface, firmware,navigator):
        if not isinstance(client, BackendInterface):
            raise TypeError('client must be an instance of BackendInterface')
        self._client = client
        self._firmware = firmware
        self._navigator = navigator
        self.accounts = [None, None]
        self.hardware = True

        # Init account with default address to compare with ledger
        for i in range(2):
            HD = self.getPrivateKey(MNEMONIC, i, 0, 0)
            key = keys.PrivateKey(HD)
            diffieHellman = ec.derive_private_key(int.from_bytes(HD, "big"), ec.SECP256K1(), default_backend())
            self.accounts[i] = {
                    "path": parse_bip32_path("44'/195'/{}'/0/0".format(i)),
                    "privateKeyHex": HD.hex(),
                    "key": key,
                    "addressHex": "41" + key.public_key.to_checksum_address()[2:].upper(),
                    "publicKey": key.public_key.to_hex().upper(),
                    "dh": diffieHellman,
                }
        
    def _exchange(self, ins: int, p1: int,p2: int, payload: bytes = b"") -> RAPDU:
        return self._client.exchange(self.CLA, ins, p1=p1,
                                     p2=p2, data=payload)
        
    def _exchange_raw(self, payload: bytes = b"") -> RAPDU:
        return self._client.exchange_raw(data=payload)

    def address_hex(self, address):
        return base58.b58decode_check(address).hex().upper()

    def getPrivateKey(self, seed, account, change, address_index):
        seed_bytes = Bip39SeedGenerator(seed).Generate()
        bip32_ctx = Bip32Slip10Secp256k1.FromSeedAndPath(seed_bytes, f"m/44'/195'/{account}'/{change}/{address_index}")
        return bytes(bip32_ctx.PrivateKey().Raw())        


    def apduMessage(self, INS, P1, P2, MESSAGE):
        hexString = "E0{:02x}{:02x}{:02x}{:02x}{}".format(INS,P1,P2,len(MESSAGE)//2,MESSAGE)
        return bytes.fromhex(hexString)
    
    def getAccount(self, number):
        return self.accounts[number]

    def packContract(self, contractType, newContract, data = None, permission_id = None):
        tx = tron.Transaction()    
        tx.raw_data.timestamp = 1575712492061
        tx.raw_data.expiration = 1575712551000
        tx.raw_data.ref_block_hash = bytes.fromhex("95DA42177DB00507")
        tx.raw_data.ref_block_bytes = bytes.fromhex("3DCE")
        if data:
            tx.raw_data.data = data
        
    
        c = tx.raw_data.contract.add()
        c.type = contractType
        param = Any()
        param.Pack(newContract,deterministic=True)
        
        c.parameter.CopyFrom(param)
        
        if permission_id:
            c.Permission_id = permission_id
        return tx.raw_data.SerializeToString()


    def get_next_length(self,tx):
        field, pos = _DecodeVarint32(tx,0)
        size, newpos = _DecodeVarint32(tx,pos)
        if (field&0x07==0): return newpos
        return size + newpos
    
    @contextmanager
    def exchange_async_and_navigate(self, 
                                    pack,
                                    snappath:Path = None,
                                    text:str =""):
        with self._client.exchange_async_raw(pack) as r:
            if self._firmware.device == "stax":
                sleep(1.5)
                self._navigator.navigate_until_text_and_compare(NavIns(NavInsID.TOUCH, (200,545)),[NavIns(NavInsID.USE_CASE_REVIEW_CONFIRM)],text,
                                                                Path(__file__).parent.resolve(),snappath,screen_change_after_last_instruction=False)
            else:
                self._navigator.navigate_until_text_and_compare(NavIns(NavInsID.RIGHT_CLICK),[NavIns(NavInsID.BOTH_CLICK)],text,
                                                                Path(__file__).parent.resolve(),snappath,screen_change_after_last_instruction=False)
    
    @contextmanager
    def sign(self,
             path,
             tx, 
             signatures=[],
             snappath:Path = None,
             text:str ="",
             navigate:bool = True):
        max_length = 255
        offset = 0
        to_send = []
        start_bytes = []

        data = bytearray.fromhex(f"05{path}")
        while len(tx)>0:
            # get next message field
            newpos = self.get_next_length(tx)
            assert(newpos<max_length)
            if (len(data)+newpos) > max_length:
                # add chunk
                to_send.append(data.hex())
                data = bytearray()
                continue
            # append to data
            data.extend(tx[:newpos])
            tx = tx[newpos:]
        # append last
        to_send.append(data.hex())
        token_pos = len(to_send)
        to_send.extend(signatures)

        if len(to_send)==1:
            start_bytes.append(0x10)
        else:
            start_bytes.append(0x00)
            for i in range(1, len(to_send) - 1):
                if (i>=token_pos):
                    start_bytes.append(0xA0 | 0X00 | i-token_pos )
                else:
                    start_bytes.append(0x80)
            
            if not(signatures==None) and len(signatures)>0:
                start_bytes.append(0xa0 | 0x08 | len(signatures)-1)
            else:
                start_bytes.append(0x90)

        for i in range(len(to_send)):
            pack = self.apduMessage(
                0x04,
                start_bytes[i],
                0x00,
                to_send[i]
            )
            if i < len(to_send)-1:
                
                ret = self._exchange_raw(payload=pack)
                if not (ret.status == 0x9000):
                    raise ValueError("Something went wrong while sending the APDU.") 

            else:    
                with self._client.exchange_async_raw(pack) as r:
                    if navigate:
                        if self._firmware.device == "stax":
                            sleep(1.5)
                            self._navigator.navigate_until_text_and_compare(NavIns(NavInsID.TOUCH, (200,545)),[NavIns(NavInsID.USE_CASE_REVIEW_CONFIRM)],text,
                                                                            Path(__file__).parent.resolve(),snappath,screen_change_after_last_instruction=False)
                        else:
                            self._navigator.navigate_until_text_and_compare(NavIns(NavInsID.RIGHT_CLICK),[NavIns(NavInsID.BOTH_CLICK)],text,
                                                                            Path(__file__).parent.resolve(),snappath,screen_change_after_last_instruction=False)
                    else:
                        pass                    
                    sleep(0.5)
