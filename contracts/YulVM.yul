//
// Copyright (C) 2022 Paul Ciarlo <paul.ciarlo@gmail.com>
//

object "YulVM" {
	code {
		let sz := datasize("runtime")
		datacopy(0, dataoffset("runtime"), sz)
		return(0,sz)
	}
	object "runtime" {
		code {
			/*
			function basefee() -> out {
				out := verbatim_0i_1o(hex"48")
			}
			function selfbalance() -> out {
				out := balance(address())
			}
			function chainid() -> out {
				out := verbatim_0i_1o(hex"46")
			}
			*/
			switch shr(0xe0, calldataload(0))
			case 0x89d5e154 { // function executeBytecode(bytes calldata _bytecode) public {}
				//let pcoffset := 4
				//let freememp := 0x40
				//let bp := 0x60 // stack base pointer
				// mstore(0x40, 0x60) // set this when calling out
				let sp := 0x60 // stack pointer, stack grows toward higher address
				//let stackmax := add(0x60,0x220) // 17*0x20 max stack 17 item (enough for SWAP16)
				//let membp := 0x280
				//let freemem := 0x280 // membp // mem size = memmax - membp
				mstore(0x40, 0x280)
				for { let ip := 4 } // instruction pointer (ie pointer into calldata, subtract 4 for pc)
					lt(ip,calldatasize())
					{ ip := add(ip,1) }
				{
					let ibuf := calldataload(ip)
					let opcode := shr(0xf8, ibuf)
					//let optype := and(0xf0,shr(0xf8, ibuf))
					//let op := and(0x0f,shr(0xf8, ibuf))
					let res := 0
					switch and(0xf0,shr(0xf8, ibuf))
					case 0x00 {
						// arithmetic
						sp := sub(sp,0x20)
						// op1 is top op2 op1 + op2
						let op1 := mload(sp)
						let op2 := mload(sub(sp,0x20))
						switch and(0x0f,shr(0xf8, ibuf))
						case 0x1 { res := add(op1, op2) }
						case 0x2 { res := mul(op1, op2) }
						case 0x3 { res := sub(op1, op2) }
						case 0x4 { res := div(op1, op2) }
						case 0x5 { res := sdiv(op1, op2) }
						case 0x6 { res := mod(op1, op2) }
						case 0x7 { res := smod(op1, op2) }
						case 0x8 {
							res := addmod(op1, op2, mload(sub(sp,0x40)))
							sp := sub(sp,0x20)
						}
						case 0x9 {
							res := addmod(op1, op2, mload(sub(sp,0x40)))
							sp := sub(sp,0x20)
						}
						case 0xa { res := exp(op1, op2) }
						case 0xb { res := signextend(op1, op2) }
						//case 0x0 { stop() }
						default { stop() }
						mstore(sub(sp,0x20), res)
					}
					case 0x10 {
						// comparison
						let op1 := mload(sub(sp,0x20))
						switch and(0x0f,shr(0xf8, ibuf))
						case 0x5 { res := iszero(op1) }
						case 0x9 { res := not(op1) }
						default {
							let op2 := mload(sub(sp,0x40))
							sp := sub(sp,0x20)
							switch and(0x0f,shr(0xf8, ibuf))
							case 0x0 { res :=   lt(op1,op2) }
							case 0x1 { res :=   gt(op1,op2) }
							case 0x2 { res :=  slt(op1,op2) }
							case 0x3 { res :=  sgt(op1,op2) }
							case 0x4 { res :=   eq(op1,op2) }
							case 0x6 { res :=  and(op1,op2) }
							case 0x7 { res :=   or(op1,op2) }
							case 0x8 { res :=  xor(op1,op2) }
							case 0xa { res := byte(op1,op2) }
							case 0xb { res :=  shl(op1,op2) }
							case 0xc { res :=  shr(op1,op2) }
							case 0xd { res :=  sar(op1,op2) }
							default { stop() }
						}
						mstore(sub(sp,0x20), res)
					}
					case 0x20 {
						// SHA3
						switch and(0x0f,shr(0xf8, ibuf))
						case 0x0 {
							sp := sub(sp,0x20)
							let hash_ := keccak256(mload(sp), mload(sub(sp,0x20)))
							mstore(sub(sp,0x20), hash_)
						}
						default { stop() }
					}
					case 0x30 {
						// tx info
						switch and(0x0f,shr(0xf8, ibuf))
						case 0x0 {
							// ADDRESS
							mstore(sp, address())
							sp := add(sp, 0x20)
						}
						case 0x1 {
							// BALANCE
							res := balance(sub(sp,0x20))
							mstore(sub(sp,0x20), res)
						}
						case 0x2 {
							// ORIGIN
							mstore(sp, origin())
							sp := add(sp, 0x20)
						}
						case 0x3 {
							// CALLER
							mstore(sp, caller())
							sp := add(sp, 0x20)
						}
						case 0x4 {
							// CALLVALUE
							mstore(sp, callvalue())
							sp := add(sp, 0x20)
						}
						case 0x5 {
							// CALLDATALOAD
							res := calldataload(sub(sp,0x20))
							mstore(sub(sp,0x20),res)
						}
						case 0x6 {
							// CALLDATASIZE
							mstore(sp, calldatasize())
							sp := add(sp, 0x20)
						}
						case 0x7 {
							// CALLDATACOPY
							sp := sub(sp,0x20)
							let destOffset := mload(sp)
							sp := sub(sp,0x20)
							let offset := mload(sp)
							sp := sub(sp, 0x20)
							let length := mload(sp)
							calldatacopy(destOffset,offset,length)
							let memmax := add(destOffset,length)
							let freemem := mload(0x40)
							if or(gt(memmax,freemem),eq(memmax,freemem)) {
								freemem := add(0x20,memmax)
								mstore(0x40,freemem)
							}
						}
						case 0x8 {
							// CODESIZE
							mstore(sp, codesize())
							sp := add(sp,0x20)
						}
						case 0x9 {
							// CODECOPY
							sp := sub(sp,0x20)
							let destOffset := mload(sp)
							sp := sub(sp,0x20)
							let offset := mload(sp)
							sp := sub(sp, 0x20)
							let length := mload(sp)
							codecopy(destOffset, offset, length)
							let memmax := add(destOffset,length)
							let freemem := mload(0x40)
							if or(gt(memmax,freemem),eq(memmax,freemem)) {
								freemem := add(0x20,memmax)
								mstore(0x40,freemem)
							}
						}
						case 0xa {
							// GASPRICE
							mstore(sp, gasprice())
							sp := add(sp, 0x20)
						}
						case 0xb {
							// EXTCODESIZE
							let stacktop := sub(sp,0x20)
							let addr := mload(stacktop)
							res := extcodesize(addr)
							mstore(stacktop,res)
						}
						case 0xc {
							// EXTCODECOPY
							sp := sub(sp,0x20)
							let addr := mload(sp)
							sp := sub(sp,0x20)
							let destOffset := mload(sp)
							sp := sub(sp, 0x20)
							let offset := mload(sp)
							sp := sub(sp, 0x40)
							let length := mload(sp)
							extcodecopy(addr, destOffset, offset, length)
							let memmax := add(destOffset,length)
							let freemem := mload(0x40)
							if or(gt(memmax,freemem),eq(memmax,freemem)) {
								freemem := add(0x20,memmax)
								mstore(0x40,freemem)
							}
						}
						case 0xd {
							// RETURNDATASIZE
							mstore(sp, returndatasize())
							sp := add(sp,0x20)
						}
						case 0xe {
							// RETURNDATACOPY
							sp := sub(sp,0x20)
							let destOffset := mload(sp)
							sp := sub(sp,0x20)
							let offset := mload(sp)
							sp := sub(sp, 0x20)
							let length := mload(sp)
							returndatacopy(destOffset, offset, length)
							let memmax := add(destOffset,length)
							let freemem := mload(0x40)
							if or(gt(memmax,freemem),eq(memmax,freemem)) {
								freemem := add(0x20,memmax)
								mstore(0x40,freemem)
							}
						}
						case 0xf {
							// EXTCODEHASH
							let stacktop := sub(sp,0x20)
							res := extcodehash(stacktop)
							mstore(stacktop,res)
						}
					}
					case 0x40 {
						// block info
						switch and(0x0f,shr(0xf8, ibuf))
						case 0x0 {
							// BLOCKHASH
							sp := sub(sp,0x20)
							let blockNumber := mload(sp)
							res := blockhash(blockNumber)
						}
						case 0x1 { res := coinbase() }
						case 0x2 { res := timestamp() }
						case 0x3 { res := number() }
						case 0x4 { res := difficulty() }
						case 0x5 { res := gaslimit() }
						case 0x6 { res := chainid() }
						case 0x7 { res := selfbalance() }
						case 0x8 { res := basefee() }
						default { stop() }
						mstore(sp,res)
						sp := add(sp,0x20)
					}
					case 0x50 {
						// memory/storage
						switch and(0x0f,shr(0xf8, ibuf))
						case 0x0 {
							// POP
							sp := sub(sp,0x20)
						}
						case 0x1 {
							// MLOAD
							let stacktop := sub(sp,0x20)
							let memp := mload(stacktop)
							let value := mload(memp)
							mstore(stacktop, value)
						}
						case 0x2 {
							// MSTORE
							sp := sub(sp,0x20)
							let offset := mload(sp)
							sp := sub(sp,0x20)
							let value := mload(sp)
							mstore(offset, value)
							let freemem := mload(0x40)
							if or(gt(offset,freemem),eq(offset,freemem)) {
								freemem := add(0x20,offset)
								mstore(0x40,freemem)
							}
						}
						case 0x3 {
							// MSTORE8
							sp := sub(sp,0x20)
							let offset := mload(sp)
							sp := sub(sp,0x20)
							let value := and(0xff,mload(sp))
							mstore(offset, value)
							let freemem := mload(0x40)
							if or(gt(offset,freemem),eq(offset,freemem)) {
								freemem := add(0x20,offset)
								mstore(0x40,freemem)
							}
						}
						case 0x4{
							// SLOAD
							let key := mload(sub(sp,0x20))
							let value := sload(key)
							mstore(value, sub(sp,0x20))
						}
						case 0x5 {
							// SSTORE
							sp := sub(sp,0x20)
							let key := mload(sp)
							sp := sub(sp,0x20)
							let value := mload(sp)
							sstore(key, value)
						}
						case 0x6 {
							// JUMP
							sp := sub(sp,0x20)
							let destination := add(mload(sp),3) // -1+4
							ip := destination
						}
						case 0x7 {
							// JUMPI
							sp := sub(sp,0x20)
							let destination := add(mload(sp),3) // -1+4
							sp := sub(sp,0x20)
							let condition := mload(sp)
							if condition { ip := destination }
						}
						case 0x8 {
							// PC
							mstore(sp,sub(ip,4))
							sp := add(sp,0x20)
						}
						case 0x9 {
							// MSIZE
							let freemem := mload(0x40)
							mstore(sp,sub(freemem,0x280))
							sp := add(sp,0x20)
						}
						case 0xa {
							// GAS
							mstore(sp, gas())
							sp := add(sp,0x20)
						}
						case 0xb {
							// JUMPDEST
							// no-op
						}
						default { stop() }
					}
					case 0x60 {
						// PUSH1-16
						let pushbytes := add(1,and(0x0f,shr(0xf8, ibuf)))
						let pushbits := shl(3,pushbytes)
						ibuf := shl(8,ibuf) // trunc. opcode
						ibuf := shr(sub(256,pushbits),ibuf)
						mstore(sp,ibuf)
						sp := add(0x20,sp)
						ip := add(pushbytes,ip)
					}
					case 0x70 {
						// PUSH17-32
						let pushbytes := add(17,and(0x0f,shr(0xf8, ibuf)))
						let pushbits := shl(3,pushbytes)
						ibuf := calldataload(add(1,ip)) // PUSH32 doesn't fit with opcode
						ibuf := shr(sub(256,pushbits), ibuf)
						mstore(sp,ibuf)
						sp := add(0x20,sp)
						ip := add(pushbytes,ip)
					}
					case 0x80 {
						// DUP1-16
						let dup := mload(sub(sp,shl(5,add(1,and(0x0f,shr(0xf8, ibuf))))))
						mstore(sp,dup)
						sp := add(sp,0x20)
					}
					case 0x90 {
						// SWAP1-16
						let stacktop := sub(sp,0x20)
						let stackswap := sub(sp,shl(5,add(2,and(0x0f,shr(0xf8, ibuf)))))
						let topval := mload(stacktop)
						let swapval := mload(stackswap)
						mstore(stacktop,swapval)
						mstore(stackswap,topval)
					}
					case 0xa0 {
						// LOG1-4
						switch and(0x0f,shr(0xf8, ibuf))
						case 0x0 {
							// LOG0
							sp := sub(sp,0x20)
							let offset := mload(sp)
							sp := sub(sp,0x20)
							let length := mload(sp)
							log0(offset, length)
						}
						case 0x1 {
							// LOG1
							sp := sub(sp,0x20)
							let offset := mload(sp)
							sp := sub(sp,0x20)
							let length := mload(sp)
							sp := sub(sp,0x20)
							let topic0 := mload(sp)
							log1(offset, length, topic0)
						}
						case 0x2 {
							// LOG2
							sp := sub(sp,0x20)
							let offset := mload(sp)
							sp := sub(sp,0x20)
							let length := mload(sp)
							sp := sub(sp,0x20)
							let topic0 := mload(sp)
							sp := sub(sp,0x20)
							let topic1 := mload(sp)
							log2(offset, length, topic0, topic1)
						}
						case 0x3 {
							// LOG3
							sp := sub(sp,0x20)
							let offset := mload(sp)
							sp := sub(sp,0x20)
							let length := mload(sp)
							sp := sub(sp,0x20)
							let topic0 := mload(sp)
							sp := sub(sp,0x20)
							let topic1 := mload(sp)
							sp := sub(sp,0x20)
							let topic2 := mload(sp)
							log3(offset, length, topic0, topic1, topic2)
						}
						case 0x4 {
							// LOG4
							sp := sub(sp,0x20)
							let offset := mload(sp)
							sp := sub(sp,0x20)
							let length := mload(sp)
							sp := sub(sp,0x20)
							let topic0 := mload(sp)
							sp := sub(sp,0x20)
							let topic1 := mload(sp)
							sp := sub(sp,0x20)
							let topic2 := mload(sp)
							sp := sub(sp,0x20)
							let topic3 := mload(sp)
							log4(offset, length, topic0, topic1, topic2, topic3)
						}
						default { stop() }
					}
					case 0xf0 {
						// execution
						switch and(0x0f,shr(0xf8, ibuf))
						case 0x0 {
							// CREATE
							sp := sub(sp,0x20)
							let value := mload(sp)
							sp := sub(sp,0x20)
							let offset := mload(sp)
							let length := mload(sub(sp,0x20))
							let addr := create(value,offset,length)
							mstore(sub(sp,0x20),addr)
						}
						case 0x1 {
							// CALL
							let retOffset := mload(sub(sp,0x120))
							let retLength := mload(sub(sp,0x140))
							let success := call(
								mload(sub(sp,0x20)),
								mload(sub(sp,0x40)),
								mload(sub(sp,0x60)),
								mload(sub(sp,0x80)),
								mload(sub(sp,0x100)),
								retOffset,
								retLength)
							sp := sub(sp,0x120)
							// not sure if this is needed maybe callee does it?
							let memmax := add(retOffset,retLength)
							let freemem := mload(0x40)
							if or(gt(memmax,freemem),eq(memmax,freemem)) {
								freemem := add(0x20,memmax)
								mstore(0x40,freemem)
							}
						}
						case 0x2 {
							// CALLCODE
							let retOffset := mload(sub(sp,0x120))
							let retLength := mload(sub(sp,0x140))
							let success := callcode(
								mload(sub(sp,0x20)),
								mload(sub(sp,0x40)),
								mload(sub(sp,0x60)),
								mload(sub(sp,0x80)),
								mload(sub(sp,0x100)),
								retOffset,
								retLength)
							sp := sub(sp,0x120)
							// not sure if this is needed maybe callee does it?
							let memmax := add(retOffset,retLength)
							let freemem := mload(0x40)
							if or(gt(memmax,freemem),eq(memmax,freemem)) {
								freemem := add(0x20,memmax)
								mstore(0x40,freemem)
							}
						}
						case 0x3 {
							// RETURN
							sp := sub(sp,0x20)
							let offset := mload(sp)
							sp := sub(sp,0x20)
							let length := mload(sp)
							return(offset,length)
						}
						case 0x4 {
							// DELEGATECALL
							let retOffset := mload(sub(sp,0x100))
							let retLength := mload(sub(sp,0x120))
							let success := delegatecall(
								mload(sub(sp,0x20)),
								mload(sub(sp,0x40)),
								mload(sub(sp,0x60)),
								mload(sub(sp,0x80)),
								retOffset,
								retLength)
							sp := sub(sp,0x100)
							// not sure if this is needed maybe callee does it?
							let memmax := add(retOffset,retLength)
							let freemem := mload(0x40)
							if or(gt(memmax,freemem),eq(memmax,freemem)) {
								freemem := add(0x20,memmax)
								mstore(0x40,freemem)
							}
						}
						case 0x5 {
							// CREATE2
							sp := sub(sp,0x20)
							let value := mload(sp)
							sp := sub(sp,0x20)
							let offset := mload(sp)
							sp := sub(sp,0x20)
							let length := mload(sp)
							let salt := mload(sub(sp,0x20))
							let addr := create2(value,offset,length,salt)
							mstore(sub(sp,0x20),addr)
						}
						// 0x6-0x9 invalid
						case 0xa {
							// STATICCALL
							let retOffset := mload(sub(sp,0x100))
							let retLength := mload(sub(sp,0x120))
							let success := staticcall(
								mload(sub(sp,0x20)),
								mload(sub(sp,0x40)),
								mload(sub(sp,0x60)),
								mload(sub(sp,0x80)),
								retOffset,
								retLength)
							sp := sub(sp,0x100)
							// not sure if this is needed maybe callee does it?
							let memmax := add(retOffset,retLength)
							let freemem := mload(0x40)
							if or(gt(memmax,freemem),eq(memmax,freemem)) {
								freemem := add(0x20,memmax)
								mstore(0x40,freemem)
							}
						}
						// 0xb-0xc invalid
						case 0xd {
							// REVERT
							sp := sub(sp,0x20)
							let offset := mload(sp)
							sp := sub(sp,0x20)
							let length := mload(sp)
							revert(offset,length)
						}
						// 0xe invalid
						case 0xf {
							// SELFDESTRUCT
							sp := sub(sp,0x20)
							let addr := mload(sp)
							selfdestruct(addr)
						}
						default { stop() }
					}
					default { stop() }
				}
			}
		}
	}
}
