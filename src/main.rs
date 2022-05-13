mod stack;
mod memory;

use primitive_types::{H256, U256};
use sha3::{Digest, Keccak256};
use std::{collections::HashMap};

use stack::Stack;
use memory::Memory;


struct Call {
    storage: HashMap<H256, H256>,
    code: Vec<u8>,
    calldata: Vec<u8>,
    pc: usize,
    stack: Stack,
    memory: Memory,
    ret_data: Vec<u8>
}

impl Call {
    fn new(code: Vec<u8>, calldata: Vec<u8>) -> Self {
        Self {
            storage: HashMap::new(),
            pc: 0,
            ret_data: Vec::new(),
            stack: Stack::new(),
            memory: Memory::new(),
            code: code,
            calldata: calldata
        }
    }

    fn run(&mut self) {
        while self.pc < self.code.len() {
            self.eval(*self.code.get(self.pc).unwrap());
        }
    }

    fn eval(&mut self, op: u8) {
        println!("Executing: {:x} {}",op, name_from_op(op));
        // println!("Stack: {:?}", self.stack.data());
        // println!("Memory: {:?} {}", self.memory.data(), self.memory.data().len());
        match op {
            /* Arithmetic */
            //ADD
            0x01 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                self.stack.push_u256(a+b);
            }
            //MUL
            0x02 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                self.stack.push_u256(a * b);
            }
            //SUB
            0x03 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                self.stack.push_u256(a-b);
            }
            //DIV
            0x04 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                self.stack.push_u256(a/b);
            }
            //SDIV
            //MOD
            0x06 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                self.stack.push_u256(a % b);
            }
            //SMOD
            //ADDMOD
            0x08 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                let n = self.stack.pop_u256();
                self.stack.push_u256((a+b) % n);
            }
            //MULMOD
            0x09 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                let n = self.stack.pop_u256();
                self.stack.push_u256((a*b) % n);
            }
            //EXP
            0x0a => {
                let a = self.stack.pop_u256();
                let exp = self.stack.pop_u256();
                self.stack.push_u256(a.pow(exp));
            }
            /* Bitwise */
            //SIGNEXTEND
            //LT
            0x10 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                let res = if a < b {U256::one()} else {U256::zero()};
                self.stack.push_u256(res);
            }
            //GT
            0x11 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                let res = if a > b {U256::one()} else {U256::zero()};
                self.stack.push_u256(res);
            }
            //SLT
            //SGT
            //EQ
            0x14 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                let res = if a == b {U256::one()} else {U256::zero()};
                self.stack.push_u256(res);
            }
            //ISZERO
            0x15 => {
                let a = self.stack.pop_u256();
                let res = if a == U256::zero() {U256::one()} else {U256::zero()};
                self.stack.push_u256(res);
            }
            //AND
            0x16 => {
                let a = self.stack.pop();
                let b = self.stack.pop();
                
                self.stack.push(a & b);
            }
            //OR
            0x17 => {
                let a = self.stack.pop();
                let b = self.stack.pop();
                
                self.stack.push(a | b);
            }
            //XOR
            0x18 => {
                let a = self.stack.pop();
                let b = self.stack.pop();
                
                self.stack.push(a ^ b);
            }
            //NOT
            0x19 => {
                let a = self.stack.pop_u256();
                
                self.stack.push_u256(!a);
            }
            //BYTE
            //TODO: understand this
            0x1A => {
                let word = self.stack.pop_u256();
                let val = self.stack.pop_u256();
                let byte = match word < U256::from(32) {
                    true => (val >> (8 * (31 - word.low_u64() as usize))) & U256::from(0xff),
                    false => U256::zero()
                };

                self.stack.push_u256(byte);
            }
            //SHL
            0x1B => {
                let shift = self.stack.pop_u256();
                let val = self.stack.pop_u256();

                self.stack.push_u256(val << shift);
            }
            //SHR
            0x1C => {
                let shift = self.stack.pop_u256();
                let val = self.stack.pop_u256();

                self.stack.push_u256(val >> shift);
            }
            //SAR

            //SHA3
            0x20 => {
                let offset = self.stack.pop_u256();
                let size = self.stack.pop_u256();

                let data = self.memory.load(offset.as_usize(), size.as_usize());
                let hash = Keccak256::digest(data.as_slice());
                self.stack.push(H256::from_slice(hash.as_slice()));
            }

            //ADDRESS
            //BALANCE
            //ORIGIN
            //CALLER
            //CALLVALUE
            //CALLDATALOAD
            0x35 => {
                let i = self.stack.pop_u256().as_usize();

                let data = &self.calldata[i..i+32];
                self.stack.push(H256::from_slice(data));
            }
            //CALLDATASIZE
            0x36 => {
                self.stack.push_u256(U256::from(self.calldata.len()));
            }
            //CALLDATACOPY
            0x37 => {
                let destination = self.stack.pop_u256().as_usize();
                let offset = self.stack.pop_u256().as_usize();
                let size = self.stack.pop_u256().as_usize();

                let mut extension = vec![u8::from(0); size];
                
                for i in 0..self.calldata.len() {
                    extension[i] = self.calldata[offset+i];
                }

                println!("{:?}", extension);

                self.memory.set(destination, &extension);
            }
            //CODESIZE
            0x38 => {
                self.stack.push_u256(U256::from(self.code.len()));
            }
            //CODECOPY
            0x39 => {
                let destination = self.stack.pop_u256().as_usize();
                let offset = self.stack.pop_u256().as_usize();
                let size = self.stack.pop_u256().as_usize();
                
                let copy = &self.code[offset..offset+size];
                self.memory.set(destination, copy);
            }
            //GASPRICE
            //EXTCODESIZE
            //EXTCODECOPY
            //RETURNDATASIZE
            //RETURNDATACOPY
            //EXTCODEHASH
            //BLOCKHASH
            //COINBASE
            //TIMESTAMP
            //NUMBER
            //DIFFICULTY
            //GASLIMIT
            //CHAINID
            //SELFBALANCE
            //BASEFEE
            
            /* Stack/Mem/Storage Operations */
            //POP
            0x50 => {
                self.stack.pop();
            }
            //MLOAD
            0x51 => {
                let offset = self.stack.pop_u256().as_usize();
                let mem = self.memory.load(offset, 32);
                self.stack.push(H256::from_slice(&mem[..]));
            }
            //MSTORE
            0x52 => {
                let offset = self.stack.pop_u256();
                let value = self.stack.pop();
                
                self.memory.set(offset.as_usize(), value.as_bytes());
            }
            //MSTORE8
            0x53 => {
                let offset = self.stack.pop_u256();
                let value = self.stack.pop();
                
                self.memory.set(offset.as_usize(), &value.as_bytes()[31..32]);
            }
            //SLOAD
            0x54 => {
                let key = self.stack.pop();
                match self.storage.get(&key) {
                    Some(value) => self.stack.push(*value),
                    None => self.stack.push(H256::zero()),
                }
            }
            //SSTORE
            0x55 => {
                let key = self.stack.pop();
                let value = self.stack.pop();

                self.storage.insert(key, value);
            }
            //JUMP
            0x56 => {
                let counter = self.stack.pop_u256().as_usize();

                let next_op = self.code[counter];
                assert_eq!(next_op, 0x5b);
                self.pc = counter-1;
            }
            //JUMPI
            0x57 => {
                let counter = self.stack.pop_u256().as_usize();
                let b = self.stack.pop();
                
                if b != H256::zero() {
                    let next_op = self.code[counter];
                    assert_eq!(next_op, 0x5b);
                    self.pc = counter-1;
                    
                }               
            }
            //PC
            0x58 => {
                self.stack.push_u256(U256::from(self.pc));
            }
            //MSIZE
            0x59 => {
                self.stack.push_u256(U256::from(self.memory.data().len()));
            }
            //GAS
            //JUMPDEST
            0x5b => {}
            //PUSHN
            0x60..=0x7F => {
                let push_n = (op + 32 - 0x7F).into();
                let loc = self.pc + 1;
                let to_push = &self.code[loc..loc+push_n];
                let mut val = [0u8; 32];
                for i in 0..push_n {
                    val[32+i-to_push.len()] = to_push[i];
                }

                self.stack.push(H256(val));
                self.pc += push_n;
            }
            //DUPN
            0x80..=0x8F => {
                let dup_n = (op + 15 - 0x8F).into();
                let value = self.stack.peek(dup_n);
                self.stack.push(value);
            }
            //SWAPN
            0x90..=0x9F => {
                let swap_n: usize = (op + 15 - 0x9F).into();
                let a = self.stack.peek(0);
                let b = self.stack.peek(swap_n+1);

                self.stack.set(0, b);
                self.stack.set(swap_n+1, a);
            }
            //LOGN

            //CREATE
            //CALL
            //CALLCODE
            //RETURN
            0xF3 => {
                let offset = self.stack.pop_u256().as_usize();
                let size = self.stack.pop_u256().as_usize();

                let return_data = self.memory.load(offset, size);
                self.ret_data = return_data;
            }
            //DELEGATECALL
            //CREATE2
            //STATICCALL
            //REVERT
            0xFD => {
                let offset = self.stack.pop_u256().as_usize();
                let size = self.stack.pop_u256().as_usize();

                let return_data = self.memory.load(offset, size);
                eprintln!("Reverted {:?}", return_data);
                self.ret_data = return_data;
            }
            //INVALID
            0xFE => {
                panic!("Invalid Opcode");
            }
            //SELFDESTRUCT

            _ => {
                panic!("Opcode {:x} not found!", op);
            }
        }
        self.pc += 1;
    }
}

fn main() {
    let code = hex_to_bytes("60246000600037600160e01b60005104636057361d8114602757636d4ce63c8114603157603d565b600451600055603d565b60005460645260206064f35b50").unwrap();
    let calldata = hex_to_bytes("6057361d000000000000000000000000000000000000000000000000000000000000000a").unwrap();

    let mut evm = Call::new(code, calldata);
    
    evm.run();
    println!("\nExecution Finished.\n");
    println!("Stack: {:?}", evm.stack.data());
    println!("Memory: {:?} {}", evm.memory.data(), evm.memory.data().len());
    println!("Storage: {}", evm.storage.len());
    for (key,value) in evm.storage {
        println!("{:x}: {:x}", key, value);
    }
    println!("Return: {:?}", evm.ret_data);
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i+2)
            .and_then(|sub| u8::from_str_radix(sub, 16).ok()))
        .collect()
}


fn name_from_op(op: u8) -> String {
    match op {
        0x00 => "STOP".to_string(),
        0x01 => "ADD".to_string(),
        0x02 => "MUL".to_string(),
        0x03 => "SUB".to_string(),
        0x04 => "DIV".to_string(),
        0x05 => "SDIV".to_string(),
        0x06 => "MOD".to_string(),
        0x07 => "SMOD".to_string(),
        0x08 => "ADDMOD".to_string(),
        0x09 => "MULMOD".to_string(),
        0x0A => "EXP".to_string(),
        0x0B => "SIGNEXTEND".to_string(),
        0x10 => "LT".to_string(),
        0x11 => "GT".to_string(), 
        0x12 => "SLT".to_string(), 
        0x13 => "SGT".to_string(), 
        0x14 => "EQ".to_string(), 
        0x15 => "ISZERO".to_string(), 
        0x16 => "AND".to_string(), 
        0x17 => "OR".to_string(), 
        0x18 => "XOR".to_string(), 
        0x19 => "NOT".to_string(), 
        0x1A => "BYTE".to_string(), 
        0x1B => "SHL".to_string(), 
        0x1C => "SHR".to_string(), 
        0x1D => "SAR".to_string(), 
        0x20 => "SHA3".to_string(), 
        0x30 => "ADDRESS".to_string(), 
        0x31 => "BALANCE".to_string(),
        0x32 => "ORIGIN".to_string(),
        0x33 => "CALLER".to_string(),
        0x34 => "CALLVALUE".to_string(),
        0x35 => "CALLDATALOAD".to_string(),
        0x36 => "CALLDATASIZE".to_string(),
        0x37 => "CALLDATACOPY".to_string(),
        0x38 => "CODESIZE".to_string(),
        0x39 => "CODECOPY".to_string(),
        0x3A => "GASPRICE".to_string(),
        0x3B => "EXTCODESIZE".to_string(),
        0x3C => "EXTCODECOPY".to_string(),
        0x3D => "RETURNDATASIZE".to_string(),
        0x3E => "RETURNDATACOPY".to_string(),
        0x3F => "EXTCODEHASH".to_string(),
        0x40 => "BLOCKHASH".to_string(),
        0x41 => "COINBASE".to_string(),
        0x42 => "TIMESTAMP".to_string(),
        0x43 => "NUMBER".to_string(),
        0x44 => "DIFFICULTY".to_string(),
        0x45 => "GASLIMIT".to_string(),
        0x46 => "CHAINID".to_string(),
        0x47 => "SELFBALANCE".to_string(),
        0x48 => "BASEFEE".to_string(),
        0x50 => "POP".to_string(),
        0x51 => "MLOAD".to_string(),
        0x52 => "MSTORE".to_string(),
        0x53 => "MSTORE8".to_string(),
        0x54 => "SLOAD".to_string(),
        0x55 => "SSTORE".to_string(),
        0x56 => "JUMP".to_string(),
        0x57 => "JUMPI".to_string(),
        0x58 => "PC".to_string(),
        0x59 => "MSIZE".to_string(),
        0x5A => "GAS".to_string(),
        0x5B => "JUMPDEST".to_string(),
        0x60..=0x7F => format!("PUSH{}", op+32-0x7F),
        0x80..=0x8F => format!("DUP{}", op+16-0x8F),
        0x90..=0x9F => format!("SWAP{}", op+16-0x9F),
        0xA0..=0xA4 => format!("LOG{}", op+4-0xA4),
        0xF0 => "CREATE".to_string(),
        0xF1 => "CALL".to_string(),
        0xF2 => "CALLCODE".to_string(),
        0xF3 => "RETURN".to_string(),
        0xF4 => "DELEGATECALL".to_string(),
        0xF5 => "CREATE2".to_string(),
        0xFA => "STATICCALL".to_string(),
        0xFD => "REVERT".to_string(),
        0xFE => "INVALID".to_string(),
        0xFF => "SELFDESTRUCT".to_string(),
        _ => "UNIMPLEMENTED".to_string()
    }
}