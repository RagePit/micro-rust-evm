mod stack;
mod memory;
mod utils;

use primitive_types::{H256, U256, H160};
use sha3::{Digest, Keccak256};
use core::panic;
use std::{collections::HashMap, ops::{Rem, Shr, Shl}, time::{SystemTime, UNIX_EPOCH}};

use stack::Stack;
use memory::Memory;

use utils::{I256, set_sign};

struct Call {
    storage: HashMap<H256, H256>,
    code: Vec<u8>,
    calldata: Vec<u8>,
    pc: usize,
    stack: Stack,
    memory: Memory,
    ret_data: Vec<u8>
}

#[derive(PartialEq, Eq)]
pub enum EvalCode {
    Continue,
    Exit(ExitReason),
    /// Unknown Opcode
    External(u8)
}
#[derive(PartialEq, Eq)]
pub enum ExitReason {
    /// Happy Path
    Succeeded(ExitSucceed),
    /// EVM Execution Error
    Error,
    /// Explicit Revert
    Revert,
}
#[derive(PartialEq, Eq)]
pub enum ExitSucceed {
    /// Explicit STOP
    Stopped,
    /// Explicit RETURN
    Returned
}

impl Call {
    pub fn new(code: Vec<u8>, calldata: Vec<u8>, storage: HashMap<H256, H256>) -> Self {
        Self {
            storage,
            pc: 0,
            ret_data: Vec::new(),
            stack: Stack::new(),
            memory: Memory::new(),
            code,
            calldata
        }
    }

    pub fn empty() -> Self {
        Self {
            storage: HashMap::new(),
            pc: 0,
            ret_data: Vec::new(),
            stack: Stack::new(),
            memory: Memory::new(),
            code: Vec::new(),
            calldata: Vec::new()
        }
    }

    pub fn run(&mut self) {
        while self.pc < self.code.len() {
            self.eval(*self.code.get(self.pc).unwrap());
        }
        self.pc = 0;
    }

    pub fn step(&mut self) -> Result<(), EvalCode> {
        match self.code.get(self.pc) {
            Some(opcode) => match self.eval(*opcode) {
                EvalCode::Continue => Ok(()),
                EvalCode::Exit(e) => Err(EvalCode::Exit(e)),
                EvalCode::External(opcode) => Err(EvalCode::External(opcode)),
            },
            None => {
                Err(EvalCode::Exit(ExitReason::Succeeded(ExitSucceed::Stopped)))
            }
        }
    } 

    fn eval(&mut self, op: u8) -> EvalCode {
        // println!("Stack: {:?}", self.stack.data());
        // println!("Memory: {:?} {}", self.memory.data(), self.memory.data().len());
        // println!("Executing: {:02x} {}",op, name_from_op(op));
        match op {
            //STOP
            0x00 => {
                self.pc = self.code.len();
                return EvalCode::Exit(ExitReason::Succeeded(ExitSucceed::Stopped));
            }
            /* Arithmetic */
            //ADD
            0x01 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                self.stack.push_u256(a.overflowing_add(b).0);
            }
            //MUL
            0x02 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                self.stack.push_u256(a.overflowing_mul(b).0);
            }
            //SUB
            0x03 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                self.stack.push_u256(a.overflowing_sub(b).0);
            }
            //DIV
            0x04 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                match b == U256::zero() {
                    true => self.stack.push(H256::zero()),
                    false => self.stack.push_u256(a/b)
                }
            }
            //SDIV
            0x05 => {
                let a = I256::from(self.stack.pop_u256());
                let b = I256::from(self.stack.pop_u256());

                let min = I256::min();
                let v = if b.val.is_zero() {
                    U256::zero()
                } else if a.val == min.val && b.val == !U256::zero(){
                    min.val
                } else {
                    let c = a.val/b.val;
                    set_sign(c, a.sign ^ b.sign)  
                };

                self.stack.push_u256(v);
            }
            //MOD
            0x06 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                match b == U256::zero() {
                    true => self.stack.push(H256::zero()),
                    false => self.stack.push_u256(a.rem(b))
                }
            }
            //SMOD
            0x07 => {
                let a = I256::from(self.stack.pop_u256());
                let b = I256::from(self.stack.pop_u256());

                let v = if !b.val.is_zero() {
                    let c = a.val % b.val;
                    set_sign(c, a.sign)
                } else {
                    U256::zero()
                };
                self.stack.push_u256(v);
            }
            //ADDMOD
            0x08 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                let n = self.stack.pop_u256();
                match n == U256::zero() {
                    true => self.stack.push(H256::zero()),
                    false => self.stack.push_u256(a.overflowing_add(b).0.rem(n))
                }
                
            }
            //MULMOD
            0x09 => {
                let a = self.stack.pop_u256();
                let b = self.stack.pop_u256();
                let n = self.stack.pop_u256();
                match n == U256::zero() {
                    true => self.stack.push(H256::zero()),
                    false => self.stack.push_u256(a.overflowing_mul(b).0.rem(n))
                }
            }
            //EXP
            0x0a => {
                let a = self.stack.pop_u256();
                let exp = self.stack.pop_u256();
                //TODO: Impl overflowing exp
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
            0x12 => {
                let a: I256 = self.stack.pop_u256().into();
                let b: I256 = self.stack.pop_u256().into();

                let is_positive_lt = a.val < b.val && !(a.sign | b.sign);
                let is_negative_lt = a.val > b.val && (a.sign & b.sign);
                let has_different_signs = a.sign && !b.sign;

                match is_positive_lt | is_negative_lt | has_different_signs {
                    true => self.stack.push_u256(U256::one()),
                    false => self.stack.push(H256::zero())
                }
            }
            //SGT
            //Credit: https://github.com/openethereum/parity-ethereum/blob/55c90d4016505317034e3e98f699af07f5404b63/ethcore/evm/src/interpreter/mod.rs#L1003
            0x13 => {
                let a: I256 = self.stack.pop_u256().into();
                let b: I256 = self.stack.pop_u256().into();

                let is_positive_gt = a.val > b.val && !(a.sign | b.sign);
                let is_negative_gt = a.val < b.val && (a.sign & b.sign);
                let has_different_signs = !a.sign && b.sign;

                match is_positive_gt | is_negative_gt | has_different_signs {
                    true => self.stack.push_u256(U256::one()),
                    false => self.stack.push(H256::zero())
                }
            }
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
                let offset = self.stack.pop_u256();
                let val = self.stack.pop_u256();

                let byte = match offset < U256::from(32) {
                    true => (val >> (8 * (31 - offset.as_usize()))) & U256::from(0xff),
                    false => U256::zero()
                };

                self.stack.push_u256(byte);
            }
            //SHL
            0x1B => {
                let shift = self.stack.pop_u256();
                let val = self.stack.pop_u256();
                match shift > U256::from(255) {
                    true => self.stack.push(H256::zero()),
                    false => self.stack.push_u256(val.shl(shift))
                }
            }
            //SHR
            0x1C => {
                let shift = self.stack.pop_u256();
                let val = self.stack.pop_u256();
                match shift > U256::from(255) {
                    true => self.stack.push(H256::zero()),
                    false => self.stack.push_u256(val.shr(shift))
                }
            }
            //SAR
            //https://github.com/openethereum/parity-ethereum/blob/55c90d4016505317034e3e98f699af07f5404b63/ethcore/evm/src/interpreter/mod.rs#L1118-L1142
            0x1D => {
                const HIBIT: U256 = U256([0,0,0,0x8000000000000000]);

                let shift = self.stack.pop_u256();
                let val = self.stack.pop_u256();
                let sign = val & HIBIT != U256::zero();

                let result = if val == U256::zero() || shift >= U256::from(256) {
                    if sign { U256::max_value() } else { U256::zero() }
                } else {
                    let shift = shift.as_usize();
                    if sign { val >> shift | (U256::max_value() << (256 - shift)) } else { val >> shift }
                };
                self.stack.push_u256(result);
            }

            //SHA3
            0x20 => {
                let offset = self.stack.pop_u256();
                let size = self.stack.pop_u256();

                let data = self.memory.load(offset.as_usize(), size.as_usize());
                let hash = Keccak256::digest(data.as_slice());
                self.stack.push(H256::from_slice(hash.as_slice()));
            }
            //CALLDATALOAD
            0x35 => {
                let offset = self.stack.pop_u256().as_usize();
                let mut load = [0u8; 32];
                //If calldata length is less than offset, return bytes32(0)
                if offset <= self.calldata.len() {
                    let to = if self.calldata.len() < offset+32 {self.calldata.len()-offset} else {32};
                    let data = &self.calldata[offset..offset+to];

                    load[..to].copy_from_slice(&data[..to]);
                }                

                self.stack.push(H256::from(load));
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

                let mut extension = vec![0; size];
                
                extension[..self.calldata.len()]
                    .copy_from_slice(&self.calldata[offset..(self.calldata.len() + offset)]);

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
                
                let mut extension = vec![0; size];
                
                extension[..self.code.len()]
                    .copy_from_slice(&self.code[offset..(self.code.len() + offset)]);

                self.memory.set(destination, &extension);
            }
            
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
            
            //RETURN
            0xF3 => {
                let offset = self.stack.pop_u256().as_usize();
                let size = self.stack.pop_u256().as_usize();

                let return_data = self.memory.load(offset, size);
                self.ret_data = return_data;
            }
            
            //REVERT
            0xFD => {
                let offset = self.stack.pop_u256().as_usize();
                let size = self.stack.pop_u256().as_usize();

                let return_data = self.memory.load(offset, size);
                self.ret_data = return_data;
                return EvalCode::Exit(ExitReason::Revert);
            }
            //INVALID
            0xFE => {
                return EvalCode::Exit(ExitReason::Error);
            }

            _ => {
                return EvalCode::External(op);
            }
        }

        self.pc += 1;
        EvalCode::Continue
    }
}

#[derive(Clone)]
struct Account {
    /// Bytes
    code: Vec<u8>,
    /// Key => Value
    storage: HashMap<H256, H256>,
    /// Ether Value
    balance: U256,
    /// Nonce
    nonce: U256
}

impl Account {
    pub fn new(code: Vec<u8>) -> Self {
        Self {
            code,
            storage: HashMap::new(),
            balance: U256::zero(),
            nonce: U256::zero()
        }
    }
}

//TODO: Change addresses to H160 potentially
struct Evm {
    pub call: Call,
    /// Address => Account
    pub state: HashMap<H160, Account>,
    /// Return Bytes from last Call
    pub ret_data: Vec<u8>,
    //Context
    pub address: H160,
    pub caller: H160,
    pub value: U256
}

impl Evm {
    pub fn new() -> Self {
        Self {
            call: Call::empty(),
            state: HashMap::new(),
            ret_data: Vec::new(),
            address: H160::zero(),
            caller: H160::zero(),
            value: U256::zero()
        }
    }

    pub fn execute_call(&mut self, address: H160, calldata: Vec<u8>) -> ExitReason {
        let account = &self.get_account(address);

        self.call = Call::new(account.code.clone(), calldata, account.storage.clone());

        let return_code = self.run(account);
        
        if return_code != ExitReason::Error || return_code != ExitReason::Revert {
            self.state.get_mut(&address).unwrap().storage = self.call.storage.clone();
        }
        self.ret_data = self.call.ret_data.clone();
        ExitReason::Error
    }
    
    fn run(&mut self, account: &Account) -> ExitReason {
        let mut return_code = EvalCode::Continue;
        while return_code == EvalCode::Continue {
            return_code = match self.call.step() {
                Err(EvalCode::Exit(e)) => return e,
                Err(EvalCode::External(opcode)) => {
                    match self.eval(opcode, &account) {
                        EvalCode::Continue => EvalCode::Continue,
                        _ => todo!()
                    }
                },
                Ok(()) => EvalCode::Continue,
                _ => todo!()
            };
        }
        ExitReason::Error
    }

    fn get_account(&self, address: H160) -> Account {
        match self.state.get(&address).cloned() {
            Some(a) => a,
            None => panic!("Account {} not found", address)
        }
    }

    pub fn deploy_contract(&mut self, code: Vec<u8>) -> H160 {
        let address = H160::from_slice(&Keccak256::digest(code.as_slice())[0..20]);
        let account = Account::new(code);
        self.state.insert(address, account);
        address
    }

    fn eval(&mut self, opcode: u8, account: &Account) -> EvalCode {
        match opcode {
            //ADDRESS
            0x30 => {
                self.call.stack.push(self.address.into());
            }
            //BALANCE
            0x31 => {
                self.call.stack.push_u256(account.balance);
            }
            //ORIGIN
            //CALLER
            0x33 => {
                self.call.stack.push(self.caller.into());
            }
            //CALLVALUE
            0x34 => {
                self.call.stack.push_u256(self.value);
            }
            //GASPRICE
            //EXTCODESIZE
            0x3B => {
                let addr = H160::from(self.call.stack.pop());
                
                match self.state.get(&addr) {
                    Some(_account) => self.call.stack.push_u256(U256::from(_account.code.len())),
                    None => self.call.stack.push(H256::zero()),
                }
            }
            //EXTCODECOPY
            0x3C => {
                let addr = H160::from(self.call.stack.pop());
                let mem_destination = self.call.stack.pop_u256().as_usize();
                let code_offset = self.call.stack.pop_u256().as_usize();
                let size = self.call.stack.pop_u256().as_usize();
                
                match self.state.get(&addr) {
                    Some(ext_account) => {
                        let mut extension = vec![0; size];
                
                        extension[..ext_account.code.len()]
                            .copy_from_slice(&ext_account.code[code_offset..(ext_account.code.len() + code_offset)]);

                        self.call.memory.set(mem_destination, &extension);
                    },
                    None => self.call.stack.push(H256::zero()),
                }
            }
            //RETURNDATASIZE
            0x3D => {
                self.call.stack.push_u256(U256::from(self.ret_data.len()));
            }
            //RETURNDATACOPY
            0x3E => {
                let mem_destination = self.call.stack.pop_u256().as_usize();
                let offset = self.call.stack.pop_u256().as_usize();
                let size = self.call.stack.pop_u256().as_usize();

                let mut extension = vec![0; size];
                
                extension[..self.ret_data.len()]
                    .copy_from_slice(&self.ret_data[offset..(self.ret_data.len() + offset)]);

                self.call.memory.set(mem_destination, &extension);
            }
            //EXTCODEHASH
            0x3F => {
                let addr = H160::from(self.call.stack.pop());
                
                match self.state.get(&addr) {
                    Some(ext_account) => {
                        let hash = Keccak256::digest(ext_account.code.as_slice());
                        self.call.stack.push(H256::from_slice(hash.as_slice()));
                    },
                    None => self.call.stack.push(H256::zero()),
                }
            }
            //BLOCKHASH
            //COINBASE
            //TIMESTAMP
            0x42 => {
                // let now = U256::from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
                // self.call.stack.push_u256(now);
                self.call.stack.push(H256::zero());

            }
            //NUMBER
            0x43 => {
                self.call.stack.push(H256::zero());
            }
            //DIFFICULTY
            //GASLIMIT
            //CHAINID
            //SELFBALANCE
            0x47 => {
                self.call.stack.push_u256(account.balance);
            }
            //BASEFEE

            //GAS

            //LOGN
            //CREATE
            //CALL
            //CALLCODE
            //DELEGATECALL
            //CREATE2
            //STATICCALL
            //SELFDESTRUCT
            _ => todo!()
        }
        self.call.pc += 1;
        EvalCode::Continue
    }
}

fn main() {
    let mut evm = Evm::new();

    let code = str_to_bytes("608060405234801561001057600080fd5b506004361061002b5760003560e01c8063764e971f14610030575b600080fd5b61004a60048036038101906100459190610117565b61004c565b005b60006040518060400160405280848152602001838152509080600181540180825580915050600190039060005260206000209060020201600090919091909150600082015181600001556020820151816001015550505050565b600080fd5b6000819050919050565b6100be816100ab565b81146100c957600080fd5b50565b6000813590506100db816100b5565b92915050565b6000819050919050565b6100f4816100e1565b81146100ff57600080fd5b50565b600081359050610111816100eb565b92915050565b6000806040838503121561012e5761012d6100a6565b5b600061013c858286016100cc565b925050602061014d85828601610102565b915050925092905056fea2646970667358221220c47ebde94f2dc04da638105ce5e0cb558c7d2ac46a4bd34add5b144818f4369e64736f6c634300080d0033");    
    let address = evm.deploy_contract(code);
    
    let calldata = str_to_bytes("0x764e971f000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000064");
    evm.execute_call(address, calldata);
    
    let call = &evm.call;
    println!("\nExecution Finished.\n");
    println!("Stack: {:?}", call.stack.data());
    println!("Memory: {:02x?}", call.memory.data());
    println!("Storage: {}", call.storage.len());
    for (key,value) in &call.storage {
        println!("{:x}: {:x}", key, value);
    }
    println!("Return: {:?}", call.ret_data);

    let calldata = str_to_bytes("0x764e971f000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000050");
    evm.execute_call(address, calldata);
    let call = &evm.call;

    println!("Stack: {:?}", call.stack.data());
    println!("Memory: {:02x?}", call.memory.data());
    println!("Storage: {}", call.storage.len());
    for (key,value) in &call.storage {
        println!("{:x}: {:x}", key, value);
    }
    println!("Return: {:?}", call.ret_data);
}

fn str_to_bytes(mut s: &str) -> Vec<u8> {
    s = s.trim_start_matches("0x");
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i+2)
            .and_then(|sub| u8::from_str_radix(sub, 16).ok()))
        .collect();

    match bytes {
        Some(b) => b,
        None => panic!("Failed to parse hex {}", s)
    }
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

//Implementing tests from https://github.com/multi-geth/tests/blob/develop/VMTests
#[cfg(test)]
mod tests {

    use super::*;

    fn run_call(code: &str, calldata: &str) -> Call {
        let mut call = Call::new(str_to_bytes(code), str_to_bytes(calldata), HashMap::new());
        call.run();
        call
    }

    fn print_values(evm: &Call) {
        println!("Stack: {:?}", evm.stack.data());
        println!("Memory: {:?} {}", evm.memory.data(), evm.memory.data().len());
        println!("Storage: {}", evm.storage.len());
        for (key,value) in &evm.storage {
            println!("{:x}: {:x}", key, value);
        }
        println!("Return: {:?}", evm.ret_data);
    }

    fn vec_to_h256(vec: Vec<u8>) -> H256 {
        let mut bytes32 = [0u8;32];
        bytes32.clone_from_slice(&vec);
        H256::from(bytes32)
    }

    #[test]
    fn test_add0() {
        let evm = run_call("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01600055", "0x");

        assert!(evm.stack.data().is_empty());
        assert!(evm.memory.data().is_empty());
        assert_eq!(evm.storage.len(), 1);

        assert_eq!(evm.storage.get(&H256::from_low_u64_be(0)).unwrap(), &vec_to_h256(str_to_bytes("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe")));
    }

    #[test]
    fn test_add1() {
        let evm = run_call("0x60047fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01600055", "0x");

        assert!(evm.stack.data().is_empty());
        assert!(evm.memory.data().is_empty());
        assert_eq!(evm.storage.len(), 1);

        assert_eq!(evm.storage.get(&H256::from_low_u64_be(0)).unwrap(), &H256::from_low_u64_be(3));
    }
}