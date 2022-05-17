mod stack;
mod memory;
mod utils;
mod opcode;

use primitive_types::{H256, U256, H160};
use sha3::{Digest, Keccak256, digest::generic_array::typenum::bit};
use core::{panic};
use std::{collections::HashMap, ops::{Rem, Shr, Shl}, time::{SystemTime, UNIX_EPOCH}, task::Context};
use rlp::RlpStream;

use opcode::{arithmetic, bitwise, misc};
use stack::Stack;
use memory::Memory;
use utils::{I256, set_sign};

pub struct CallContext {
    calldata: Vec<u8>,
    address: H160,
    caller: H160,
    value: U256
}

impl CallContext {
    pub fn new(calldata: Vec<u8>, address: H160, caller: H160, value: U256) -> Self {
        Self { calldata, address, caller, value }
    }

    pub fn empty() -> Self {
        Self { calldata: Vec::new(), address: H160::zero(), caller: H160::zero(), value: U256::zero() }
    }
}

pub struct Call {
    temp_state: HashMap<H160, Account>,
    stack: Stack,
    memory: Memory,

    code: Vec<u8>,
    pc: usize,
    ret_data: Vec<u8>,
    //Context
    context: CallContext
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
    pub fn new(code: Vec<u8>, context: CallContext, starting_state: HashMap<H160, Account>) -> Self {
        Self {
            temp_state: starting_state,
            pc: 0,
            ret_data: Vec::new(),
            stack: Stack::new(),
            memory: Memory::new(),
            code,
            context
        }
    }

    pub fn empty() -> Self {
        Self {
            temp_state: HashMap::new(),
            pc: 0,
            ret_data: Vec::new(),
            stack: Stack::new(),
            memory: Memory::new(),
            code: Vec::new(),
            context: CallContext::empty()
        }
    }

    pub fn run(&mut self) {
        while self.pc < self.code.len() {
            let res = self.eval(*self.code.get(self.pc).unwrap());
            match res {
                EvalCode::External(_) => panic!("External Call Not Supposed To Happen Here"),
                _ => {}
            }
        }
        self.pc = 0;
    }

    pub fn step(&mut self) -> Result<(), EvalCode> {
        match self.code.get(self.pc).cloned() {
            Some(opcode) => match self.eval(opcode) {
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
        let res = match op {
            //STOP
            0x00 => {
                self.pc = self.code.len();
                return EvalCode::Exit(ExitReason::Succeeded(ExitSucceed::Stopped));
            }
            /* Arithmetic */
            
            //ADD
            0x01 => arithmetic::eval_add(self),
            //MUL
            0x02 => arithmetic::eval_mul(self),
            //SUB
            0x03 => arithmetic::eval_sub(self),
            //DIV
            0x04 => arithmetic::eval_div(self),
            //SDIV
            0x05 => arithmetic::eval_sdiv(self),
            //MOD
            0x06 => arithmetic::eval_mod(self),
            //SMOD
            0x07 => arithmetic::eval_smod(self),
            //ADDMOD
            0x08 => arithmetic::eval_addmod(self),
            //MULMOD
            0x09 => arithmetic::eval_mulmod(self),
            //EXP
            0x0a => arithmetic::eval_exp(self),
            /* Bitwise */

            //SIGNEXTEND
            //LT
            0x10 => bitwise::eval_lt(self),
            //GT
            0x11 => bitwise::eval_gt(self),
            //SLT
            0x12 => bitwise::eval_slt(self),
            //SGT
            0x13 => bitwise::eval_sgt(self),
            //EQ
            0x14 => bitwise::eval_eq(self),
            //ISZERO
            0x15 => bitwise::eval_iszero(self),
            //AND
            0x16 => bitwise::eval_and(self),
            //OR
            0x17 => bitwise::eval_or(self),
            //XOR
            0x18 => bitwise::eval_xor(self),
            //NOT
            0x19 => bitwise::eval_not(self),
            //BYTE
            0x1A => bitwise::eval_byte(self),
            //SHL
            0x1B => bitwise::eval_shl(self),
            //SHR
            0x1C => bitwise::eval_shr(self),
            //SAR
            0x1D => bitwise::eval_sar(self),
            /* Misc */

            //SHA3
            0x20 => misc::eval_sha3(self),
            //CALLDATALOAD
            0x35 => misc::eval_calldataload(self),
            //CALLDATASIZE
            0x36 => misc::eval_calldatasize(self),
            //CALLDATACOPY
            0x37 => misc::eval_calldatacopy(self),
            //CODESIZE
            0x38 => misc::eval_codesize(self),
            //CODECOPY
            0x39 => misc::eval_codecopy(self),
            
            /* Stack/Mem/Storage Operations */
            //POP
            0x50 => misc::eval_pop(self),
            //MLOAD
            0x51 => misc::eval_mload(self),
            //MSTORE
            0x52 => misc::eval_mstore(self),
            //MSTORE8
            0x53 => misc::eval_mstore8(self),
            //JUMP
            0x56 => misc::eval_jump(self),
            //JUMPI
            0x57 => misc::eval_jumpi(self),
            //PC
            0x58 => misc::eval_pc(self),
            //MSIZE
            0x59 => misc::eval_msize(self),
            
            //JUMPDEST
            0x5b => EvalCode::Continue,
            //PUSHN
            0x60..=0x7F => misc::eval_push(self, op),
            //DUPN
            0x80..=0x8F => misc::eval_dup(self, op),
            //SWAPN
            0x90..=0x9F => misc::eval_swap(self, op),
            
            //RETURN
            0xF3 => misc::eval_return(self),
            
            //REVERT
            0xFD => return misc::eval_revert(self),
            //INVALID
            0xFE => return EvalCode::Exit(ExitReason::Error),

            _ => return EvalCode::External(op)
        };

        self.pc += 1;
        res
    }
}

#[derive(Clone)]
pub struct Account {
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

struct Evm {
    /// Address => Account
    pub state: HashMap<H160, Account>,
    /// Return Bytes from last Call
    pub ret_data: Vec<u8>,
}

impl Evm {
    pub fn new() -> Self {
        Self {
            state: HashMap::new(),
            ret_data: Vec::new()
        }
    }

    ///Top level call entrance
    fn execute_call(&mut self, address: H160, calldata: Vec<u8>) -> ExitReason {
        let account = self.state.get(&address).unwrap();

        let mut call = Call::new(account.code.clone(), CallContext::new(calldata, address, H160::zero(), U256::zero()), self.state.clone());
        // println!("\nEntering New Context\n");
        let return_code = self.execute_defined_call(&mut Call::empty(), &mut call);

        if return_code != ExitReason::Error && return_code != ExitReason::Revert {
            //Successful Call
            //Write all changes to state
            for (addr, acc) in &call.temp_state {
                match self.state.get_mut(&addr) {
                    //Existing account
                    Some(state_acc) => {
                        state_acc.balance = acc.balance;
                        state_acc.nonce = acc.nonce;
                        for (key, val) in &acc.storage {
                            state_acc.storage.insert(*key, *val);
                        }
                    },
                    //Newly created account
                    None => {
                        let mut state_acc = Account::new(acc.code.clone());
                        state_acc.balance = acc.balance;
                        state_acc.nonce = acc.nonce;
                        for (key, val) in &acc.storage {
                            state_acc.storage.insert(*key, *val);
                        }
                        self.state.insert(*addr, state_acc);
                    },
                }
                
            }
        }
        
        // println!("\nExecution Finished.\n");
        // print_values(&call);
        return_code
    }

    ///Used for internal calls
    fn execute_defined_call(&mut self, outer_call: &mut Call, inner_call: &mut Call) -> ExitReason {
        let return_code = self.run(inner_call);
        
        if return_code != ExitReason::Error && return_code != ExitReason::Revert {
            //Successful Call
            outer_call.temp_state = inner_call.temp_state.clone();
        }
        self.ret_data = inner_call.ret_data.clone();
        return_code
    }
    
    fn run(&mut self, call: &mut Call) -> ExitReason {
        let mut return_code = EvalCode::Continue;
        while return_code == EvalCode::Continue {
            return_code = match call.step() {
                Err(EvalCode::Exit(e)) => return e,
                Err(EvalCode::External(opcode)) => {
                    match self.eval(opcode, call) {
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

    fn get_account_in_call(&self, call: &Call, address: H160) -> Option<Account> {
        match call.temp_state.get(&address) {
            //Account is in current call context
            Some(acc) => Some(acc.clone()),
            //Account may be in historical state
            None => {
                match self.state.get(&address) {
                    //Found account in historical state
                    Some(acc) => Some(acc.clone()),
                    //Account does not exist
                    None => None,
                }
            },
        }
    }

    fn deploy_contract(&mut self, code: Vec<u8>, from: H160, nonce: U256) -> H160 {
        let address = self.create_address(from, nonce);
        let account = Account::new(code);
        self.state.insert(address, account);
        address
    }

    fn create_address(&self, from: H160, nonce: U256) -> H160 {
        let mut stream = RlpStream::new_list(2);
        stream.append(&from);
        stream.append(&nonce);
        
        H160::from_slice(&Keccak256::digest(&stream.out()).as_slice()[12..32])
    }

    fn create2_address(&self, caller: H160, code: &Vec<u8>, salt: H256) -> H160 {
        let code_hash = H256::from_slice(Keccak256::digest(code).as_slice());
        let mut hasher = Keccak256::new();
        hasher.update(&[0xff]);
        hasher.update(&caller[..]);
        hasher.update(&salt[..]);
        hasher.update(&code_hash[..]);
        H256::from_slice(hasher.finalize().as_slice()).into()
    }

    fn eval(&mut self, opcode: u8, call: &mut Call) -> EvalCode {
        match opcode {
            //ADDRESS
            0x30 => {
                call.stack.push(call.context.address.into());
            }
            //BALANCE
            0x31 => {
                let address = call.stack.pop().into();
                let balance = match self.get_account_in_call(call, address) {
                    Some(account) => account.balance,
                    None => U256::zero(),
                };
                call.stack.push_u256(balance);
            }
            //ORIGIN
            //CALLER
            0x33 => {
                call.stack.push(call.context.caller.into());
            }
            //CALLVALUE
            0x34 => {
                call.stack.push_u256(call.context.value);
            }
            //GASPRICE
            //EXTCODESIZE
            0x3B => {
                let addr = H160::from(call.stack.pop());
                
                match self.state.get(&addr) {
                    Some(_account) => call.stack.push_u256(U256::from(_account.code.len())),
                    None => call.stack.push(H256::zero()),
                }
            }
            //EXTCODECOPY
            0x3C => {
                let addr = H160::from(call.stack.pop());
                let mem_destination = call.stack.pop_u256().as_usize();
                let code_offset = call.stack.pop_u256().as_usize();
                let size = call.stack.pop_u256().as_usize();
                
                match self.state.get(&addr) {
                    Some(ext_account) => {
                        let mut extension = vec![0; size];
                
                        extension[..ext_account.code.len()]
                            .copy_from_slice(&ext_account.code[code_offset..(ext_account.code.len() + code_offset)]);

                        call.memory.set(mem_destination, &extension);
                    },
                    None => call.stack.push(H256::zero()),
                }
            }
            //RETURNDATASIZE
            0x3D => {
                call.stack.push_u256(U256::from(self.ret_data.len()));
            }
            //RETURNDATACOPY
            0x3E => {
                let mem_destination = call.stack.pop_u256().as_usize();
                let offset = call.stack.pop_u256().as_usize();
                let size = call.stack.pop_u256().as_usize();

                let mut extension = vec![0; size];
                
                extension[..self.ret_data.len()]
                    .copy_from_slice(&self.ret_data[offset..(self.ret_data.len() + offset)]);

                call.memory.set(mem_destination, &extension);
            }
            //EXTCODEHASH
            0x3F => {
                let addr = H160::from(call.stack.pop());
                
                match self.state.get(&addr) {
                    Some(ext_account) => {
                        let hash = Keccak256::digest(ext_account.code.as_slice());
                        call.stack.push(H256::from_slice(hash.as_slice()));
                    },
                    None => call.stack.push(H256::zero()),
                }
            }
            //BLOCKHASH
            //COINBASE
            //TIMESTAMP
            0x42 => {
                let now = U256::from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
                call.stack.push_u256(now);
                // call.stack.push(H256::zero());

            }
            //NUMBER
            0x43 => {
                //TODO
                call.stack.push(H256::zero());
            }
            //DIFFICULTY
            //GASLIMIT
            //CHAINID
            //SELFBALANCE
            0x47 => {
                let balance = match self.get_account_in_call(call, call.context.address) {
                    Some(account) => account.balance,
                    None => panic!("This shouldn't happen!"),
                };
                call.stack.push_u256(balance);
            }
            //BASEFEE
            //SLOAD
            0x54 => {
                let key = call.stack.pop();

                //Check current context state for the key
                match call.temp_state.get(&call.context.address).unwrap().storage.get(&key) {
                    //Value is in current context temporary storage
                    Some(value) => call.stack.push(*value),
                    //Value might be in historical state
                    None => {
                        match self.state.get(&call.context.address).unwrap().storage.get(&key) {
                            Some(value) => call.stack.push(*value),
                            //Is not in context state or historical state
                            None => call.stack.push(H256::zero())
                        }
                    }
                }
            }
            //SSTORE
            0x55 => {
                let key = call.stack.pop();
                let value = call.stack.pop();

                match call.temp_state.get_mut(&call.context.address) {
                    //Account is in context state
                    Some(acc) => {
                        acc.storage.insert(key, value);
                    },
                    //It is not in the current context, so we copy the account data from historical
                    None => {
                        //Should most definitely be in historical state
                        let mut state_acc = self.state.get(&call.context.address).unwrap().clone();
                        state_acc.storage.insert(key, value);
                        call.temp_state.insert(call.context.address, state_acc);
                    }
                };
            }
            //GAS

            //LOGN
            //CREATE
            0xF0 => {
                let value = call.stack.pop_u256();
                let offset = call.stack.pop_u256().as_usize();
                let size = call.stack.pop_u256().as_usize();
                
                let create_code = call.memory.load(offset, size);
                let address = self.create_address(call.context.address, self.state.get(&call.context.address).unwrap().nonce);
                call.temp_state.insert(address, Account::new(create_code.clone()));

                let mut create_call = Call::new(
                    create_code, 
                    CallContext::new(Vec::new(), address, call.context.caller, value), 
                    call.temp_state.clone());

                let res = self.execute_defined_call(call, &mut create_call);
                match res {
                    //Edit code in account to return data of the call
                    ExitReason::Succeeded(_) => {
                        call.stack.push(address.into());
                        call.temp_state.get_mut(&address).unwrap().code = self.ret_data.clone();
                    },
                    //Create failed so remove the account's state
                    _ => {
                        call.stack.push(H256::zero());
                        call.temp_state.remove(&address);
                    }
                };

                let caller_account = call.temp_state.get_mut(&call.context.address).unwrap();
                caller_account.nonce += U256::one();
                
            }
            //CALL
            0xF1 => {
                let gas = call.stack.pop();
                let address = H160::from(call.stack.pop());
                let value = call.stack.pop_u256();
                let args_offset = call.stack.pop_u256().as_usize();
                let args_size = call.stack.pop_u256().as_usize();
                let ret_offset = call.stack.pop_u256().as_usize();
                let ret_size = call.stack.pop_u256().as_usize();

                let calldata = call.memory.load(args_offset, args_size);
                let code = match self.get_account_in_call(call, address) {
                    //address was deployed in current context
                    Some(acc) => acc.code,
                    //may be in historical state
                    None => Vec::new()
                };
                let mut inner_call = Call::new(
                    code,
                    CallContext::new(calldata, address, call.context.address, value),
                    call.temp_state.clone()
                );
                let success = self.execute_defined_call(call, &mut inner_call);
                match success {
                    ExitReason::Succeeded(_) => call.stack.push_u256(U256::one()),
                    _ => call.stack.push_u256(U256::zero())
                }
                
                call.memory.set(ret_offset, &self.ret_data[..ret_size]);
            }
            //CALLCODE
            //DELEGATECALL
            0xF4 => {
                let gas = call.stack.pop();
                let address = H160::from(call.stack.pop());
                let args_offset = call.stack.pop_u256().as_usize();
                let args_size = call.stack.pop_u256().as_usize();
                let ret_offset = call.stack.pop_u256().as_usize();
                let ret_size = call.stack.pop_u256().as_usize();

                let calldata = call.memory.load(args_offset, args_size);
                let create_code = match self.get_account_in_call(call, address) {
                    //address was deployed in current context
                    Some(acc) => acc.code,
                    //may be in historical state
                    None => Vec::new()
                };
                let mut delegate_call = Call::new(
                    create_code,
                    CallContext::new(calldata, call.context.address, call.context.caller, U256::zero()),
                    call.temp_state.clone());
                
                let success = self.execute_defined_call(call,&mut delegate_call);
                match success {
                    ExitReason::Succeeded(_) => call.stack.push_u256(U256::one()),
                    _ => call.stack.push_u256(U256::zero())
                }
                
                call.memory.set(ret_offset, &self.ret_data[..ret_size])
            }
            //CREATE2
            0xF5 => {
                let value = call.stack.pop_u256();
                let offset = call.stack.pop_u256().as_usize();
                let size = call.stack.pop_u256().as_usize();
                let salt = call.stack.pop();

                let code = call.memory.load(offset, size);
                let address = self.create2_address(call.context.caller, &code, salt);
                
                let mut inner_call = Call::new(
                    code,
                    CallContext::new(Vec::new(), address, call.context.address, value),
                    call.temp_state.clone()
                );
                let success = self.execute_defined_call(call, &mut inner_call);
                match success {
                    //Edit code in account to return data of the call
                    ExitReason::Succeeded(_) => {
                        call.stack.push(address.into());
                        call.temp_state.get_mut(&address).unwrap().code = self.ret_data.clone();
                    },
                    //Create failed so remove the account's state
                    _ => {
                        call.stack.push(H256::zero());
                        call.temp_state.remove(&address);
                    }
                };
            }
            //STATICCALL
            //SELFDESTRUCT
            _ => todo!()
        }
        call.pc += 1;
        EvalCode::Continue
    }
}

fn main() {
    let s = SystemTime::now();
    let mut evm = Evm::new();

    let code = str_to_bytes("7067600035600757fe5b60005260086018f36000526011600f6000f0600060006000600060008561fffff1600060006020600060008661fffff1");    

    let address = evm.deploy_contract(code, H160::from_slice(&str_to_bytes("147Ea4Cb33e215D24f6e81820B6653D978adc346")[0..20]), U256::from(0));
    let res = evm.execute_call(address, str_to_bytes(""));
    println!("\n\nFinished Execution in: {:?}", s.elapsed().unwrap());

    if res == ExitReason::Error || res == ExitReason::Revert {
        panic!("~~~~~~~~~~~~~~ Call Failed ~~~~~~~~~~~~~~");
    }
    println!("Accounts:");
    for (key, value) in &evm.state {
        println!("{:?} {:02x?}", key, value.code);
    }
    
    // let code = str_to_bytes("608060405234801561001057600080fd5b506004361061002b5760003560e01c8063764e971f14610030575b600080fd5b61004a60048036038101906100459190610117565b61004c565b005b60006040518060400160405280848152602001838152509080600181540180825580915050600190039060005260206000209060020201600090919091909150600082015181600001556020820151816001015550505050565b600080fd5b6000819050919050565b6100be816100ab565b81146100c957600080fd5b50565b6000813590506100db816100b5565b92915050565b6000819050919050565b6100f4816100e1565b81146100ff57600080fd5b50565b600081359050610111816100eb565b92915050565b6000806040838503121561012e5761012d6100a6565b5b600061013c858286016100cc565b925050602061014d85828601610102565b915050925092905056fea2646970667358221220c47ebde94f2dc04da638105ce5e0cb558c7d2ac46a4bd34add5b144818f4369e64736f6c634300080d0033");    
    // let address = evm.deploy_contract(code, H160::from_slice(&str_to_bytes("147Ea4Cb33e215D24f6e81820B6653D978adc346")[0..20]), U256::from(0));
    
    // let calldata = str_to_bytes("0x764e971f000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000064");
    // evm.execute_call(address, calldata);
    
    // let calldata = str_to_bytes("0x764e971f000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000050");
    // evm.execute_call(address, calldata);
    
}

fn print_values(call: &Call) {
    println!("Stack: {:?}", call.stack.data());
    println!("Memory: {:02x?} {}", call.memory.data(), call.memory.data().len());
    println!("State: {}", call.temp_state.len());
    for (addr, acc) in &call.temp_state {
        println!("Storage for address {:?}", addr);
        for (key,value) in &acc.storage {
            println!("{:x}: {:x}", key, value);
        }
    }
    
    println!("Return: {:02x?}", call.ret_data);
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
        // 0x00 => Opcode::new("STOP", str_to_bytes),
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

    fn get_call(call: &mut Call, code: &str, calldata: &str) {
        let mut context = CallContext::empty();
        context.calldata = str_to_bytes(calldata);
        call.code = str_to_bytes(code);
        call.context = context;
    }

    fn vec_to_h256(vec: Vec<u8>) -> H256 {
        let mut bytes32 = [0u8;32];
        bytes32.clone_from_slice(&vec);
        H256::from(bytes32)
    }

    #[test]
    fn test_add0() {
        let mut evm = Evm::new();
        let code = str_to_bytes("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01600055");
        let contract = evm.deploy_contract(
            code.clone(), 
            H160::from_slice(&str_to_bytes("147Ea4Cb33e215D24f6e81820B6653D978adc346")[0..20]), 
            U256::zero());
        
        let mut call = Call::new(code, CallContext::empty(), HashMap::new());
        call.context.address = contract;
        evm.execute_defined_call(&mut Call::empty(), &mut call);

        assert!(call.stack.data().is_empty());
        assert!(call.memory.data().is_empty());
        let account = call.temp_state.get(&contract).unwrap();
        assert_eq!(account.storage.len(), 1);

        assert_eq!(account.storage.get(&H256::from_low_u64_be(0)).unwrap(), &vec_to_h256(str_to_bytes("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe")));
    }

    #[test]
    fn test_add1() {
        let mut evm = Evm::new();
        let code = str_to_bytes("0x60047fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01600055");
        let contract = evm.deploy_contract(
            code.clone(), 
            H160::from_slice(&str_to_bytes("147Ea4Cb33e215D24f6e81820B6653D978adc346")[0..20]), 
            U256::zero());
        
        let mut call = Call::new(code, CallContext::empty(), HashMap::new());
        call.context.address = contract;
        evm.execute_defined_call(&mut Call::empty(), &mut call);


        assert!(call.stack.data().is_empty());
        assert!(call.memory.data().is_empty());
        let account = call.temp_state.get(&contract).unwrap();
        assert_eq!(account.storage.len(), 1);

        assert_eq!(account.storage.get(&H256::from_low_u64_be(0)).unwrap(), &H256::from_low_u64_be(3));
    }

    #[test]
    fn test_delegatecall() {
        let mut evm = Evm::new();
        let code = str_to_bytes("7067600054600757fe5b60005260086018f36000526011600f6000f060006000600060008461fffff4600160005560006000602060008561fffff4");
    
        let address = evm.deploy_contract(code, H160::from_slice(&str_to_bytes("147Ea4Cb33e215D24f6e81820B6653D978adc346")[0..20]), U256::from(0));
        let res = evm.execute_call(address, str_to_bytes(""));
        if res == ExitReason::Error || res == ExitReason::Revert {
            assert!(false);
        }

        //Deployed contract
        let account = evm.state.get(&H160::from_slice(&str_to_bytes("0x7048d8bc3c4f37986746bc42572a979bd8a26ee0"))).unwrap();
        //CREATE'd
        let account2 = evm.state.get(&H160::from_slice(&str_to_bytes("0x22b59b6c192a6beaab9a3d602bb3033013735b89"))).unwrap();
        assert_eq!(account.storage.len(), 1);
        assert_eq!(account2.storage.len(), 0);

        assert_eq!(account.storage.get(&H256::from_low_u64_be(0)).unwrap(), &H256::from_low_u64_be(1));
    }
}