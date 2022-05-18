use primitive_types::{U256, H160, H256};
use sha3::{Keccak256, Digest};

use crate::{Evm, EvalCode, Call, CallContext, Account, ExitReason};

pub fn eval_origin(evm: &mut Evm, call: &mut Call) -> EvalCode {
    call.stack.push(evm.origin.into());
    EvalCode::Continue
}

pub fn eval_balance(evm: &mut Evm, call: &mut Call) -> EvalCode {
    let address = call.stack.pop().into();
    let balance = match evm.get_account_in_call(call, address) {
        Some(account) => account.balance,
        None => U256::zero(),
    };
    call.stack.push_u256(balance);
    EvalCode::Continue
}

pub fn eval_extcodesize(evm: &mut Evm, call: &mut Call) -> EvalCode {
    let addr = H160::from(call.stack.pop());
    
    match evm.get_account_in_call(call, addr) {
        Some(ext_account) => call.stack.push_u256(U256::from(ext_account.code.len())),
        None => call.stack.push(H256::zero()),
    }
    EvalCode::Continue
}

pub fn eval_extcodecopy(evm: &mut Evm, call: &mut Call) -> EvalCode {
    let addr = H160::from(call.stack.pop());
    let mem_destination = call.stack.pop_u256().as_usize();
    let code_offset = call.stack.pop_u256().as_usize();
    let size = call.stack.pop_u256().as_usize();
    
    match evm.get_account_in_call(call, addr) {
        Some(ext_account) => {
            let mut extension = vec![0; size];
    
            extension[..ext_account.code.len()]
                .copy_from_slice(&ext_account.code[code_offset..(ext_account.code.len() + code_offset)]);

            call.memory.set(mem_destination, &extension);
        },
        None => {
            let extension = vec![0; size];
            call.memory.set(mem_destination, &extension);
        }
    }
    EvalCode::Continue
}

pub fn eval_returndatasize(evm: &mut Evm, call: &mut Call) -> EvalCode {
    call.stack.push_u256(U256::from(evm.ret_data.len()));
    EvalCode::Continue
}

pub fn eval_returndatacopy(evm: &mut Evm, call: &mut Call) -> EvalCode {
    let mem_destination = call.stack.pop_u256().as_usize();
    let offset = call.stack.pop_u256().as_usize();
    let size = call.stack.pop_u256().as_usize();

    let mut extension = vec![0; size];
    
    extension[..evm.ret_data.len()]
        .copy_from_slice(&evm.ret_data[offset..(evm.ret_data.len() + offset)]);

    call.memory.set(mem_destination, &extension);
    EvalCode::Continue
}

pub fn eval_extcodehash(evm: &mut Evm, call: &mut Call) -> EvalCode {
    let addr = H160::from(call.stack.pop());
                
    match evm.get_account_in_call(call, addr) {
        Some(ext_account) => {
            let hash = Keccak256::digest(ext_account.code.as_slice());
            call.stack.push(H256::from_slice(hash.as_slice()));
        },
        None => call.stack.push(H256::zero())
    }
    EvalCode::Continue
}

//TODOs
pub fn eval_timestamp(evm: &mut Evm, call: &mut Call) -> EvalCode {
    // let now = U256::from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
    // call.stack.push_u256(now);
    call.stack.push(H256::zero());
    EvalCode::Continue
}

//TODO
pub fn eval_number(evm: &mut Evm, call: &mut Call) -> EvalCode {
    call.stack.push(H256::zero());
    EvalCode::Continue
}

pub fn eval_selfbalance(evm: &mut Evm, call: &mut Call) -> EvalCode {
    let balance = match evm.get_account_in_call(call, call.context.address) {
        Some(account) => account.balance,
        None => panic!("This shouldn't happen!"),
    };
    call.stack.push_u256(balance);
    EvalCode::Continue
}

pub fn eval_sload(evm: &mut Evm, call: &mut Call) -> EvalCode {
    let key = call.stack.pop();

    //Search current context and historical state for account
    match evm.get_account_in_call(call, call.context.address) {
        Some(account) => {
            match account.storage.get(&key) {
                Some(value) => call.stack.push(*value),
                None => call.stack.push(H256::zero()),
            }
        },
        None => panic!("This shouldn't happen!"),
    }
    EvalCode::Continue
}

pub fn eval_sstore(evm: &mut Evm, call: &mut Call) -> EvalCode {
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
            let mut state_acc = evm.state.get(&call.context.address).unwrap().clone();
            state_acc.storage.insert(key, value);
            call.temp_state.insert(call.context.address, state_acc);
        }
    };
    EvalCode::Continue
}

pub fn eval_create(evm: &mut Evm, call: &mut Call) -> EvalCode {
    let value = call.stack.pop_u256();
    let offset = call.stack.pop_u256().as_usize();
    let size = call.stack.pop_u256().as_usize();
    
    let create_code = call.memory.load(offset, size);
    let nonce = match evm.get_account_in_call(call, call.context.address) {
        Some(account) => account.nonce,
        None => U256::zero(),
    };
    let address = evm.create_address(call.context.address, nonce);
    call.temp_state.insert(address, Account::new(create_code.clone()));

    let mut create_call = Call::new(
        create_code, 
        CallContext::new(Vec::new(), address, call.context.caller, value), 
        call.temp_state.clone());

    let res = evm.execute_defined_call(call, &mut create_call);
    match res {
        //Edit code in account to return data of the call
        ExitReason::Succeeded(_) => {
            call.stack.push(address.into());
            call.temp_state.get_mut(&address).unwrap().code = evm.ret_data.clone();
        },
        //Create failed so remove the created account's state
        _ => {
            call.stack.push(H256::zero());
            call.temp_state.remove(&address);
        }
    };
    match call.temp_state.get_mut(&call.context.address) {
        Some(account) => account.nonce += U256::one(),
        None => {
            let mut account = Account::new(Vec::new());
            account.nonce = U256::one();
            call.temp_state.insert(call.context.address, account);
        },
    }
    EvalCode::Continue
}

pub fn eval_call(evm: &mut Evm, call: &mut Call) -> EvalCode {
    let gas = call.stack.pop();
    let address = H160::from(call.stack.pop());
    let value = call.stack.pop_u256();
    let args_offset = call.stack.pop_u256().as_usize();
    let args_size = call.stack.pop_u256().as_usize();
    let ret_offset = call.stack.pop_u256().as_usize();
    let ret_size = call.stack.pop_u256().as_usize();

    let calldata = call.memory.load(args_offset, args_size);
    let code = match evm.get_account_in_call(call, address) {
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
    let success = evm.execute_defined_call(call, &mut inner_call);
    match success {
        ExitReason::Succeeded(_) => call.stack.push_u256(U256::one()),
        _ => call.stack.push_u256(U256::zero())
    }
    
    call.memory.set(ret_offset, &evm.ret_data[..ret_size]);
    EvalCode::Continue
}

pub fn eval_delegatecall(evm: &mut Evm, call: &mut Call) -> EvalCode {
    let gas = call.stack.pop();
    let address = H160::from(call.stack.pop());
    let args_offset = call.stack.pop_u256().as_usize();
    let args_size = call.stack.pop_u256().as_usize();
    let ret_offset = call.stack.pop_u256().as_usize();
    let ret_size = call.stack.pop_u256().as_usize();

    let calldata = call.memory.load(args_offset, args_size);
    let create_code = match evm.get_account_in_call(call, address) {
        //address was deployed in current context
        Some(acc) => acc.code,
        //may be in historical state
        None => Vec::new()
    };
    let mut delegate_call = Call::new(
        create_code,
        CallContext::new(calldata, call.context.address, call.context.caller, U256::zero()),
        call.temp_state.clone());
    
    let success = evm.execute_defined_call(call,&mut delegate_call);
    match success {
        ExitReason::Succeeded(_) => call.stack.push_u256(U256::one()),
        _ => call.stack.push_u256(U256::zero())
    }
    
    call.memory.set(ret_offset, &evm.ret_data[..ret_size]);
    EvalCode::Continue
}

pub fn eval_create2(evm: &mut Evm, call: &mut Call) -> EvalCode {
    let value = call.stack.pop_u256();
    let offset = call.stack.pop_u256().as_usize();
    let size = call.stack.pop_u256().as_usize();
    let salt = call.stack.pop();

    let code = call.memory.load(offset, size);
    let address = evm.create2_address(call.context.caller, &code, salt);
    
    let mut inner_call = Call::new(
        code,
        CallContext::new(Vec::new(), address, call.context.address, value),
        call.temp_state.clone()
    );
    let success = evm.execute_defined_call(call, &mut inner_call);
    match success {
        //Edit code in account to return data of the call
        ExitReason::Succeeded(_) => {
            call.stack.push(address.into());
            call.temp_state.get_mut(&address).unwrap().code = evm.ret_data.clone();
        },
        //Create failed so remove the created account's state
        _ => {
            call.stack.push(H256::zero());
            call.temp_state.remove(&address);
        }
    };
    EvalCode::Continue
}