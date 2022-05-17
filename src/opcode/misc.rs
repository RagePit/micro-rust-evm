use primitive_types::{H256, U256};
use sha3::{Keccak256, Digest};

use crate::{Call, EvalCode, ExitReason};

pub fn eval_sha3(call: &mut Call) -> EvalCode {
    let offset = call.stack.pop_u256();
    let size = call.stack.pop_u256();

    let data = call.memory.load(offset.as_usize(), size.as_usize());
    call.stack.push(H256::from_slice(Keccak256::digest(data.as_slice()).as_slice()));
    EvalCode::Continue
}

pub fn eval_calldataload(call: &mut Call) -> EvalCode {
    let offset = call.stack.pop_u256().as_usize();
    let mut load = [0u8; 32];
    //If calldata length is less than offset, return bytes32(0)
    if offset <= call.context.calldata.len() {
        let to = if call.context.calldata.len() < offset+32 {call.context.calldata.len()-offset} else {32};
        let data = &call.context.calldata[offset..offset+to];

        load[..to].copy_from_slice(&data[..to]);
    }                

    call.stack.push(H256::from(load));
    EvalCode::Continue
}

pub fn eval_calldatasize(call: &mut Call) -> EvalCode {
    call.stack.push_u256(U256::from(call.context.calldata.len()));
    EvalCode::Continue
}

pub fn eval_calldatacopy(call: &mut Call) -> EvalCode {
    let destination = call.stack.pop_u256().as_usize();
    let offset = call.stack.pop_u256().as_usize();
    let size = call.stack.pop_u256().as_usize();

    let mut extension = vec![0; size];
    
    extension[..call.context.calldata.len()]
        .copy_from_slice(&call.context.calldata[offset..(call.context.calldata.len() + offset)]);

    call.memory.set(destination, &extension);
    EvalCode::Continue
}

pub fn eval_codesize(call: &mut Call) -> EvalCode {
    call.stack.push_u256(U256::from(call.code.len()));
    EvalCode::Continue
}

pub fn eval_codecopy(call: &mut Call) -> EvalCode {
    let destination = call.stack.pop_u256().as_usize();
    let offset = call.stack.pop_u256().as_usize();
    let size = call.stack.pop_u256().as_usize();
    
    let mut extension = vec![0; size];
    
    extension[..call.code.len()]
        .copy_from_slice(&call.code[offset..(call.code.len() + offset)]);

    call.memory.set(destination, &extension);
    EvalCode::Continue
}

pub fn eval_pop(call: &mut Call) -> EvalCode {
    call.stack.pop();
    EvalCode::Continue
}

pub fn eval_mload(call: &mut Call) -> EvalCode {
    let offset = call.stack.pop_u256().as_usize();
    let mem = call.memory.load(offset, 32);
    call.stack.push(H256::from_slice(&mem[..]));
    EvalCode::Continue
}

pub fn eval_mstore(call: &mut Call) -> EvalCode {
    let offset = call.stack.pop_u256();
    let value = call.stack.pop();
    
    call.memory.set(offset.as_usize(), value.as_bytes());
    EvalCode::Continue
}

pub fn eval_mstore8(call: &mut Call) -> EvalCode {
    let offset = call.stack.pop_u256();
    let value = call.stack.pop();
    
    call.memory.set(offset.as_usize(), &value.as_bytes()[31..32]);
    EvalCode::Continue
}

pub fn eval_jump(call: &mut Call) -> EvalCode {
    let counter = call.stack.pop_u256().as_usize();

    match call.code[counter] == 0x5b {
        true => {
            call.pc = counter-1;
            EvalCode::Continue
        },
        false => EvalCode::Exit(ExitReason::Error)
    }    
}

pub fn eval_jumpi(call: &mut Call) -> EvalCode {
    let counter = call.stack.pop_u256().as_usize();
    let b = call.stack.pop();
    
    if b != H256::zero() {
        match call.code[counter] == 0x5b {
            true => {
                call.pc = counter-1
            },
            false => return EvalCode::Exit(ExitReason::Error)
        }  
    }
    EvalCode::Continue
}

pub fn eval_pc(call: &mut Call) -> EvalCode {
    call.stack.push_u256(U256::from(call.pc));
    EvalCode::Continue
}

pub fn eval_msize(call: &mut Call) -> EvalCode {
    call.stack.push_u256(U256::from(call.memory.data().len()));
    EvalCode::Continue
}

pub fn eval_push(call: &mut Call, op: u8) -> EvalCode {
    let push_n = (op + 32 - 0x7F).into();
    let loc = call.pc + 1;
    let to_push = &call.code[loc..loc+push_n];
    let mut val = [0u8; 32];
    for i in 0..push_n {
        val[32+i-to_push.len()] = to_push[i];
    }

    call.stack.push(H256(val));
    call.pc += push_n;
    EvalCode::Continue
}

pub fn eval_dup(call: &mut Call, op: u8) -> EvalCode {
    let dup_n = (op + 15 - 0x8F).into();
    let value = call.stack.peek(dup_n);
    call.stack.push(value);
    EvalCode::Continue
}

pub fn eval_swap(call: &mut Call, op: u8) -> EvalCode {
    let swap_n: usize = (op + 15 - 0x9F).into();
    let a = call.stack.peek(0);
    let b = call.stack.peek(swap_n+1);

    call.stack.set(0, b);
    call.stack.set(swap_n+1, a);
    EvalCode::Continue
}

pub fn eval_return(call: &mut Call) -> EvalCode {
    let offset = call.stack.pop_u256().as_usize();
    let size = call.stack.pop_u256().as_usize();

    let return_data = call.memory.load(offset, size);
    call.ret_data = return_data;
    EvalCode::Continue
}

pub fn eval_revert(call: &mut Call) -> EvalCode {
    let offset = call.stack.pop_u256().as_usize();
    let size = call.stack.pop_u256().as_usize();

    let return_data = call.memory.load(offset, size);
    call.ret_data = return_data;
    EvalCode::Exit(ExitReason::Revert)
}