use primitive_types::{U256, H256};

use crate::{EvalCode, Call, utils::{I256, set_sign}};


pub fn eval_add(call: &mut Call) -> EvalCode {
    let a = call.stack.pop_u256();
    let b = call.stack.pop_u256();
    call.stack.push_u256(a.overflowing_add(b).0);
    EvalCode::Continue
}

pub fn eval_mul(call: &mut Call) -> EvalCode {
    let a = call.stack.pop_u256();
    let b = call.stack.pop_u256();
    call.stack.push_u256(a.overflowing_mul(b).0);
    EvalCode::Continue
}

pub fn eval_sub(call: &mut Call) -> EvalCode {
    let a = call.stack.pop_u256();
    let b = call.stack.pop_u256();
    call.stack.push_u256(a.overflowing_sub(b).0);
    EvalCode::Continue
}

pub fn eval_div(call: &mut Call) -> EvalCode {
    let a = call.stack.pop_u256();
    let b = call.stack.pop_u256();
    match b == U256::zero() {
        true => call.stack.push(H256::zero()),
        false => call.stack.push_u256(a/b)
    }
    EvalCode::Continue
}

pub fn eval_sdiv(call: &mut Call) -> EvalCode {
    let a = I256::from(call.stack.pop_u256());
    let b = I256::from(call.stack.pop_u256());
    let min = I256::min();

    let v = if b.val.is_zero() {
        U256::zero()
    } else if a.val == min.val && b.val == !U256::zero(){
        min.val
    } else {
        let c = a.val/b.val;
        set_sign(c, a.sign ^ b.sign)  
    };

    call.stack.push_u256(v);
    EvalCode::Continue
}

pub fn eval_mod(call: &mut Call) -> EvalCode {
    let a = call.stack.pop_u256();
    let b = call.stack.pop_u256();
    match b == U256::zero() {
        true => call.stack.push(H256::zero()),
        false => call.stack.push_u256(a % b)
    }
    EvalCode::Continue
}

pub fn eval_smod(call: &mut Call) -> EvalCode {
    let a = I256::from(call.stack.pop_u256());
    let b = I256::from(call.stack.pop_u256());

    let v = if !b.val.is_zero() {
        set_sign(a.val % b.val, a.sign)
    } else {
        U256::zero()
    };
    call.stack.push_u256(v);
    EvalCode::Continue
}

pub fn eval_addmod(call: &mut Call) -> EvalCode {
    let a = call.stack.pop_u256();
    let b = call.stack.pop_u256();
    let n = call.stack.pop_u256();
    match n == U256::zero() {
        true => call.stack.push(H256::zero()),
        false => call.stack.push_u256(a.overflowing_add(b).0 % n)
    }
    EvalCode::Continue
}

pub fn eval_mulmod(call: &mut Call) -> EvalCode {
    let a = call.stack.pop_u256();
    let b = call.stack.pop_u256();
    let n = call.stack.pop_u256();
    match n == U256::zero() {
        true => call.stack.push(H256::zero()),
        false => call.stack.push_u256(a.overflowing_mul(b).0 % n)
    }
    EvalCode::Continue
}

pub fn eval_exp(call: &mut Call) -> EvalCode {
    let destination = call.stack.pop_u256().as_usize();
    let offset = call.stack.pop_u256().as_usize();
    let size = call.stack.pop_u256().as_usize();

    let mut extension = vec![0; size];
    
    extension[..call.context.calldata.len()]
        .copy_from_slice(&call.context.calldata[offset..(call.context.calldata.len() + offset)]);

    call.memory.set(destination, &extension);
    EvalCode::Continue
}

