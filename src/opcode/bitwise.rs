use primitive_types::{U256, H256};

use crate::{Call, EvalCode, utils::I256};


pub fn eval_lt(call: &mut Call) -> EvalCode {
    let a = call.stack.pop_u256();
    let b = call.stack.pop_u256();
    let res = if a < b {U256::one()} else {U256::zero()};
    call.stack.push_u256(res);
    EvalCode::Continue
}

pub fn eval_gt(call: &mut Call) -> EvalCode {
    let a = call.stack.pop_u256();
    let b = call.stack.pop_u256();
    let res = if a > b {U256::one()} else {U256::zero()};
    call.stack.push_u256(res);
    EvalCode::Continue
}

pub fn eval_slt(call: &mut Call) -> EvalCode {
    let a: I256 = call.stack.pop_u256().into();
    let b: I256 = call.stack.pop_u256().into();

    let is_positive_lt = a.val < b.val && !(a.sign | b.sign);
    let is_negative_lt = a.val > b.val && (a.sign & b.sign);
    let has_different_signs = a.sign && !b.sign;

    match is_positive_lt | is_negative_lt | has_different_signs {
        true => call.stack.push_u256(U256::one()),
        false => call.stack.push(H256::zero())
    }
    EvalCode::Continue
}

//Credit: https://github.com/openethereum/parity-ethereum/blob/55c90d4016505317034e3e98f699af07f5404b63/ethcore/evm/src/interpreter/mod.rs#L1003
pub fn eval_sgt(call: &mut Call) -> EvalCode {
    let a: I256 = call.stack.pop_u256().into();
    let b: I256 = call.stack.pop_u256().into();

    let is_positive_gt = a.val > b.val && !(a.sign | b.sign);
    let is_negative_gt = a.val < b.val && (a.sign & b.sign);
    let has_different_signs = !a.sign && b.sign;

    match is_positive_gt | is_negative_gt | has_different_signs {
        true => call.stack.push_u256(U256::one()),
        false => call.stack.push(H256::zero())
    }
    EvalCode::Continue
}

pub fn eval_eq(call: &mut Call) -> EvalCode {
    let a = call.stack.pop_u256();
    let b = call.stack.pop_u256();
    let res = if a == b {U256::one()} else {U256::zero()};
    call.stack.push_u256(res);
    EvalCode::Continue
}

pub fn eval_iszero(call: &mut Call) -> EvalCode {
    let a = call.stack.pop_u256();
    let res = if a == U256::zero() {U256::one()} else {U256::zero()};
    call.stack.push_u256(res);
    EvalCode::Continue
}

pub fn eval_and(call: &mut Call) -> EvalCode {
    let a = call.stack.pop();
    let b = call.stack.pop();
    
    call.stack.push(a & b);
    EvalCode::Continue
}

pub fn eval_or(call: &mut Call) -> EvalCode {
    let a = call.stack.pop();
    let b = call.stack.pop();
    
    call.stack.push(a | b);
    EvalCode::Continue
}

pub fn eval_xor(call: &mut Call) -> EvalCode {
    let a = call.stack.pop();
    let b = call.stack.pop();
    
    call.stack.push(a ^ b);
    EvalCode::Continue
}

pub fn eval_not(call: &mut Call) -> EvalCode {
    let a = call.stack.pop_u256();

    call.stack.push_u256(!a);
    EvalCode::Continue
}

//TODO: understand this
pub fn eval_byte(call: &mut Call) -> EvalCode {
    let offset = call.stack.pop_u256();
    let val = call.stack.pop_u256();

    let byte = match offset < U256::from(32) {
        true => (val >> (8 * (31 - offset.as_usize()))) & U256::from(0xff),
        false => U256::zero()
    };

    call.stack.push_u256(byte);
    EvalCode::Continue
}

pub fn eval_shl(call: &mut Call) -> EvalCode {
    let shift = call.stack.pop_u256();
    let val = call.stack.pop_u256();
    match shift > U256::from(255) {
        true => call.stack.push(H256::zero()),
        false => call.stack.push_u256(val << shift)
    }
    EvalCode::Continue
}

pub fn eval_shr(call: &mut Call) -> EvalCode {
    let shift = call.stack.pop_u256();
    let val = call.stack.pop_u256();
    match shift > U256::from(255) {
        true => call.stack.push(H256::zero()),
        false => call.stack.push_u256(val >> shift)
    }
    EvalCode::Continue
}

//https://github.com/openethereum/parity-ethereum/blob/55c90d4016505317034e3e98f699af07f5404b63/ethcore/evm/src/interpreter/mod.rs#L1118-L1142
pub fn eval_sar(call: &mut Call) -> EvalCode {
    const HIBIT: U256 = U256([0,0,0,0x8000000000000000]);

    let shift = call.stack.pop_u256();
    let val = call.stack.pop_u256();
    let sign = val & HIBIT != U256::zero();

    let result = if val == U256::zero() || shift >= U256::from(256) {
        if sign { U256::max_value() } else { U256::zero() }
    } else {
        let shift = shift.as_usize();
        if sign { val >> shift | (U256::max_value() << (256 - shift)) } else { val >> shift }
    };
    call.stack.push_u256(result);
    EvalCode::Continue
}