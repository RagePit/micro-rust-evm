use crate::{Evm, EvalCode, Call};



pub fn eval_address(call: &mut Call) -> EvalCode {
    call.stack.push(call.context.address.into());
    EvalCode::Continue
}

pub fn eval_caller(call: &mut Call) -> EvalCode {
    call.stack.push(call.context.caller.into());
    EvalCode::Continue
}

pub fn eval_callvalue(call: &mut Call) -> EvalCode {
    call.stack.push_u256(call.context.value);
    EvalCode::Continue
}

