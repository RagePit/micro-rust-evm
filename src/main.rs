mod stack;
mod memory;

use std::ops::Index;

use primitive_types::{H256, U256};

use stack::Stack;
use memory::Memory;


struct Evm {
    pc: usize,
    ret_data: Vec<u8>,
    stack: Stack,
    memory: Memory,
    code: String
}

impl Evm {
    fn new(code: String) -> Self {
        Self {
            pc: 0,
            ret_data: Vec::new(),
            stack: Stack::new(),
            memory: Memory::new(),
            code: code
        }
    }

    fn run(&mut self) {
        while self.pc * 2 < self.code.len() {
            self.eval(hex_str_to_u8(&self.code[self.pc*2..self.pc*2+2]));
        }
    }

    fn eval(&mut self, op: u8) {
        match op {
            0x60 => {
                let loc = self.pc + 1;
                let to_push = hex_str_to_u8(&self.code[loc*2..loc*2+2]);
                let mut val = [0u8; 32];
                val[31] = to_push;
                self.stack.push(H256(val));
                self.pc += 1;
            },
            0x52 => {
                let offset = self.stack.pop();
                let offset = U256::from(offset.as_fixed_bytes());
                let value = self.stack.pop();
                
                self.memory.set(offset.as_usize(), value.as_bytes());
            },
            0xF3 => {
                let offset = U256::from(self.stack.pop().as_fixed_bytes()).as_usize();
                let size = U256::from(self.stack.pop().as_fixed_bytes()).as_usize();

                let return_data = self.memory.load(offset, size);
                self.ret_data = return_data;
            }
            _ => ()
        }
        self.pc += 1;
    }
}

fn main() {

    let mut evm = Evm::new(String::from("604260005260206000F3"));

    evm.run();
    println!("{:?}", evm.stack.data());
    println!("{:?}", evm.memory.data());
    println!("{:?}", evm.ret_data);
}

fn hex_str_to_u8(str: &str) -> u8 {
    match u8::from_str_radix(str, 16) {
        Ok(op) => op,
        Err(e) => panic!("{}", e)
    }
}