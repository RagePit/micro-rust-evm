use primitive_types::{H256, U256};

pub struct Stack {
    pub data: Vec<H256>
}

/// Bottom of the stack is index 0
/// Top of the stack is data.len - 1
/// Grows upward

impl Stack {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn push(&mut self, value: H256) {
        self.data.push(value);
    }

    pub fn push_u256(&mut self, value: U256) {
        let mut to = H256::default();
        value.to_big_endian(&mut to[..]);
        self.push(to);
    }

    pub fn pop(&mut self) -> H256 {
        match self.data.pop() {
            Some(v) => v,
            None => panic!()
        }
    }

    pub fn pop_u256(&mut self) -> U256 {
        U256::from_big_endian(self.pop().as_bytes())
    }

    pub fn peek(&self, depth: usize) -> H256 {
        self.data[self.data.len() - depth - 1]
    }

    pub fn set(&mut self, depth: usize, value: H256) {
        let len = self.data.len();
        self.data[len - depth - 1] = value;
    }
}