use primitive_types::H256;

pub struct Stack {
    data: Vec<H256>
}

/// Bottom of the stack is index 0
/// Top of the stack is data.len - 1
/// Grows upward

impl Stack {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn data(&self) -> &Vec<H256> {
        &self.data
    }

    pub fn depth(&self) -> usize {
        self.data.len()
    }

    pub fn push(&mut self, value: H256) {
        self.data.push(value);
    }

    pub fn pop(&mut self) -> H256 {
        match self.data.pop() {
            Some(v) => v,
            None => panic!()
        }
    }

    pub fn peek(&self, depth: usize) -> H256 {
        self.data[self.data.len() - depth - 1]
    }

    pub fn set(&mut self, depth: usize, value: H256) {
        let len = self.data.len();
        self.data[len - depth - 1] = value;
    }
}