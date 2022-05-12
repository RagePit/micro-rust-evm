pub struct Memory {
    data: Vec<u8>
}

impl Memory {

    pub fn new() -> Self {
        Self {
            data: Vec::new()
        }
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn load(&self, offset: usize, size: usize) -> Vec<u8> {
        let mut ret = Vec::new();

        ret.resize(size, 0);
        ret.clone_from_slice(&self.data[offset..offset+size]);

        ret
    }

    pub fn set(&mut self, offset: usize, value: &[u8]) {
        if self.data.len() < offset + value.len() {
            self.data.resize(offset + value.len(), 0);
        }
        
        self.data[offset..(value.len() + offset)].clone_from_slice(value);
    }
}