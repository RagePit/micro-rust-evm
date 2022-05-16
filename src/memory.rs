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
        //If calldata length is less than offset, return 0
        if offset <= self.data.len() {
            let to = if self.data.len() < offset+size {self.data.len()-offset} else {size};
            let data = &self.data[offset..offset+to];
            
            ret[..to].copy_from_slice(&data[..to]);
        }

        ret
    }

    pub fn set(&mut self, offset: usize, value: &[u8]) {
        if self.data.len() < offset + value.len() {
            let mut len = offset + value.len();
            if len % 32 != 0 {len += 32-(len%32)}
            self.data.resize(len , 0);
        }
        
        self.data[offset..(value.len() + offset)].clone_from_slice(value);
    }
}