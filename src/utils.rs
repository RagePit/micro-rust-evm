use primitive_types::{U256};

pub struct I256 {
    /// false == positive, true == negative
    pub sign: bool,
    pub val: U256
}

impl I256 {
    pub fn min() -> I256 {
        I256::from((U256::one() << 255) - U256::one())
    }

    // pub fn zero() -> I256 {
    //     I256{
    //         sign: false, 
    //         val: U256::zero()
    //     }
    // }
}

impl From<U256> for I256 {
    fn from(val: U256) -> I256 {
        let U256(arr) = val;
        let sign = arr[3].leading_zeros() == 0;
        I256 {
            val: set_sign(val, sign), 
            sign
        }
    }
}

pub fn set_sign(value: U256, sign: bool) -> U256 {
	if sign {
		(!U256::zero() ^ value).overflowing_add(U256::one()).0
	} else {
		value
	}
}