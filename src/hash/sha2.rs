use crate::hash::Operations;
use crate::hash::HashDataCtx;
use num::Zero;
use num_traits::PrimInt;
use core::ops::BitAnd;
use core::ops::BitXor;
use core::ops::Not;
use num::traits::WrappingAdd;
use core::ops::BitOrAssign;
use crate::utils::UsizeCast;


pub const SHA512_BLOCKSIZE: usize = 128;
pub const SHA512_DIGEST_SIZE: usize = 64;
pub const SHA512_SCHED_SIZE: usize = 80;

pub const SHA256_BLOCKSIZE: usize = 64;
pub const SHA256_SCHED_SIZE: usize = 64;
pub const SHA256_DIGEST_SIZE: usize = 32;

pub const SHA384_DIGEST_SIZE: usize = 48;

pub const SHA2_STATE_SIZE: usize = 8;

trait SHA512Like {}

#[derive(Debug)]
pub struct SHA256;
#[derive(Debug)]
pub struct SHA512;
#[derive(Debug)]
pub struct SHA384;

impl SHA512Like for SHA512 {}
impl SHA512Like for SHA384 {}

static K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];


static K512: [u64; 80] = [
	0x428a2f98d728ae22, 0x7137449123ef65cd,
	0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019,
	0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe,
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
	0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
	0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210,
	0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725,
	0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926,
	0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8,
	0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001,
	0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910,
	0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
	0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60,
	0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9,
	0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207,
	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6,
	0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493,
	0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
	0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

trait SHA2Algo<
    const BLOCKSIZE: usize,
    const DIGEST_SIZE: usize,
    const STATE_SIZE: usize,
    const SCHED_SIZE: usize,
    T: PrimInt + BitAnd<Output=T> + Not<Output=T> + BitXor<Output=T> + Zero 
        + WrappingAdd + Copy + BitOrAssign + From<u8>> {

    fn sha2_ch(x: T, y: T, z: T) -> T{
        return (x & y) ^ ((!x) & z);
    }
    
    fn sha2_maj(x: T, y: T, z: T) -> T {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    fn sha2_bsig0(x: T) -> T; 
    
    fn sha2_bsig1(x: T) -> T;
    
    fn sha2_ssig0(x: T) -> T;
    
    fn sha2_ssig1(x: T) -> T;

    fn u8toT(x:u8)-> T;

    fn prepare_schedule(W: &mut[T; SCHED_SIZE], t: usize, input: &[u8]) -> ();

    fn sha2_round(state: &mut [T; STATE_SIZE], mut input: &[u8], K: &[T;SCHED_SIZE]) {
        let mut W: [T; SCHED_SIZE] = [T::zero(); SCHED_SIZE];
        let mut a: T;
        let mut b: T;
        let mut c: T;
        let mut d: T;
        let mut e: T;
        let mut f: T;
        let mut g: T;
        let mut h: T;
        let mut T1: T;
        let mut T2: T;
        let mut t: T;

        let mut mlen: i64 = input.len().i64() - BLOCKSIZE.i64();
        while mlen >= 0 {
            mlen -= BLOCKSIZE.i64();

            // Initialized the woking variables.
            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];
            e = state[4];
            f = state[5];
            g = state[6];
            h = state[7];

            //  Prepare the message schedule W and compute intermmediate values.
            for t in 0..16 {
                //W[t] = Self::u8toT(input[t * 4]) << 24;
                //W[t] |= Self::u8toT(input[t * 4 + 1]) << 16;
                //W[t] |= Self::u8toT(input[t * 4 + 2]) << 8;
                //W[t] |= Self::u8toT(input[t * 4 + 3]);
                Self::prepare_schedule(&mut W, t, input);

                T1 = h
                    .wrapping_add(&Self::sha2_bsig1(e))
                    .wrapping_add(&Self::sha2_ch(e, f, g))
                    .wrapping_add(&K[t])
                    .wrapping_add(&W[t]);

                T2 = Self::sha2_bsig0(a).wrapping_add(&Self::sha2_maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(&T1);
                d = c;
                c = b;
                b = a;
                a = T1.wrapping_add(&T2);
            }

            for t in 16..SCHED_SIZE {
                W[t] = Self::sha2_ssig1(W[t - 2])
                    .wrapping_add(&W[t - 7])
                    .wrapping_add(&Self::sha2_ssig0(W[t - 15]))
                    .wrapping_add(&W[t - 16]);

                T1 = h
                    .wrapping_add(&Self::sha2_bsig1(e))
                    .wrapping_add(&Self::sha2_ch(e, f, g))
                    .wrapping_add(&K[t])
                    .wrapping_add(&W[t]);

                T2 = Self::sha2_bsig0(a).wrapping_add(&Self::sha2_maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(&T1);
                d = c;
                c = b;
                b = a;
                a = T1.wrapping_add(&T2);
            }
            /* Store the intermediate hash value/ */
            state[0] = state[0].wrapping_add(&a);
            state[1] = state[1].wrapping_add(&b);
            state[2] = state[2].wrapping_add(&c);
            state[3] = state[3].wrapping_add(&d);
            state[4] = state[4].wrapping_add(&e);
            state[5] = state[5].wrapping_add(&f);
            state[6] = state[6].wrapping_add(&g);
            state[7] = state[7].wrapping_add(&h);

            input = &input[BLOCKSIZE..];
        }
    }
}

impl SHA2Algo<SHA256_BLOCKSIZE, SHA256_DIGEST_SIZE, SHA2_STATE_SIZE, SHA256_SCHED_SIZE, u32> for SHA256 {
    fn prepare_schedule(W: &mut[u32; SHA256_SCHED_SIZE], t: usize, input: &[u8]) {
        W[t] = Self::u8toT(input[t * 4]) << 24;
        W[t] |= Self::u8toT(input[t * 4 + 1]) << 16;
        W[t] |= Self::u8toT(input[t * 4 + 2]) << 8;
        W[t] |= Self::u8toT(input[t * 4 + 3]);
    }

    fn u8toT(x:u8) -> u32 {
        return x.into();
    }

    fn sha2_bsig0(x: u32) -> u32 {
        return x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22);
    }
    
    fn sha2_bsig1(x: u32) -> u32 {
        return x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25);
    }
    
    fn sha2_ssig0(x: u32) -> u32 {
        return x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
    }
    
    fn sha2_ssig1(x: u32) -> u32 {
        return x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10);
    }
}


impl<T> SHA2Algo<SHA512_BLOCKSIZE,
              SHA512_DIGEST_SIZE,
              SHA2_STATE_SIZE,
              SHA512_SCHED_SIZE, u64> for T where T: SHA512Like {

    fn prepare_schedule(W: &mut[u64; SHA512_SCHED_SIZE], t: usize, input: &[u8]) {
		W[t] =  Self::u8toT(input[t * 8]) << 56; 
		W[t] |= Self::u8toT(input[t * 8 + 1]) << 48; 
		W[t] |= Self::u8toT(input[t * 8 + 2]) << 40; 
		W[t] |= Self::u8toT(input[t * 8 + 3]) << 32; 
		W[t] |= Self::u8toT(input[t * 8 + 4]) << 24; 
		W[t] |= Self::u8toT(input[t * 8 + 5]) << 16; 
		W[t] |= Self::u8toT(input[t * 8 + 6]) << 8; 
		W[t] |= Self::u8toT(input[t * 8 + 7]);
    }

    fn u8toT(x:u8) -> u64 {
        return x.into();
    }

    fn sha2_bsig0(x: u64) -> u64 {
        return x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39);
    }
    
    fn sha2_bsig1(x: u64) -> u64 {
        return x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41);
    }
    
    fn sha2_ssig0(x: u64) -> u64 {
        return x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7);
    }
    
    fn sha2_ssig1(x: u64) -> u64 {
        return x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6);
    }
}


impl Operations<SHA256_BLOCKSIZE, SHA256_DIGEST_SIZE, SHA2_STATE_SIZE, u32> for SHA256 
    where SHA256: SHA2Algo<SHA256_BLOCKSIZE, SHA256_DIGEST_SIZE, SHA2_STATE_SIZE, SHA256_SCHED_SIZE, u32> {

    fn Ttou8(x:u32) -> u8 {
        return x as u8;
    }

    fn _transform(&self, state: &mut [u32; SHA2_STATE_SIZE], mut input: &[u8]) {
        Self::sha2_round(state, input, &K256);
    }
    fn _init(&self, ctx: &mut HashDataCtx<SHA256_BLOCKSIZE, SHA2_STATE_SIZE, u32>) {
        // clear ctx since it could be reused
        ctx.count = 0;
        ctx.rem_pos = 0;
        ctx.buffer.fill(0);

        //set initial state
        ctx.state[0] = 0x6a09e667;
        ctx.state[1] = 0xbb67ae85;
        ctx.state[2] = 0x3c6ef372;
        ctx.state[3] = 0xa54ff53a;
        ctx.state[4] = 0x510e527f;
        ctx.state[5] = 0x9b05688c;
        ctx.state[6] = 0x1f83d9ab;
        ctx.state[7] = 0x5be0cd19;
    }
}


impl Operations<SHA512_BLOCKSIZE, SHA512_DIGEST_SIZE, SHA2_STATE_SIZE, u64> for SHA512 {
    fn Ttou8(x:u64) -> u8 {
        return x as u8;
    }

    fn _transform(&self, state: &mut [u64; SHA2_STATE_SIZE], mut input: &[u8]) {
        Self::sha2_round(state, input, &K512);
    }
    fn _init(&self, ctx: &mut HashDataCtx<SHA512_BLOCKSIZE, SHA2_STATE_SIZE, u64>) {
        // clear ctx since it could be reused
        ctx.count = 0;
        ctx.rem_pos = 0;
        ctx.buffer.fill(0);

        //set initial state
        ctx.state[0] = 0x6a09e667f3bcc908;
        ctx.state[1] = 0xbb67ae8584caa73b;
        ctx.state[2] = 0x3c6ef372fe94f82b;
        ctx.state[3] = 0xa54ff53a5f1d36f1;
        ctx.state[4] = 0x510e527fade682d1;
        ctx.state[5] = 0x9b05688c2b3e6c1f;
        ctx.state[6] = 0x1f83d9abfb41bd6b;
        ctx.state[7] = 0x5be0cd19137e2179;

    }
}

impl Operations<SHA512_BLOCKSIZE, SHA384_DIGEST_SIZE, SHA2_STATE_SIZE, u64> for SHA384 {
    fn Ttou8(x:u64) -> u8 {
        return x as u8;
    }

    fn _transform(&self, state: &mut [u64; SHA2_STATE_SIZE], mut input: &[u8]) {
        Self::sha2_round(state, input, &K512);
    }

    fn _init(&self, ctx: &mut HashDataCtx<SHA512_BLOCKSIZE, SHA2_STATE_SIZE, u64>) {
        // clear ctx since it could be reused
        ctx.count = 0;
        ctx.rem_pos = 0;
        ctx.buffer.fill(0);

        //set initial state
	    ctx.state[0] = 0xcbbb9d5dc1059ed8;
	    ctx.state[1] = 0x629a292a367cd507;
	    ctx.state[2] = 0x9159015a3070dd17;
	    ctx.state[3] = 0x152fecd8f70e5939;
	    ctx.state[4] = 0x67332667ffc00b31;
	    ctx.state[5] = 0x8eb44a8768581511;
	    ctx.state[6] = 0xdb0c2e0d64f98fa7;
	    ctx.state[7] = 0x47b5481dbefa4fa4;
    }
}
